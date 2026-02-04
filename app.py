#!/usr/bin/env python3
"""
Flask Web Application for JavaScript Security Analyzer

- ALL analysis happens server-side via analyzer.JavaScriptAnalyzer
- Frontend should POST to /api/analyze (recommended)
- Compatibility aliases included: /analyze, /analyze-multiple, /analyze-file
"""

from __future__ import annotations

import os
import uuid
import traceback
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify, send_from_directory, g, abort
from flask_cors import CORS
from werkzeug.utils import secure_filename

from analyzer import JavaScriptAnalyzer
from analysis_engine.ml_chat import MLChatEngine
from ratelimit import RateLimiter
from auth import get_api_key

# ===========================
# App setup
# ===========================
app = Flask(__name__)

# Initialize Rate Limiter (e.g., 10 requests per 10 seconds)
limiter = RateLimiter(limit=10, window=10)

# CORS: okay for dev; for production restrict origins.
CORS(app)

# Max upload size (adjust as needed)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
analyzer = JavaScriptAnalyzer()
chat_engine = MLChatEngine()

# Store analysis results in memory (prod: use Redis/DB)
analysis_results: Dict[str, Dict[str, Any]] = {}

def _get_client_ip() -> str:
    """Resolve client IP reliably (proxy-aware) and normalize local dev cases."""
    try:
        forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        ip = forwarded or (request.remote_addr or "")
        # Normalize dev addresses that are non-routable
        if ip in ("", "0.0.0.0", "::", "::1"):
            ip = "127.0.0.1"
        return ip
    except Exception:
        return "127.0.0.1"

def _normalize_localhost(url: str) -> str:
    """
    Replace 0.0.0.0 with 127.0.0.1 for local analysis to avoid fetch failures.
    Preserve port and userinfo if present.
    """
    try:
        p = urlparse(url.strip())
        if p.scheme in ("http", "https") and p.netloc and p.netloc.startswith("0.0.0.0"):
            netloc = p.netloc.replace("0.0.0.0", "127.0.0.1")
            return p._replace(netloc=netloc).geturl()
        return url
    except Exception:
        return url


@app.route("/rate-limited")
def rate_limited():
    """Explicit route for rate limit page"""
    return render_template("429.html"), 429

@app.before_request
def check_rate_limit():
    # Skip for static files and simple health checks if needed
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return
        
    # Skip if valid API key is present (trusted client)
    if request.headers.get("X-API-Key") == get_api_key() or request.args.get("api_key") == get_api_key():
        return
        
    # Get client identifier (IP address)
    client_id = _get_client_ip()
    g.client_id = client_id
    
    if not limiter.is_allowed(client_id):
        # API requests get JSON, Browser requests get HTML
        if request.path.startswith("/api/") or request.accept_mimetypes.accept_json:
             return error_response("Rate limit exceeded. Please try again later.", 429)
        return render_template("429.html"), 429


@app.after_request
def add_security_headers(response):
    """Add Content Security Policy and other security headers"""
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://js.puter.com; "
        "connect-src 'self' https://*.puter.com wss://*.puter.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Hide server info
    response.headers['Server'] = 'SecurityAnalyzer'
    if 'X-Powered-By' in response.headers:
        del response.headers['X-Powered-By']

    # Add Rate Limit Headers
    if hasattr(g, 'client_id'):
        limit = limiter.limit
        remaining = limiter.get_remaining(g.client_id)
        response.headers['X-RateLimit-Limit'] = str(limit)
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        
    return response

# ===========================
# Utility helpers
# ===========================
def error_response(message: str, status: int = 400, **extra):
    payload = {"error": message}
    payload.update(extra)
    return jsonify(payload), status


def is_valid_http_url(url: str) -> bool:
    """Basic URL validation to avoid invalid schemes."""
    try:
        p = urlparse(url.strip())
        if not (p.scheme in ("http", "https") and bool(p.netloc)):
            return False
        # Disallow non-routable host explicitly; UI suggests localhost/127.0.0.1
        if p.netloc.startswith("0.0.0.0"):
            return False
        return True
    except Exception:
        return False


def extract_urls_from_text(text: str) -> List[str]:
    """Extract non-empty, non-comment lines as URLs."""
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def normalize_urls(payload: dict) -> List[str]:
    """
    Normalize JSON payload into a list of URLs.
    Supports:
      - {"url": "..."}
      - {"urls": ["...","..."]}
      - {"urls": "..."}  (string)
    """
    urls = payload.get("urls", [])
    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        url = (payload.get("url") or "").strip()
        if url:
            urls = [url]

    # Clean
    urls = [_normalize_localhost(u.strip()) for u in urls if isinstance(u, str) and u.strip()]
    return urls


def analyze_urls(urls: List[str]) -> Dict[str, Any]:
    """
    Run analysis for each URL using analyzer.analyze(url) in PARALLEL.
    Returns { session_id, total_files, results: [...] }
    """
    # Generate session ID for this batch
    session_id = str(uuid.uuid4())
    analysis_results[session_id] = {"files": [], "total": len(urls), "completed": 0}

    results: List[Dict[str, Any]] = []

    def process_url(idx_url_tuple):
        idx, url = idx_url_tuple
        try:
            # Normalize dev host if needed
            url = _normalize_localhost(url)
            if not is_valid_http_url(url):
                raise ValueError("Invalid URL. Only http(s) URLs are allowed.")

            result = analyzer.analyze(url)

            result_dict = {
                "file_id": idx + 1,
                "url": getattr(result, "url", url),
                "api_keys": getattr(result, "api_keys", None) or [],
                "credentials": getattr(result, "credentials", None) or [],
                "emails": getattr(result, "emails", None) or [],
                "interesting_comments": getattr(result, "interesting_comments", None) or [],
                "xss_vulnerabilities": getattr(result, "xss_vulnerabilities", None) or [],
                "xss_functions": getattr(result, "xss_functions", None) or [],
                "api_endpoints": getattr(result, "api_endpoints", None) or [],
                "parameters": getattr(result, "parameters", None) or [],
                "paths_directories": getattr(result, "paths_directories", None) or [],
                "errors": getattr(result, "errors", None) or [],
                "file_size": getattr(result, "file_size", 0),
                "analysis_timestamp": getattr(result, "analysis_timestamp", ""),
                "server_info": getattr(result, "server_info", None),
                "csp_info": getattr(result, "csp_info", None),
                "ip_address": getattr(result, "ip_address", None),
                "cloudflare_analysis": getattr(result, "cloudflare_analysis", None),
                "rate_limit_info": getattr(result, "rate_limit_info", None),
                "recommendations": getattr(result, "recommendations", None) or [],
            }
            return result_dict

        except Exception as e:
            traceback.print_exc()
            return {
                "file_id": idx + 1,
                "url": url,
                "errors": [f"Analysis failed: {str(e)}"],
                "api_keys": [],
                "credentials": [],
                "emails": [],
                "interesting_comments": [],
                "xss_vulnerabilities": [],
                "xss_functions": [],
                "api_endpoints": [],
                "parameters": [],
                "paths_directories": [],
                "file_size": 0,
                "analysis_timestamp": "",
                "server_info": None,
                "csp_info": None,
                "ip_address": None,
                "cloudflare_analysis": None,
                "rate_limit_info": None,
                "recommendations": [],
            }

    # Parallel execution
    # Use max_workers=10 for reasonable concurrency
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks
        future_to_url = {
            executor.submit(process_url, (idx, url)): idx 
            for idx, url in enumerate(urls)
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_url):
            result_dict = future.result()
            results.append(result_dict)
            analysis_results[session_id]["files"].append(result_dict)
            analysis_results[session_id]["completed"] += 1

    # Sort results by file_id to maintain order
    results.sort(key=lambda x: x["file_id"])
    
    # Update the session results with sorted list
    analysis_results[session_id]["files"] = results

    return {"session_id": session_id, "total_files": len(results), "results": results}


# ===========================
# Routes
# ===========================
@app.route("/")
def index():
    """Main page"""
    return render_template("index.html")


# -----------------------------------------
# Recommended unified endpoint:
# POST /api/analyze
# - JSON: {url:"..."} or {urls:[...]}
# - multipart/form-data: file=<txt/csv>
# -----------------------------------------
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        urls: List[str] = []
        is_code_file = False  # Initialize flag

        # JSON payload mode
        if request.is_json:
            data = request.get_json(silent=True) or {}
            urls = normalize_urls(data)

            if not urls:
                return error_response("URL(s) are required", 400)

        # File upload mode
        else:
            if "file" not in request.files:
                return error_response("No file or JSON data provided", 400)

            f = request.files["file"]
            if not f or not f.filename:
                return error_response("No file uploaded", 400)

            filename = secure_filename(f.filename)
            raw = f.read().decode("utf-8", errors="ignore")
            
            # First, try to extract URLs
            urls = extract_urls_from_text(raw)
            
            # If the file itself looks like code (e.g. .js extension) OR no URLs found, 
            # we analyze the CONTENT directly.
            is_code_file = filename.lower().endswith(('.js', '.html', '.htm', '.json', '.php', '.ts', '.jsx', '.tsx', '.vue', '.map'))
            
            if is_code_file or not urls:
                # Generate a session ID
                session_id = str(uuid.uuid4())
                
                # Analyze content directly
                result = analyzer.analyze_content(raw, url=filename)
                
                # Generate recommendations for file upload
                result.recommendations = analyzer.generate_recommendations(result)
                
                # Convert AnalysisResult object to dict
                result_dict = {
                    "file_id": 1,
                    "url": getattr(result, "url", filename),
                    "api_keys": getattr(result, "api_keys", None) or [],
                    "credentials": getattr(result, "credentials", None) or [],
                    "emails": getattr(result, "emails", None) or [],
                    "interesting_comments": getattr(result, "interesting_comments", None) or [],
                    "xss_vulnerabilities": getattr(result, "xss_vulnerabilities", None) or [],
                    "xss_functions": getattr(result, "xss_functions", None) or [],
                    "api_endpoints": getattr(result, "api_endpoints", None) or [],
                    "parameters": getattr(result, "parameters", None) or [],
                    "paths_directories": getattr(result, "paths_directories", None) or [],
                    "errors": getattr(result, "errors", None) or [],
                    "file_size": getattr(result, "file_size", 0),
                    "analysis_timestamp": getattr(result, "analysis_timestamp", ""),
                    "server_info": getattr(result, "server_info", None),
                    "csp_info": getattr(result, "csp_info", None),
                    "ip_address": getattr(result, "ip_address", None),
                    "cloudflare_analysis": getattr(result, "cloudflare_analysis", None),
                    "rate_limit_info": getattr(result, "rate_limit_info", None),
                    "recommendations": getattr(result, "recommendations", None) or [],
                }
                
                results_list = [result_dict]
                analysis_results[session_id] = {"files": results_list, "total": 1, "completed": 1}
                
                return jsonify({"session_id": session_id, "total_files": 1, "results": results_list}), 200

            if not urls:
                return error_response("No valid URLs found in file", 400, filename=filename)

        # Run analysis
        payload = analyze_urls(urls)
        return jsonify(payload), 200

    except Exception as e:
        traceback.print_exc()
        return error_response(str(e), 500)


# -----------------------------------------
# Compatibility aliases (so your old JS works)
# -----------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze_alias_single():
    return api_analyze()


@app.route("/analyze-multiple", methods=["POST"])
def analyze_alias_multiple():
    return api_analyze()


@app.route("/analyze-file", methods=["POST"])
def analyze_alias_file():
    return api_analyze()


# -----------------------------------------
# Results endpoints (session-based)
# -----------------------------------------
@app.route("/api/results/<session_id>", methods=["GET"])
def get_results(session_id: str):
    """Get analysis results for a session"""
    if session_id not in analysis_results:
        return error_response("Session not found", 404)

    return jsonify(analysis_results[session_id]), 200


@app.route("/api/file/<session_id>/<int:file_id>", methods=["GET"])
def get_file_result(session_id: str, file_id: int):
    """Get specific file result"""
    if session_id not in analysis_results:
        return error_response("Session not found", 404)

    files = analysis_results[session_id].get("files", [])
    file_result = next((f for f in files if f.get("file_id") == file_id), None)

    if not file_result:
        return error_response("File not found", 404)

    return jsonify(file_result), 200


@app.route("/api/chat/config", methods=["GET"])
def chat_config():
    """Get chat configuration (system instruction/knowledge base)"""
    return jsonify({
        "system_instruction": chat_engine.get_system_instruction()
    })



# -----------------------------------------
# Optional health endpoint
# -----------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200


# -----------------------------------------
# Serve JS files from project root (testing)
# REMOVED for security: User reported exposure of internal structure.
# -----------------------------------------
# @app.route("/<path:filename>")
# def serve_file(filename: str):
#     return error_response("File access restricted", 403)


# -----------------------------------------
# Protected Static Files (JS)
# -----------------------------------------
@app.route("/js/<path:filename>")
def protected_js(filename):
    """Serve JS files (Referer check disabled for debugging)"""
    # referer = request.headers.get("Referer")
    # if not referer:
    #     # Block requests with no referer (direct access)
    #     return error_response("Access denied", 403)
    
    # # Check if referer is from our own domain
    # parsed_ref = urlparse(referer)
    # if parsed_ref.netloc != request.host:
    #     return error_response("Access denied", 403)
        
    return send_from_directory(os.path.join(BASE_DIR, "protected_static", "js"), filename)


@app.errorhandler(404)
def not_found_error(error):
    return error_response("Resource not found", 404)

@app.errorhandler(500)
def internal_error(error):
    return error_response("Internal server error", 500)


# ===========================
# Run
# ===========================
if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host=host, port=port)
