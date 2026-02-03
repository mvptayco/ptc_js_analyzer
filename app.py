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

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from analyzer import JavaScriptAnalyzer
from ratelimit import RateLimiter
from auth import require_api_key, get_api_key

# ===========================
# App setup
# ===========================
app = Flask(__name__)

# Initialize Rate Limiter (e.g., 100 requests per minute)
limiter = RateLimiter(limit=100, window=60)

# CORS: okay for dev; for production restrict origins.
CORS(app)

# Max upload size (adjust as needed)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
analyzer = JavaScriptAnalyzer()

# Store analysis results in memory (prod: use Redis/DB)
analysis_results: Dict[str, Dict[str, Any]] = {}


@app.before_request
def check_rate_limit():
    # Skip for static files and simple health checks if needed
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return
        
    # Skip if valid API key is present (trusted client)
    if request.headers.get("X-API-Key") == get_api_key() or request.args.get("api_key") == get_api_key():
        return
        
    # Get client identifier (IP address)
    client_id = request.remote_addr
    
    if not limiter.is_allowed(client_id):
        return error_response("Rate limit exceeded. Please try again later.", 429)

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
        return p.scheme in ("http", "https") and bool(p.netloc)
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
    urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
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


# -----------------------------------------
# Optional health endpoint
# -----------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200


# -----------------------------------------
# Serve JS files from project root (testing)
# IMPORTANT: must be LAST to avoid route conflicts
# Example: http://192.168.1.15:5000/test.js
# -----------------------------------------
@app.route("/<path:filename>")
def serve_file(filename: str):
    # Skip if it's an API route or static/templates
    if filename.startswith("api/") or filename.startswith("static/") or filename.startswith("templates/"):
        return error_response("Not found", 404)

    # Only serve .js files
    if filename.endswith(".js"):
        # SECURITY: Block access to raw JS files unless authorized
        # or "encrypt" (obfuscate) the content for viewers
        
        # Check if authorized to view raw source
        is_authorized = (
            request.args.get("api_key") == get_api_key() or 
            request.headers.get("X-API-Key") == get_api_key()
        )

        try:
            # Check if file exists
            file_path = os.path.join(BASE_DIR, filename)
            if not os.path.exists(file_path):
                return error_response(f"File {filename} not found", 404)
                
            # If authorized, serve raw file
            if is_authorized:
                return send_from_directory(BASE_DIR, filename, mimetype="application/javascript")
                
            # "Encrypt" / Obfuscate for public view
            # This hides the source code from casual viewing
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Simple base64 obfuscation wrapper
            import base64
            encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            obfuscated_js = f"""
/**
 * Protected Source Code
 * This content is encoded to prevent unauthorized viewing.
 */
(function() {{
    var _c = "{encoded}";
    var _d = atob(_c);
    // Execute or just show it's protected
    console.log("Protected script loaded.");
    // eval(_d); // Uncomment to execute (DANGEROUS if not trusted)
}})();
"""
            return obfuscated_js, 200, {'Content-Type': 'application/javascript'}

        except Exception as e:
            return error_response(f"Error serving file: {str(e)}", 500)

    return error_response("File not found", 404)


# ===========================
# Run
# ===========================
if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host=host, port=port)