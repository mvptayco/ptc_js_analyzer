#!/usr/bin/env python3
"""
Enhanced JavaScript Security Analyzer
Reduced false positives, better detection patterns
"""

import re
import requests
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import urllib3

# Import from new analysis engine modules
from analysis_engine.models import AnalysisResult
from analysis_engine.patterns import SecurityPatterns
from analysis_engine.extractors import PatternExtractor
from analysis_engine.headers import (
    analyze_server_info, 
    analyze_csp, 
    analyze_cloudflare, 
    analyze_rate_limit
)
from analysis_engine.recommendations import generate_recommendations

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JavaScriptAnalyzer:
    """Enhanced analyzer with reduced false positives"""
    
    def __init__(self):
        # Initialize patterns and extractor
        self.security_patterns = SecurityPatterns()
        self.extractor = PatternExtractor(self.security_patterns)

    def fetch_js_file(self, url: str) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, str]], Optional[str]]:
        """
        Fetch JavaScript file from URL
        
        NOTE: This runs on the SERVER, not in the browser.
        The server downloads the JavaScript file for analysis.
        Returns: (content, error_message, headers, ip_address)
        """
        headers_dict = None
        ip_address = None
        
        try:
            # Fix 0.0.0.0 to localhost for local connections
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0',
            }
            
            # Timeout 5s (reduced from 10s for better performance)
            # stream=True allows us to get the IP from the connection
            response = requests.get(url, headers=headers, timeout=5, verify=False, stream=True, allow_redirects=True)
            
            # Capture headers
            headers_dict = dict(response.headers)
            
            # Extract IP address from the underlying socket connection if possible
            # This avoids a separate DNS lookup which can be slow/blocking
            try:
                if hasattr(response.raw, '_connection') and getattr(response.raw._connection, 'sock', None):
                    ip_address = response.raw._connection.sock.getpeername()[0]
            except Exception:
                # If we can't get IP, it's not critical
                pass
            
            # Handle specific status codes - but try to read content anyway for crawling
            status_error = None
            if response.status_code == 403:
                status_error = f"Access Denied (403 Forbidden). Analyzing returned content."
            elif response.status_code == 404:
                status_error = f"File not found (404). Analyzing returned content."
            elif response.status_code == 401:
                status_error = f"Unauthorized (401). Analyzing returned content."
            elif response.status_code >= 400:
                status_error = f"Server returned status {response.status_code}. Analyzing returned content."
                
            if not status_error:
                response.raise_for_status()
            
            # Check content type - some servers return wrong content type
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check content length
            content_length = response.headers.get('Content-Length')
            if content_length:
                try:
                    size_mb = int(content_length) / (1024 * 1024)
                    if size_mb > 10:  # Reduced Limit to 10MB for performance
                        return None, f"File too large ({size_mb:.1f}MB). Max limit is 10MB.", headers_dict, ip_address
                except (ValueError, TypeError):
                    pass
            
            # Read content in chunks for large files
            content = ""
            max_size = 10 * 1024 * 1024  # 10MB limit for performance
            try:
                # Always read raw bytes and decode manually to avoid UnicodeDecodeError in stream
                # and to strictly enforce size limits
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                    if chunk:
                        # Decode chunk safely
                        chunk_str = chunk.decode('utf-8', errors='ignore')
                        content += chunk_str
                        
                        if len(content) > max_size:
                            # Truncate if too large
                            content = content[:max_size]
                            break
            except Exception as e:
                # If streaming fails, we might have partial content which is better than nothing
                if not content:
                     return None, f"Error reading stream: {str(e)}", headers_dict, ip_address
            
            if content:
                return content, status_error, headers_dict, ip_address
            else:
                return None, status_error or "Empty response received.", headers_dict, ip_address
            
        except requests.exceptions.Timeout:
            return None, "Connection timed out (120s limit exceeded).", headers_dict, ip_address
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {str(e)}", headers_dict, ip_address
        except requests.exceptions.RequestException as e:
            return None, f"Request failed: {str(e)}", headers_dict, ip_address
        except Exception as e:
            return None, f"Unexpected error: {str(e)}", headers_dict, ip_address

    def generate_recommendations(self, result: AnalysisResult) -> List[Dict[str, Any]]:
        """Proxy to the imported generate_recommendations function"""
        return generate_recommendations(result)

    def analyze_content(self, content: str, url: str = "local") -> AnalysisResult:
        """
        Analyze JavaScript content directly
        """
        errors = []
        file_size = len(content)
        
        # Run all analyses with error handling
        try:
            api_keys = self.extractor.find_patterns(content, self.security_patterns.api_key_patterns)
        except Exception as e:
            errors.append(f"Error analyzing API keys: {str(e)}")
            api_keys = []
        
        try:
            credentials = self.extractor.find_patterns(content, self.security_patterns.credential_patterns)
        except Exception as e:
            errors.append(f"Error analyzing credentials: {str(e)}")
            credentials = []
        
        try:
            emails = self.extractor.find_patterns(content, self.security_patterns.email_patterns)
        except Exception as e:
            errors.append(f"Error analyzing emails: {str(e)}")
            emails = []
        
        try:
            interesting_comments = self.extractor.find_patterns(content, self.security_patterns.comment_patterns)
        except Exception as e:
            errors.append(f"Error analyzing comments: {str(e)}")
            interesting_comments = []
        
        try:
            xss_vulnerabilities = self.extractor.find_patterns(content, self.security_patterns.xss_patterns)
        except Exception as e:
            errors.append(f"Error analyzing XSS vulnerabilities: {str(e)}")
            xss_vulnerabilities = []
            
        try:
            xss_functions = self.extractor.find_patterns(content, self.security_patterns.xss_function_patterns)
        except Exception as e:
            errors.append(f"Error analyzing XSS functions: {str(e)}")
            xss_functions = []
            
        try:
            api_endpoints = self.extractor.extract_api_endpoints(content)
        except Exception as e:
            errors.append(f"Error extracting API endpoints: {str(e)}")
            api_endpoints = []
            
        try:
            parameters = self.extractor.extract_parameters(content)
        except Exception as e:
            errors.append(f"Error extracting parameters: {str(e)}")
            parameters = []
            
        try:
            paths_directories = self.extractor.extract_paths(content)
            
            # If it looks like HTML, try to extract script tags too
            if '<html' in content.lower() or '<script' in content.lower() or '<!doctype html>' in content.lower():
                html_scripts = self.extractor.extract_html_scripts(content, url)
                # Convert to path format
                for script in html_scripts:
                    paths_directories.append(script)
                    
        except Exception as e:
            errors.append(f"Error extracting paths: {str(e)}")
            paths_directories = []
            
        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            emails=emails,
            interesting_comments=interesting_comments,
            xss_vulnerabilities=xss_vulnerabilities,
            xss_functions=xss_functions,
            api_endpoints=api_endpoints,
            parameters=parameters,
            paths_directories=paths_directories,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat()
        )

    def analyze(self, url: str) -> AnalysisResult:
        """
        Analyze JavaScript file for security issues
        
        ALL ANALYSIS HAPPENS SERVER-SIDE:
        - Fetches JavaScript file from URL (server-side HTTP request)
        - Runs regex patterns to find sensitive data
        - Extracts API endpoints, parameters, paths
        - Detects XSS vulnerabilities
        - Returns structured results
        
        No processing happens in the browser - only results are sent back.
        """
        errors = []
        
        try:
            # Try to fetch the file
            original_url = url
            # Fix 0.0.0.0 to localhost
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            
            content, error_msg, headers, ip_address = self.fetch_js_file(url)
            
            if content is None:
                # Try with 127.0.0.1 if localhost failed
                if 'localhost' in url:
                    url_alt = url.replace('localhost', '127.0.0.1')
                    content_alt, error_msg_alt, headers_alt, ip_alt = self.fetch_js_file(url_alt)
                    if content_alt:
                        content = content_alt
                        url = url_alt
                        error_msg = error_msg_alt
                        headers = headers_alt
                        ip_address = ip_alt
                
                if content is None:
                    final_error = f"Failed to fetch {original_url}. "
                    if error_msg:
                        final_error += error_msg
                    else:
                        final_error += "The file may be too large, inaccessible, or the server timed out."
                        
                    if '0.0.0.0' in original_url:
                        final_error += " Note: 0.0.0.0 is not a valid address to connect to. Please use 'localhost' or '127.0.0.1' instead. "
                    
                    errors.append(final_error)
                    return AnalysisResult(
                        url=url,
                        api_keys=[],
                        credentials=[],
                        emails=[],
                        interesting_comments=[],
                        xss_vulnerabilities=[],
                        xss_functions=[],
                        api_endpoints=[],
                        parameters=[],
                        paths_directories=[],
                        errors=errors,
                        file_size=0,
                        analysis_timestamp=datetime.now().isoformat()
                    )
            
            # Analyze content
            result = self.analyze_content(content, url)
            
            # Add server info if available
            if headers:
                result.server_info = analyze_server_info(headers)
                result.csp_info = analyze_csp(headers)
                result.cloudflare_analysis = analyze_cloudflare(headers, ip_address)
                result.rate_limit_info = analyze_rate_limit(headers)
            
            if ip_address:
                result.ip_address = ip_address
                
            # Generate recommendations
            result.recommendations = self.generate_recommendations(result)
            
            return result
            
        except Exception as e:
            errors.append(f"Analysis failed: {str(e)}")
            return AnalysisResult(
                url=url,
                api_keys=[],
                credentials=[],
                emails=[],
                interesting_comments=[],
                xss_vulnerabilities=[],
                xss_functions=[],
                api_endpoints=[],
                parameters=[],
                paths_directories=[],
                errors=errors,
                file_size=0,
                analysis_timestamp=datetime.now().isoformat()
            )
