import os
from functools import wraps
from flask import request, jsonify

# Default API Key for testing if not set in environment
DEFAULT_API_KEY = "test-api-key-12345"

def get_api_key():
    """Retrieve the configured API key."""
    return os.environ.get("JS_ANALYZER_API_KEY", DEFAULT_API_KEY)

def require_api_key(f):
    """Decorator to require API key for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check header
        api_key = request.headers.get("X-API-Key")
        # Check query param (optional, for convenience)
        if not api_key:
            api_key = request.args.get("api_key")
            
        valid_key = get_api_key()
        
        if not api_key or api_key != valid_key:
            return jsonify({
                "error": "Unauthorized", 
                "message": "Invalid or missing API key"
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function
