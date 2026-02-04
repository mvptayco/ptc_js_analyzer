"""
Analysis Engine Header Analysis
"""
from typing import Dict, Any, Optional, List

def analyze_server_info(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """Analyze server information from headers"""
    if not headers:
        return None
        
    info = {}
    server_header = headers.get('Server', headers.get('server', ''))
    if server_header:
        info['server_header'] = server_header
        # Detect specific servers
        if 'nginx' in server_header.lower():
            info['type'] = 'Nginx'
        elif 'apache' in server_header.lower():
            info['type'] = 'Apache'
        elif 'cloudflare' in server_header.lower():
            info['type'] = 'Cloudflare'
        elif 'microsoft-iis' in server_header.lower():
            info['type'] = 'IIS'
        else:
            info['type'] = 'Unknown'
    
    # Check for other interesting headers
    powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
    if powered_by:
        info['x_powered_by'] = powered_by
        
    info['technique'] = 'HTTP Header Analysis'
    return info if info else None

def analyze_csp(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """Analyze Content Security Policy"""
    if not headers:
        return None
        
    csp_header = headers.get('Content-Security-Policy', headers.get('content-security-policy', ''))
    
    if not csp_header:
        # Return object indicating missing CSP so UI can show "CSP Missing"
        return {
            'is_present': False,
            'raw': None,
            'directives': {},
            'weaknesses': ["CSP Header is missing"],
            'technique': 'HTTP Header Analysis'
        }
        
    csp_info = {
        'is_present': True,
        'raw': csp_header,
        'directives': {},
        'weaknesses': [],
        'technique': 'HTTP Header Analysis'
    }
    
    # Parse directives
    for directive in csp_header.split(';'):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split(None, 1)
        name = parts[0].lower()
        value = parts[1] if len(parts) > 1 else ''
        csp_info['directives'][name] = value
        
    # Check for weaknesses
    directives = csp_info['directives']
    
    if 'script-src' in directives:
        if "'unsafe-inline'" in directives['script-src']:
            csp_info['weaknesses'].append("script-src allows 'unsafe-inline' (High Risk)")
        if "'unsafe-eval'" in directives['script-src']:
            csp_info['weaknesses'].append("script-src allows 'unsafe-eval' (Medium Risk)")
        if '*' in directives['script-src'] and not ("'self'" in directives['script-src'] and len(directives['script-src']) < 10):
            csp_info['weaknesses'].append("script-src allows wildcard '*' (High Risk)")
    elif 'default-src' not in directives:
            csp_info['weaknesses'].append("No script-src or default-src defined (High Risk)")
            
    if 'default-src' in directives and '*' in directives['default-src']:
            csp_info['weaknesses'].append("default-src allows wildcard '*' (Medium Risk)")
            
    return csp_info

def analyze_cloudflare(headers: Optional[Dict[str, str]], ip_address: Optional[str]) -> Optional[Dict[str, Any]]:
    """Analyze Cloudflare presence and effectiveness"""
    if not headers:
        return None
        
    cf_info = {
        'is_present': False,
        'details': []
    }
    
    # Check headers
    server = headers.get('Server', headers.get('server', '')).lower()
    cf_ray = headers.get('CF-RAY', headers.get('cf-ray', ''))
    cf_cache = headers.get('CF-Cache-Status', headers.get('cf-cache-status', ''))
    
    if 'cloudflare' in server or cf_ray:
        cf_info['is_present'] = True
        cf_info['details'].append("Cloudflare headers detected")
        
        if cf_cache:
            cf_info['details'].append(f"Cache Status: {cf_cache}")
    
    # Check IP (simple check if we had a range database, but for now just rely on headers/logic)
    # Real implementation would check IP ranges. 
    # For now, we assume if headers are there, it's proxied.
    
    if cf_info['is_present']:
        cf_info['technique'] = 'HTTP Header Analysis'
        return cf_info
    return None

def analyze_rate_limit(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """Analyze Rate Limiting information"""
    if not headers:
        return None
        
    rl_info = {
        'is_present': False,
        'details': [],
        'provider': 'Unknown',
        'technique': 'HTTP Header Analysis'
    }
    
    # Check standard headers
    rl_headers = [
        'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset',
        'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset',
        'Retry-After'
    ]
    
    found_headers = []
    for h in rl_headers:
        # Case insensitive check
        val = headers.get(h) or headers.get(h.lower())
        if val:
            found_headers.append(f"{h}: {val}")
    
    if found_headers:
        rl_info['is_present'] = True
        rl_info['details'].extend(found_headers)
        rl_info['provider'] = 'Standard/Custom'
        
    # Check provider specific headers
    # Cloudflare
    if headers.get('CF-RAY') or headers.get('cf-ray'):
            # Cloudflare usually has built-in DDoS protection/rate limiting
            if not rl_info['is_present']:
                rl_info['is_present'] = True
                rl_info['details'].append("Cloudflare Rate Limiting (inferred from CF-RAY)")
                rl_info['provider'] = 'Cloudflare'
            elif rl_info['provider'] == 'Standard/Custom':
                rl_info['provider'] = 'Cloudflare'

    # AWS WAF
    if headers.get('x-amzn-RequestId') or headers.get('X-Amz-Cf-Id'):
            if not rl_info['is_present']: # Only if not already found (or maybe AWS adds standard headers too)
                pass # AWS doesn't always expose rate limit headers unless 429
            
            # If we saw 429 earlier (not checking status code here, only headers), we might know.
            # But here we only check headers of a successful (or failed) request.
    
    # Akamai
    if headers.get('X-Akamai-Trans-Id'):
            rl_info['is_present'] = True
            rl_info['provider'] = 'Akamai'

    return rl_info if rl_info['is_present'] else None
