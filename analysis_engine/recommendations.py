"""
Analysis Engine Recommendations
"""
from typing import List, Dict, Any, Set
from .models import AnalysisResult

def generate_recommendations(result: AnalysisResult) -> List[Dict[str, Any]]:
    """Generate dynamic security recommendations based on specific analysis findings"""
    recommendations = []
    
    # Track added recommendation titles to avoid duplicates
    added_titles: Set[str] = set()
    
    def add_rec(priority: str, category: str, title: str, description: str):
        if title not in added_titles:
            recommendations.append({
                'priority': priority,
                'category': category,
                'title': title,
                'description': description
            })
            added_titles.add(title)

    # 1. API Keys & Secrets
    if result.api_keys:
        aws_keys = [k for k in result.api_keys if 'AWS' in k.get('type', '')]
        google_keys = [k for k in result.api_keys if 'Google' in k.get('type', '')]
        stripe_keys = [k for k in result.api_keys if 'Stripe' in k.get('type', '')]
        github_keys = [k for k in result.api_keys if 'GitHub' in k.get('type', '')]
        
        if aws_keys:
            add_rec('Critical', 'Secrets Management', 'AWS Credentials Exposed', 
                   f"Found {len(aws_keys)} AWS keys. Immediately rotate these keys. "
                   "Use IAM Roles for EC2/Lambda, or environment variables. "
                   "Never commit AWS keys to version control.")
            
        if google_keys:
            add_rec('High', 'Secrets Management', 'Google API Keys Exposed',
                   f"Found {len(google_keys)} Google API keys. Ensure these keys have "
                   "referrer/IP restrictions configured in the Google Cloud Console. "
                   "If these are backend keys, move them to environment variables.")
            
        if stripe_keys:
            add_rec('High', 'Secrets Management', 'Stripe Keys Exposed',
                   f"Found {len(stripe_keys)} Stripe keys. Ensure 'sk_live' (Secret Keys) "
                   "are NEVER exposed on the client-side. Only 'pk_' (Publishable Keys) "
                   "should be visible in JavaScript.")
            
        if github_keys:
            add_rec('Critical', 'Secrets Management', 'GitHub Tokens Exposed',
                   f"Found {len(github_keys)} GitHub tokens. Revoke these immediately. "
                   "Exposed tokens can allow attackers to access private repositories "
                   "or modify code.")
            
        # Generic catch-all if specific ones weren't the only ones
        if len(result.api_keys) > (len(aws_keys) + len(google_keys) + len(stripe_keys) + len(github_keys)):
            add_rec('High', 'Secrets Management', 'Hardcoded API Keys',
                   "Generic API keys found. Move all secrets to environment variables "
                   "(.env files) or a secure secrets manager (Vault, AWS Secrets Manager).")

    # 2. Credentials
    if result.credentials:
        add_rec('Critical', 'Secrets Management', 'Hardcoded Credentials',
               f"Found {len(result.credentials)} potential passwords or usernames. "
               "Hardcoding credentials poses a severe security risk. "
               "Rotate passwords immediately and use environment variables.")

    # 3. XSS Vulnerabilities
    if result.xss_vulnerabilities:
        inner_html = [x for x in result.xss_vulnerabilities if 'innerHTML' in x.get('type', '')]
        eval_usage = [x for x in result.xss_vulnerabilities if 'eval' in x.get('type', '').lower() or 'Function' in x.get('type', '')]
        doc_write = [x for x in result.xss_vulnerabilities if 'document.write' in x.get('type', '')]
        danger_react = [x for x in result.xss_vulnerabilities if 'dangerouslySetInnerHTML' in x.get('type', '')]
        vue_html = [x for x in result.xss_vulnerabilities if 'v-html' in x.get('type', '')]
        
        if inner_html:
            add_rec('High', 'XSS Prevention', 'Unsafe DOM Manipulation',
                   "Detected usage of 'innerHTML' or 'outerHTML'. This can lead to DOM-based XSS. "
                   "Use safer alternatives like 'textContent', 'innerText', or DOM creation methods "
                   "(document.createElement).")
            
        if eval_usage:
            add_rec('Critical', 'Code Injection', 'Dangerous Code Execution',
                   "Detected usage of 'eval()' or 'new Function()'. "
                   "This is extremely dangerous and allows arbitrary code execution. "
                   "Refactor code to avoid dynamic evaluation. Use JSON.parse() for JSON data.")
            
        if doc_write:
            add_rec('Medium', 'XSS Prevention', 'Deprecated DOM Methods',
                   "Detected usage of 'document.write()'. This is poor practice and can be dangerous. "
                   "Use modern DOM manipulation methods instead.")
            
        if danger_react:
            add_rec('High', 'Framework Security', 'Unsafe React Pattern',
                   "Detected 'dangerouslySetInnerHTML' in React. Ensure content is sanitized "
                   "using a library like DOMPurify before rendering.")
            
        if vue_html:
            add_rec('High', 'Framework Security', 'Unsafe Vue Pattern',
                   "Detected 'v-html' in Vue. This bypasses auto-escaping. "
                   "Use 'v-text' or curly braces {{ }} for untrusted content, "
                   "or sanitize the HTML first.")
                   
        # Generic XSS advice if no specific categories matched but vulnerabilities exist
        if not (inner_html or eval_usage or doc_write or danger_react or vue_html):
             add_rec('High', 'XSS Prevention', 'Potential XSS Vectors',
                    "Found potential XSS vectors. Ensure all user input is validated and encoded "
                    "before rendering to the DOM.")

    # 4. Security Headers (CSP, etc.)
    if result.csp_info:
        if result.csp_info.get('weaknesses'):
            add_rec('Medium', 'Security Headers', 'Weak Content Security Policy',
                   "CSP is present but has weaknesses: " + ", ".join(result.csp_info['weaknesses']) + 
                   ". Tighten policies by avoiding 'unsafe-inline' and 'unsafe-eval'.")
        elif not result.csp_info.get('raw'):
            # This logic depends on how analyze_csp returns data when missing
             pass 
    
    # Check specifically for missing CSP if we analyzed a URL
    if result.url and result.url.startswith('http') and (not result.csp_info or not result.csp_info.get('raw')):
        add_rec('Medium', 'Security Headers', 'Missing Content Security Policy',
               "No Content Security Policy (CSP) header detected. "
               "Implement CSP to mitigate XSS attacks. Start with a report-only policy.")

    # Server Info Leakage
    if result.server_info and result.server_info.get('x_powered_by'):
        add_rec('Low', 'Information Disclosure', 'Server Banner Exposure',
               f"Server is leaking technology details via X-Powered-By: {result.server_info['x_powered_by']}. "
               "Remove this header in server configuration to make reconnaissance harder for attackers.")

    # 5. Rate Limiting
    if result.rate_limit_info:
        if not result.rate_limit_info.get('is_present'):
            add_rec('Medium', 'DoS Prevention', 'Missing Rate Limiting',
                   "No rate limiting headers were detected. "
                   "Implement rate limiting (via Nginx, API Gateway, or WAF) to prevent "
                   "brute-force attacks and Denial of Service (DoS).")
        else:
            # If present, maybe verify if it's strict enough? (Hard to tell automatically)
            provider = result.rate_limit_info.get('provider', 'Unknown')
            if provider != 'Unknown':
                 add_rec('Info', 'DoS Prevention', 'Rate Limiting Detected',
                        f"Rate limiting is active via {provider}. Monitor logs to ensure limits "
                        "are appropriate for legitimate traffic.")

    # 6. Cloudflare / WAF
    if result.cloudflare_analysis:
        cf = result.cloudflare_analysis
        if cf.get('uses_cloudflare'):
            if not cf.get('is_proxied'):
                add_rec('High', 'Infrastructure', 'Cloudflare Proxy Disabled',
                       "Domain is using Cloudflare DNS but not the Proxy (Orange Cloud). "
                       "The origin IP is likely exposed. Enable the Proxy to benefit from "
                       "WAF, DDoS protection, and IP masking.")
            else:
                 add_rec('Info', 'Infrastructure', 'Cloudflare Protected',
                        "Website is proxied through Cloudflare. Ensure 'Authenticated Origin Pulls' "
                        "are enabled so the origin server only accepts traffic from Cloudflare.")

    return recommendations
