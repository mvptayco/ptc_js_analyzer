"""
Analysis Engine Patterns
Contains regex patterns for security analysis
"""

class SecurityPatterns:
    """Container for all security analysis patterns"""
    
    def __init__(self):
        # Improved API key patterns - more specific to reduce false positives
        self.api_key_patterns = [
            # AWS - very specific
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', True),
            (r'(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key', True),
            
            # Google API - specific format
            (r'AIza[0-9A-Za-z\-]{35}', 'Google API Key', True),
            (r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\'](AIza[0-9A-Za-z\-]{35})["\']', 'Google API Key', True),
            
            # GitHub tokens - specific prefixes
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', True),
            (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained Token', True),
            
            # Stripe - specific prefixes
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Secret Key', True),
            (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Secret Key', True),
            (r'pk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Publishable Key', True),
            (r'pk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Publishable Key', True),
            
            # PayPal
            (r'access_token\$production\$[a-zA-Z0-9]{22}\$[a-zA-Z0-9]{86}', 'PayPal Access Token', True),
            
            # Slack
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,48}', 'Slack Token', True),
            
            # Firebase
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging Token', True),
            
            # Twilio
            (r'AC[a-z0-9]{32}', 'Twilio Account SID', True),
            (r'SK[a-z0-9]{32}', 'Twilio API Key', True),
            
            # SendGrid
            (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'SendGrid API Key', True),
            
            # Mailgun
            (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key', True),
            
            # DigitalOcean
            (r'dop_v1_[a-f0-9]{64}', 'DigitalOcean Personal Access Token', True),
            
            # Heroku
            (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'Heroku API Key', False), # High false positive rate
            
            # Square
            (r'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token', True),
            (r'sq0csp-[0-9A-Za-z\-_]{43}', 'Square Client Secret', True),

            # JWT - but filter out common false positives
            (r'\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]{10,}\b', 'JWT Token', False),
            
            # Generic - only if it looks like a real key (not just variable names)
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Generic API Key', False),
            (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{20,})["\']', 'Secret Key', False),
            
            # From js_analyzer.py (Legacy/CLI patterns) - Broadened scope
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*([a-zA-Z0-9_\-]{20,})', 'Generic API Key (no quotes)', False),
            (r'(?i)(token|auth[_-]?token|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Generic Token', False),
        ]
        
        # Credentials - more specific
        self.credential_patterns = [
            # Passwords - avoid common false positives like "password: false"
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Password', False),
            (r'(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Database Password', False),
            (r'(?i)(username|user[_-]?name|login)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Username', False),
        ]
        
        # Email patterns - more accurate
        self.email_patterns = [
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'Email Address', True),
        ]
        
        # IP Address patterns
        self.ip_patterns = [
            # IPv4 - strict matching to avoid version numbers etc
            (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 'IPv4 Address', True),
            # IPv6 - basic matching
            (r'\b([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}\b', 'IPv6 Address', True),
        ]
        
        # Comments
        self.comment_patterns = [
            (r'//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING|TEMP)', 'Interesting Comment', True),
            (r'/\*[\s\S]{0,500}?(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)[\s\S]{0,500}?\*/', 'Interesting Comment (Multi-line)', True),
            (r'//\s*(password|secret|key|token|admin|backdoor|debug|test|hardcoded)', 'Suspicious Comment', False),
        ]
        
        # XSS patterns - improved
        self.xss_patterns = [
            (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML Assignment', 'high'),
            (r'\.outerHTML\s*=\s*([^;]+)', 'outerHTML Assignment', 'high'),
            (r'document\.body\.innerHTML\s*=\s*([^;]+)', 'document.body.innerHTML', 'critical'),
            (r'\.insertAdjacentHTML\s*\([^,]+,\s*([^)]+)\)', 'insertAdjacentHTML', 'high'),
            (r'document\.write\s*\(([^)]+)\)', 'document.write()', 'high'),
            (r'document\.writeln\s*\(([^)]+)\)', 'document.writeln()', 'high'),
            (r'eval\s*\([^)]*?\b(\$|location|window\.|document\.|user|input|param|query|search|code|data|str|cmd|command|expr)\b', 'eval() with User Input', 'critical'),
            (r'new\s+Function\s*\([^)]*\)', 'new Function() (eval)', 'critical'),
            (r'dangerouslySetInnerHTML\s*=\s*\{[^}]*\}', 'React dangerouslySetInnerHTML', 'high'),
            (r'\$\([^)]+\)\.html\s*\(([^)]+)\)', 'jQuery .html()', 'medium'),
            (r'\$\([^)]+\)\.append\s*\(([^)]+)\)', 'jQuery .append()', 'medium'),
            (r'\$\([^)]+\)\.prepend\s*\(([^)]+)\)', 'jQuery .prepend()', 'medium'),
            (r'\$\([^)]+\)\.wrap\s*\(([^)]+)\)', 'jQuery .wrap()', 'medium'),
            (r'\$\([^)]+\)\.replaceWith\s*\(([^)]+)\)', 'jQuery .replaceWith()', 'medium'),
            (r'location\.(href|hash|search|pathname)\s*=\s*([^;]+)', 'Location Manipulation', 'medium'),
            (r'location\.assign\s*\(([^)]+)\)', 'location.assign()', 'medium'),
            (r'location\.replace\s*\(([^)]+)\)', 'location.replace()', 'medium'),
            (r'innerHTML\s*[+\=]\s*["\']', 'innerHTML Concatenation', 'high'),
            (r'javascript:\s*[^"\']+', 'javascript: Protocol', 'high'),
            (r'setTimeout\s*\(\s*["\']([^"\']+)["\']', 'setTimeout with String (eval)', 'high'),
            (r'setInterval\s*\(\s*["\']([^"\']+)["\']', 'setInterval with String (eval)', 'high'),
            (r'\.setAttribute\s*\(\s*["\'](on\w+|src|href|srcdoc)["\']\s*,\s*[^)]+\)', 'Dangerous setAttribute', 'high'),
            (r'\.setAttribute\s*\(\s*["\']onclick["\']\s*,\s*([^)]+)\)', 'setAttribute(onclick)', 'high'),
            (r'document\.execCommand\s*\(([^)]+)\)', 'document.execCommand', 'medium'),
            (r'window\.open\s*\(([^)]+)\)', 'window.open with User Input', 'medium'),
            (r'window\.name\s*=\s*([^;]+)', 'window.name Assignment', 'medium'),
            (r'document\.cookie\s*=\s*([^;]+)', 'Cookie Manipulation', 'medium'),
            (r'\$sce\.trustAsHtml\s*\(([^)]+)\)', 'AngularJS $sce.trustAsHtml', 'high'),
            (r'ng-bind-html\s*=\s*["\']([^"\']+)["\']', 'AngularJS ng-bind-html', 'medium'),
            (r'v-html\s*=\s*["\']([^"\']+)["\']', 'Vue v-html', 'high'),
        ]
        
        # XSS function patterns - functions that might lead to XSS
        self.xss_function_patterns = [
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML|write|insertAdjacentHTML)', 'Function with DOM Manipulation', 'high'),
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*eval\s*\(', 'Function with eval()', 'critical'),
            (r'(\w+)\s*[:=]\s*function\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML|write)', 'Arrow function with DOM manipulation', 'high'),
            (r'\.(onclick|onerror|onload|onmouseover|onmouseout|onkeydown|onkeypress|onkeyup)\s*=\s*function', 'Event handler assignment', 'medium'),
            (r'window\.addEventListener\s*\(\s*["\']message["\']\s*,', 'postMessage Listener (Check Origin!)', 'medium'),
        ]
        
        # API patterns
        self.api_patterns = [
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch()'),
            (r'fetch\s*\(\s*`([^`]+)`', 'fetch() (template)'),
            (r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']', 'XMLHttpRequest'),
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios (config)'),
            (r'\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'\$\.(ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', 'jQuery AJAX (short)'),
            (r'\$\.getJSON\s*\(\s*["\']([^"\']+)["\']', 'jQuery getJSON'),
            (r'["\'](/api/[^"\']+)["\']', 'API Path'),
            (r'["\'](/v\d+/[^"\']+)["\']', 'API Versioned Path'),
            (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
            (r'api[_-]?url\s*[:=]\s*["\']([^"\']+)["\']', 'API URL Variable'),
        ]
        
        # Parameter patterns - comprehensive detection of ALL parameters
        self.parameter_patterns = [
            # URL query parameters - ALL parameters (not just sensitive ones)
            # Pattern: ?param=value or &param=value
            (r'["\']([^"\']*[?&](\w+)\s*=\s*[^"\'&\s]+)["\']', 'URL Query Parameter'),
            (r'[?&](\w+)\s*=\s*([^&\s"\']+)', 'Query Parameter'),
            
            # Multiple parameters in URL: ?param1=value1&param2=value2
            (r'["\']([^"\']*[?&][\w\-]+\s*=\s*[^"\'&\s]+(?:\s*&\s*[\w\-]+\s*=\s*[^"\'&\s]+)+)["\']', 'URL with Multiple Parameters'),
            
            # URL patterns with any parameters
            (r'["\']([^"\']+[?&][^"\']+)["\']', 'URL with Query Parameters'),
            
            # Function parameters - ALL function definitions
            # (r'function\s+(\w+)\s*\(([^)]+)\)', 'Function Parameters'),
            # (r'function\s*\(([^)]+)\)', 'Anonymous Function Parameters'),
            # (r'(\w+)\s*[:=]\s*function\s*\(([^)]+)\)', 'Function Expression Parameters'),
            # (r'\(([^)]+)\)\s*=>', 'Arrow Function Parameters'),
            # (r'const\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (const)'),
            # (r'let\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (let)'),
            # (r'var\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (var)'),
            
            # Method parameters
            # (r'\.(\w+)\s*\(([^)]+)\)', 'Method Call Parameters'),
            
            # URLSearchParams - extract all parameters
            (r'URLSearchParams\s*\([^)]*\)', 'URL Parameters Object'),
            (r'new\s+URLSearchParams\s*\(([^)]+)\)', 'URLSearchParams Constructor'),
            (r'\.get\s*\(["\']([^"\']+)["\']', 'URLSearchParams.get()'),
            (r'\.getAll\s*\(["\']([^"\']+)["\']', 'URLSearchParams.getAll()'),
            (r'\.has\s*\(["\']([^"\']+)["\']', 'URLSearchParams.has()'),
            
            # Request parameters - ALL HTTP methods
            (r'\.(get|post|put|delete|patch|head|options)\s*\([^,]+,\s*\{([^}]+)\}', 'Request Parameters'),
            (r'\.(get|post|put|delete|patch)\s*\([^,]+,\s*([^,)]+)\)', 'Request Parameters (short)'),
            (r'fetch\s*\([^,]+,\s*\{([^}]+)\}', 'Fetch Request Parameters'),
            (r'axios\s*\(\s*\{([^}]+)\}', 'Axios Request Parameters'),
            
            # URL constructor with parameters
            (r'new\s+URL\s*\([^,]+,\s*["\']([^"\']+)["\']', 'URL Constructor with Parameters'),
            
            # Location/search patterns - ALL location parameters
            (r'location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Location with Parameters'),
            (r'window\.location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Window Location with Parameters'),
            (r'document\.location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Document Location with Parameters'),
            
            # Template literals with parameters
            (r'`([^`]*[?&]\w+\s*=\s*[^`&]+)`', 'Template Literal with Parameters'),
            
            # Object/JSON parameters
            (r'\{([^};]+:\s*[^,};]+(?:,\s*[^};]+:\s*[^,};]+)*)\}', 'Object Parameters'),
            
            # Destructuring parameters
            (r'const\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (const)'),
            (r'let\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (let)'),
            (r'var\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (var)'),
            (r'function\s+\w+\s*\(\{([^}]+)\}\)', 'Function with Destructuring'),
            
            # Array destructuring
            (r'const\s+\[([^\]]+)\]\s*=', 'Array Destructuring (const)'),
            (r'let\s+\[([^\]]+)\]\s*=', 'Array Destructuring (let)'),
            
            # Event handler parameters
            (r'\.(on\w+)\s*=\s*function\s*\(([^)]+)\)', 'Event Handler Parameters'),
            (r'\.addEventListener\s*\(["\']([^"\']+)["\'],\s*function\s*\(([^)]+)\)', 'EventListener Parameters'),
            (r'\.addEventListener\s*\(["\']([^"\']+)["\'],\s*\(([^)]+)\)\s*=>', 'EventListener Arrow Parameters'),
            
            # Callback parameters
            # (r'\.(then|catch|finally)\s*\(([^)]+)\)', 'Promise Callback Parameters'),
            # (r'\.(map|filter|reduce|forEach|find)\s*\(([^)]+)\)', 'Array Method Parameters'),
        ]
        
        # Path and directory patterns
        self.path_patterns = [
            (r'["\']\s*(https?://[a-zA-Z0-9\-\.]+(?:\:[0-9]+)?(?:/[a-zA-Z0-9_\-\./\?%&=]*)?)\s*["\']', 'Hardcoded URL'),
            (r'["\'](/[a-zA-Z0-9_\-/]+)["\']', 'Path'),
            (r'["\'](\.\.?/[a-zA-Z0-9_\-/]+)["\']', 'Relative Path'),
            (r'path\s*[:=]\s*["\']([^"\']+)["\']', 'Path Variable'),
            (r'dir\s*[:=]\s*["\']([^"\']+)["\']', 'Directory Variable'),
            (r'["\']([a-zA-Z0-9_\-/]+\.(js|json|html|css|png|jpg|svg))["\']', 'File Path'),
            (r'["\'](/etc/[a-zA-Z0-9_\-/]+)["\']', 'System Path (Linux)'),
            (r'["\']([C-Z]:\\[a-zA-Z0-9_\\\-]+)["\']', 'System Path (Windows)'),
            (r'["\'](/var/[a-zA-Z0-9_\-/]+)["\']', 'System Path (Var)'),
            (r'["\'](/home/[a-zA-Z0-9_\-/]+)["\']', 'Home Directory Path'),
        ]

        # Server Info patterns
        self.server_info_patterns = [
            (r'["\'](X-Powered-By)\s*[:=]\s*([^"\']+)["\']', 'Server Header (X-Powered-By)', True),
            (r'["\'](Server)\s*[:=]\s*([^"\']+)["\']', 'Server Header (Server)', True),
            (r'["\'](Apache/[0-9\.]+)["\']', 'Apache Version', True),
            (r'["\'](Nginx/[0-9\.]+)["\']', 'Nginx Version', True),
            (r'["\'](IIS/[0-9\.]+)["\']', 'IIS Version', True),
            (r'["\'](PHP/[0-9\.]+)["\']', 'PHP Version', True),
            (r'["\'](Werkzeug/[0-9\.]+)["\']', 'Werkzeug Version', True),
        ]

        # Library/Dependency Patterns
        self.library_patterns = [
            (r'jQuery\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'jQuery Version', True),
            (r'React\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'React Version', True),
            (r'Vue\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'Vue.js Version', True),
            (r'AngularJS\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'AngularJS Version', True),
            (r'Bootstrap\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'Bootstrap Version', True),
            (r'Lodash\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'Lodash Version', True),
            (r'Moment\.js\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'Moment.js Version', True),
            (r'axios\s*v?([0-9]+\.[0-9]+\.[0-9]+)', 'Axios Version', True),
            (r'["\'](react)["\']\s*:', 'React Dependency', False),
            (r'["\'](vue)["\']\s*:', 'Vue Dependency', False),
            (r'["\'](jquery)["\']\s*:', 'jQuery Dependency', False),
            (r'window\.jQuery\s*=', 'jQuery Global', True),
            (r'window\.React\s*=', 'React Global', True),
            (r'window\.Vue\s*=', 'Vue Global', True),
        ]

        # Obfuscation & Source Map Patterns
        self.obfuscation_patterns = [
            (r'//#\s*sourceMappingURL=([^\s]+)', 'Source Map (v3)', True),
            (r'//@\s*sourceMappingURL=([^\s]+)', 'Source Map (Legacy)', True),
            (r'eval\(function\(p,a,c,k,e,d\)', 'Packed/Obfuscated Code (Dean Edwards)', True),
            (r'var\s+_0x[a-f0-9]+', 'Obfuscated Variable (_0x...)', False),
            (r'\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}', 'Hex Encoded Strings', False),
        ]


        # Common CSS properties to filter out
        self.css_props = {
            'box-sizing', 'font-family', 'margin', 'padding', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
            'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
            'color', 'background', 'background-color', 'background-image', 'border', 'border-radius',
            'display', 'text-align', 'width', 'height', 'min-width', 'max-width', 'min-height', 'max-height',
            'position', 'top', 'left', 'right', 'bottom', 'z-index',
            'overflow', 'overflow-x', 'overflow-y', 'flex', 'flex-direction', 'flex-wrap', 'align-items', 'justify-content',
            'transform', 'transition', 'animation', 'opacity',
            'line-height', 'font-size', 'font-weight', 'cursor',
            'content', 'outline', 'visibility', 'list-style',
            'text-decoration', 'white-space', 'vertical-align',
            'box-shadow', 'text-shadow', 'fill', 'stroke', 'stop-color',
            'font-style', 'letter-spacing', 'gap', 'grid', 'grid-template-columns',
            'pointer-events', 'user-select', 'object-fit'
        }
        
        # Common CSS values/units to filter out
        self.css_values_regex = r'^(-?[\d.]+(px|rem|em|vh|vw|%|pt|pc|in|cm|mm|ex|ch)|(none|block|flex|grid|inline|hidden|visible|auto|inherit|initial|unset))$'
