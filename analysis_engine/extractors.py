"""
Analysis Engine Extractors
Contains logic for extracting patterns, parameters, and endpoints
"""
import re
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse
from analysis_engine.patterns import SecurityPatterns

class PatternExtractor:
    """Extractor for security patterns"""
    
    def __init__(self, security_patterns: SecurityPatterns):
        self.patterns = security_patterns
        self.css_props = self.patterns.css_props
        self.css_values_regex = self.patterns.css_values_regex

    def _is_subdomain(self, url: str, base_url: str) -> bool:
        """Check if url is a subdomain of base_url"""
        if not base_url or not url:
            return False
            
        try:
            # Handle relative URLs - not subdomains
            if not url.startswith(('http:', 'https:', '//')):
                return False
                
            base_parsed = urlparse(base_url)
            url_parsed = urlparse(url)
            
            base_domain = base_parsed.netloc.lower()
            target_domain = url_parsed.netloc.lower()
            
            if not base_domain or not target_domain:
                return False
                
            # Remove port if present
            base_domain = base_domain.split(':')[0]
            target_domain = target_domain.split(':')[0]
            
            # Remove www.
            if base_domain.startswith('www.'):
                base_domain = base_domain[4:]
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
                
            # Exact match is not a subdomain
            if base_domain == target_domain:
                return False
                
            # Check if target is subdomain of base
            # e.g. api.example.com ends with .example.com
            if target_domain.endswith('.' + base_domain):
                return True
                
            return False
        except Exception:
            return False
        
    def is_false_positive(self, match: str, pattern_type: str) -> bool:
        """Filter out common false positives"""
        match_lower = match.lower()
        
        # General filtering for all types
        if 'example.com' in match_lower or 'localhost' in match_lower:
            return True
            
        # Placeholder values
        placeholders = ['your_api_key', 'your-api-key', 'your_password', 'your-password', 
                       'insert_key_here', 'token_here', 'api_key_here', '123456789',
                       '00000000', 'abcdef']
        if any(ph in match_lower for ph in placeholders):
            return True

        # Credentials Filtering
        if pattern_type in ['Password', 'Database Password', 'Username']:
            # Boolean values or null/undefined often get matched by generic patterns
            if re.search(r'[:=]\s*(true|false|null|undefined|""|\'\'|0|1)\s*$', match_lower):
                return True
            # Variable declarations without assignment of literal string
            if re.search(r'(var|let|const)\s+\w+\s*;\s*$', match_lower):
                return True
            # Function calls
            if re.search(r'\w+\s*\([^)]*\)', match_lower) and not re.search(r'["\']', match_lower):
                return True
        
        # CSS Filtering for Object Parameters
        if pattern_type == 'Object Parameters':
            # Common CSS properties
            if any(prop in match_lower for prop in [p + ':' for p in self.css_props]):
                return True

        # Filter out JWT tokens that are too short or look like base64 encoded data structures
        if pattern_type == 'JWT Token':
            parts = match.split('.')
            if len(parts) < 3:
                return True
            if len(match) < 50:  # Too short to be a real JWT
                return True

        return False
    
    def find_patterns(self, content: str, patterns: List[tuple], context_lines: int = 5) -> List[Dict[str, Any]]:
        """Find patterns with context and false positive filtering"""
        findings = []
        if not content:
            return findings
        
        # Handle minified files (single line) - limit context
        lines = content.split('\n')
        if len(lines) == 1 and len(content) > 10000:
            # Very long single line - likely minified, reduce context
            context_lines = 0
        
        for pattern_info in patterns:
            try:
                if len(pattern_info) == 3:
                    pattern, label, is_strict = pattern_info
                else:
                    pattern, label = pattern_info[:2]
                    is_strict = False
                
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    try:
                        match_text = match.group(0)
                        
                        # Filter false positives
                        should_check_fp = True
                        if isinstance(is_strict, bool) and is_strict:
                            should_check_fp = False
                        elif isinstance(is_strict, str):
                            should_check_fp = False 

                        if should_check_fp and self.is_false_positive(match_text, label):
                            continue
                        
                        start_pos = match.start()
                        line_num = content[:start_pos].count('\n') + 1
                        
                        # Get context with more lines
                        start_line = max(0, line_num - context_lines - 1)
                        end_line = min(len(lines), line_num + context_lines)
                        context_lines_list = lines[start_line:end_line]
                        context = '\n'.join(context_lines_list)
                        
                        # For very long lines (minified), truncate context
                        if len(context) > 1000:
                            # Show snippet around the match position
                            match_start_in_line = start_pos - content[:start_pos].rfind('\n', max(0, start_pos - 500), start_pos)
                            context_start = max(0, match_start_in_line - 200)
                            context_end = min(len(context), match_start_in_line + len(match_text) + 200)
                            context = context[context_start:context_end]
                        
                        # Get exact code snippet
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        # Truncate very long lines
                        if len(line_content) > 500:
                            line_content = line_content[:200] + "..." + line_content[-200:]
                        
                        # Calculate confidence
                        confidence = "Medium"
                        if isinstance(is_strict, bool):
                            confidence = "High" if is_strict else "Medium"
                        elif isinstance(is_strict, str):
                            # Severity map to confidence
                            if is_strict in ['critical', 'high']:
                                confidence = "High"
                            else:
                                confidence = "Medium"
                        
                        finding = {
                            'type': str(label),
                            'match': str(match_text),
                            'line': int(line_num),
                            'line_content': str(line_content.strip()),
                            'context': str(context),
                            'context_start_line': int(start_line + 1),
                            'context_end_line': int(end_line),
                            'confidence': confidence,
                        }
                        
                        if len(pattern_info) > 2 and isinstance(pattern_info[2], str):
                            finding['severity'] = str(pattern_info[2])
                        
                        findings.append(finding)
                    except Exception as e:
                        # Skip problematic matches
                        continue
            except Exception as e:
                # Skip problematic patterns
                continue
        
        # Deduplication
        unique_findings = []
        seen = set()
        
        for finding in findings:
            # Key based on line, type, and match content
            # We use match content to differentiate different findings on same line
            # But if different patterns match SAME text on SAME line, we want to dedup
            key = (finding['line'], finding['match'], finding['type'])
            
            # Also check if we have a "more specific" finding already?
            # For now, simple deduplication is better than nothing
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
                
        return unique_findings
    
    def extract_api_endpoints(self, content: str, base_url: str = None) -> List[Dict[str, Any]]:
        """Extract API endpoints"""
        endpoints = []
        lines = content.split('\n')
        
        for pattern, method in self.patterns.api_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                url_path = match.group(1) if match.lastindex >= 1 else match.group(0)
                if len(match.groups()) > 1:
                    url_path = match.group(2) if match.lastindex >= 2 else match.group(1)
                
                # Filter out common false positives
                if any(fp in url_path.lower() for fp in ['example.com', 'localhost', 'placeholder']):
                    continue
                
                # Filter out subdomains if base_url is provided (Strict Domain Matching)
                if base_url and self._is_subdomain(url_path, base_url):
                    continue

                endpoint = {
                    'method': method,
                    'path': url_path[:200],
                    'line': line_num,
                    'full_match': match.group(0)[:150],
                    'line_content': lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
                
                endpoints.append(endpoint)
        
        # Remove duplicates
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = (ep['path'], ep['line'])
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        return unique_endpoints
    
    def extract_parameters(self, content: str) -> List[Dict[str, Any]]:
        """Extract parameters from JavaScript including URL query parameters"""
        params = []
        if not content:
            return params
        
        lines = content.split('\n')
        
        for pattern, label in self.patterns.parameter_patterns:
            try:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    try:
                        start_pos = match.start()
                        line_num = content[:start_pos].count('\n') + 1
                        
                        # Extract parameter information
                        full_match = match.group(0)
                        param_text = full_match
                        
                        # Try to extract parameter name and value
                        param_name = None
                        param_value = None
                        
                        if len(match.groups()) >= 1:
                            # For URL query parameters like ?key=value or &email=test
                            if '?' in full_match or '&' in full_match:
                                # Extract the parameter part
                                param_part = match.group(1) if match.lastindex >= 1 else full_match
                                if '=' in param_part:
                                    # Handle multiple parameters: param1=val1&param2=val2
                                    if '&' in param_part:
                                        # Extract first parameter for display
                                        first_param = param_part.split('&')[0]
                                        if '=' in first_param:
                                            parts = first_param.split('=', 1)
                                            if len(parts) == 2:
                                                param_name = parts[0].lstrip('?&').strip()
                                            param_value = parts[1].strip()
                                            param_text = f"{param_name}={param_value}"
                                    else:
                                        parts = param_part.split('=', 1)
                                        if len(parts) == 2:
                                            # Remove ? or & from param name
                                            param_name = parts[0].lstrip('?&').strip()
                                            param_value = parts[1].strip()
                                            param_text = f"{param_name}={param_value}"
                            # For function parameters
                            elif '(' in full_match and ')' in full_match:
                                # Extract parameters from function definition
                                param_text = match.group(2) if len(match.groups()) > 1 and match.lastindex >= 2 else (match.group(1) if match.lastindex >= 1 else full_match)
                                # Try to extract first parameter name
                                params_str = param_text.split(',')[0] if ',' in param_text else param_text
                                if '=' in params_str:
                                    # Default parameter value
                                    param_name = params_str.split('=')[0].strip()
                                elif ':' in params_str:
                                    # Type annotation or object property
                                    param_name = params_str.split(':')[0].strip()
                                else:
                                    param_name = params_str.strip()
                            # For object/destructuring parameters
                            elif '{' in full_match:
                                param_text = match.group(1) if match.lastindex >= 1 else full_match
                                # Extract first property name
                                if ':' in param_text:
                                    param_name = param_text.split(':')[0].strip()
                                else:
                                    param_name = param_text.split(',')[0].strip() if ',' in param_text else param_text.strip()
                            else:
                                param_text = match.group(1) if match.lastindex >= 1 else (match.group(2) if len(match.groups()) > 1 and match.lastindex >= 2 else full_match)
                                # Try to extract parameter name from various patterns
                                if '=' in param_text:
                                    param_name = param_text.split('=')[0].strip()
                        
                        # Filter out CSS properties (False Positive Reduction)
                        if param_name and any(prop == param_name.lower() for prop in self.css_props):
                            continue
                            
                        # Filter out CSS values in values
                        if param_value and re.match(self.css_values_regex, param_value.strip("'\""), re.IGNORECASE):
                            continue
                        
                        short_name_labels = {
                            'Function Parameters',
                            'Anonymous Function Parameters',
                            'Function Expression Parameters',
                            'Arrow Function Parameters',
                            'Arrow Function (const)',
                            'Arrow Function (let)',
                            'Arrow Function (var)',
                            'Method Call Parameters',
                            'Event Handler Parameters',
                            'EventListener Parameters',
                            'EventListener Arrow Parameters',
                            'Promise Callback Parameters',
                            'Array Method Parameters'
                        }
                        if label in short_name_labels:
                            if param_name and len(param_name) <= 2:
                                continue
                            if param_name and param_name.lower() in {'e', 'ev', 'evt', 'x', 'y', 'i', 'j', 'k', '_'}:
                                continue
                        
                        if label in {'URL Query Parameter', 'Query Parameter', 'URL with Query Parameters', 'URL with Multiple Parameters'}:
                            if not (param_name and param_value):
                                continue

                        # Get exact code snippet
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        # Truncate very long lines
                        if len(line_content) > 500:
                            line_content = line_content[:200] + "..." + line_content[-200:]
                        
                        # Get context for parameters (like other findings)
                        start_line = max(0, line_num - 5 - 1)
                        end_line = min(len(lines), line_num + 5)
                        context_lines_list = lines[start_line:end_line]
                        context = '\n'.join(context_lines_list)
                        
                        # For very long lines (minified), truncate context
                        if len(context) > 1000:
                            # Show snippet around the match
                            match_start = max(0, start_pos - 200)
                            match_end = min(len(content), start_pos + len(full_match) + 200)
                            context = content[match_start:match_end]
                        
                        param = {
                            'type': label,
                            'parameter': param_text,
                            'param_name': param_name[:100] if param_name else None,
                            'param_value': param_value,
                            'line': line_num,
                            'full_match': full_match,
                            'line_content': line_content,
                            'context': context,
                            'context_start_line': start_line + 1,
                            'context_end_line': end_line,
                        }
                        
                        params.append(param)
                    except Exception as e:
                        # Skip problematic matches
                        continue
            except Exception as e:
                # Skip problematic patterns
                continue
        
        # Remove duplicates based on line and parameter
        seen = set()
        unique_params = []
        for param in params:
            key = (param['line'], param['parameter'])
            if key not in seen:
                seen.add(key)
                unique_params.append(param)
        
        return unique_params
    
    def extract_paths(self, content: str) -> List[Dict[str, Any]]:
        """Extract paths and directories"""
        paths = []
        lines = content.split('\n')
        
        for pattern, label in self.patterns.path_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                path_text = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Filter out common false positives (unless it's explicitly a URL pattern)
                if label != 'Hardcoded URL' and any(fp in path_text.lower() for fp in ['http://', 'https://', 'www.', 'example.com']):
                    continue
                
                path = {
                    'type': label,
                    'path': path_text,
                    'line': line_num,
                    'full_match': match.group(0),
                    'line_content': lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
                
                paths.append(path)
        
        # Remove duplicates
        seen = set()
        unique_paths = []
        for path in paths:
            key = (path['path'], path['line'])
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)
        
        return unique_paths
    
    def extract_html_scripts(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract script sources from HTML content"""
        scripts = []
        
        # Simple regex for <script src="...">
        # Covers " ' and no quotes, and different attributes order
        src_pattern = r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']'
        matches = re.finditer(src_pattern, content, re.IGNORECASE)
        
        for match in matches:
            src = match.group(1)
            
            # Strict Domain Matching: Skip subdomains
            if base_url and self._is_subdomain(src, base_url):
                continue

            # Normalize URL if needed (handle relative paths)
            # For now, just report the raw path, the user can see it
            scripts.append({
                'path': src,
                'line': content[:match.start()].count('\n') + 1,
                'type': 'Script Reference',
                'confidence': 'High',
                'line_content': match.group(0)
            })
            
        return scripts
