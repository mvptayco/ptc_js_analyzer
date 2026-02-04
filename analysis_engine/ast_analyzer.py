
import esprima
import logging
from typing import List, Dict, Any, Optional

class ASTAnalyzer:
    """
    Performs static analysis on JavaScript code using AST parsing (Esprima).
    Detects dangerous patterns, sinks, and API usage that Regex might miss.
    """

    def __init__(self):
        self.findings = []
        
        # Knowledge Base for Risk Classification
        self.risk_catalog = {
            # Browser / DOM XSS
            "eval": {"cwe": "CWE-95", "owasp": "A03:2021-Injection", "severity": "Critical", "desc": "Use of eval() allows execution of arbitrary code."},
            "document.write": {"cwe": "CWE-79", "owasp": "A03:2021-Injection", "severity": "High", "desc": "document.write() can lead to Cross-Site Scripting (XSS)."},
            "innerHTML": {"cwe": "CWE-79", "owasp": "A03:2021-Injection", "severity": "Medium", "desc": "Assignment to innerHTML is a common XSS sink."},
            "outerHTML": {"cwe": "CWE-79", "owasp": "A03:2021-Injection", "severity": "Medium", "desc": "Assignment to outerHTML is a common XSS sink."},
            "dangerouslySetInnerHTML": {"cwe": "CWE-79", "owasp": "A03:2021-Injection", "severity": "High", "desc": "React's dangerous sink for HTML insertion."},
            
            # Node.js Dangerous APIs
            "child_process": {"cwe": "CWE-78", "owasp": "A03:2021-Injection", "severity": "Critical", "desc": "Usage of child_process allows OS command execution."},
            "exec": {"cwe": "CWE-78", "owasp": "A03:2021-Injection", "severity": "Critical", "desc": "Execution of OS commands."},
            "spawn": {"cwe": "CWE-78", "owasp": "A03:2021-Injection", "severity": "High", "desc": "Spawning new processes can be dangerous if inputs are uncontrolled."},
            "vm": {"cwe": "CWE-94", "owasp": "A03:2021-Injection", "severity": "Critical", "desc": "The 'vm' module allows compiling and running code dynamically."},
            "fs": {"cwe": "CWE-73", "owasp": "A01:2021-Broken Access Control", "severity": "Medium", "desc": "File system access should be audited for path traversal."},
            
            # Communication / Storage
            "postMessage": {"cwe": "CWE-345", "owasp": "A04:2021-Insecure Design", "severity": "Low", "desc": "Cross-origin messaging should validate origin."},
            "localStorage": {"cwe": "CWE-312", "owasp": "A04:2021-Insecure Design", "severity": "Low", "desc": "Sensitive data should not be stored in localStorage."},
            "sessionStorage": {"cwe": "CWE-312", "owasp": "A04:2021-Insecure Design", "severity": "Low", "desc": "Sensitive data should not be stored in sessionStorage."},
        }

    def analyze(self, content: str) -> List[Dict[str, Any]]:
        """
        Parses content into AST and walks it to find issues.
        """
        self.findings = []
        if not content or not content.strip():
            return []

        try:
            # Parse to AST (tolerant mode to ignore minor syntax errors)
            ast = esprima.parseScript(content, {'loc': True, 'tolerant': True})
            self._walk(ast)
        except Exception as e:
            # Fallback or log error (AST parsing might fail on minified/complex code)
            logging.debug(f"AST Parsing failed: {e}")
            return []

        return self.findings

    def _walk(self, node):
        """
        Recursive AST traversal.
        """
        if isinstance(node, list):
            for item in node:
                self._walk(item)
            return

        if not isinstance(node, esprima.nodes.Node):
            return

        # Check the node type and properties
        self._check_node(node)

        # Recursively walk children
        for key, value in node.__dict__.items():
            if key == 'type' or key == 'loc': 
                continue
            self._walk(value)

    def _check_node(self, node):
        """
        Inspect specific node types for dangerous patterns.
        """
        
        # 1. CallExpressions: eval(), exec(), child_process.exec()
        if node.type == 'CallExpression':
            self._check_call_expression(node)

        # 2. AssignmentExpression: innerHTML = ...
        elif node.type == 'AssignmentExpression':
            self._check_assignment_expression(node)
            
        # 3. NewExpression: new Function(...)
        elif node.type == 'NewExpression':
            self._check_new_expression(node)

    def _check_call_expression(self, node):
        callee = node.callee
        
        # Simple calls: eval(...)
        if callee.type == 'Identifier':
            name = callee.name
            if name in self.risk_catalog:
                self._add_finding(name, node, "Dangerous Function Call")

        # Member calls: child_process.exec(...) or document.write(...)
        elif callee.type == 'MemberExpression':
            # Handle object.property format
            prop_name = None
            obj_name = None
            
            if callee.property.type == 'Identifier':
                prop_name = callee.property.name
            
            if callee.object.type == 'Identifier':
                obj_name = callee.object.name

            # Check full match (e.g., child_process) or property match (e.g., exec)
            # This is a heuristic; 'exec' could be on any object, but it's worth flagging
            if prop_name in self.risk_catalog:
                 self._add_finding(f"{obj_name}.{prop_name}" if obj_name else prop_name, node, "Dangerous Method Call")

    def _check_assignment_expression(self, node):
        left = node.left
        if left.type == 'MemberExpression':
            if left.property.type == 'Identifier':
                prop_name = left.property.name
                if prop_name in ['innerHTML', 'outerHTML', 'dangerouslySetInnerHTML']:
                    self._add_finding(prop_name, node, "DOM Sink Assignment")

    def _check_new_expression(self, node):
        callee = node.callee
        if callee.type == 'Identifier' and callee.name == 'Function':
             self._add_finding("new Function", node, "Dynamic Code Generation")

    def _add_finding(self, trigger: str, node, technique: str):
        # Resolve risk info (handle "obj.prop" by taking the "prop" part if needed)
        # Or look up exact match first, then partial
        
        risk_info = self.risk_catalog.get(trigger)
        if not risk_info:
            # Try to match the last part for member expressions (e.g. child_process.exec -> exec)
            parts = trigger.split('.')
            if len(parts) > 1 and parts[-1] in self.risk_catalog:
                risk_info = self.risk_catalog[parts[-1]]
            # Special case for React
            elif "dangerouslySetInnerHTML" in trigger:
                risk_info = self.risk_catalog["dangerouslySetInnerHTML"]
        
        if not risk_info:
            return

        # Extract location
        line = node.loc.start.line if hasattr(node, 'loc') else 0
        
        finding = {
            "type": risk_info["desc"],
            "match": trigger,
            "line": line,
            "technique": "Abstract Syntax Tree (AST) analysis",
            "confidence": "High", # AST is structurally accurate
            "severity": risk_info["severity"],
            "cwe": risk_info["cwe"],
            "owasp": risk_info["owasp"],
            "detection_logic": f"AST Analysis identified '{trigger}' usage. {risk_info['desc']} (Category: {risk_info['cwe']})"
        }
        self.findings.append(finding)
