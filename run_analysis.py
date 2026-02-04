from analyzer import JavaScriptAnalyzer
import json
import sys

def run_analysis():
    analyzer = JavaScriptAnalyzer()
    
    try:
        with open('test_cases.js', 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    result = analyzer.analyze_content(content, "test_cases.js")
    result.recommendations = analyzer.generate_recommendations(result)
    
    # Extract parameter names safely
    params = []
    for p in result.parameters:
        if isinstance(p, dict):
            # Use param_name if available, otherwise parameter text
            name = p.get('param_name')
            if not name:
                name = p.get('parameter')
            if name:
                params.append(name)
        else:
            params.append(str(p))

    output = {
        "api_keys": result.api_keys,
        "credentials": result.credentials,
        "xss_vulnerabilities": result.xss_vulnerabilities,
        "emails": result.emails,
        "api_endpoints": result.api_endpoints,
        "parameters": result.parameters,
        "recommendations": result.recommendations
    }
    
    with open('analysis_result.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    
    print("Analysis complete. Results written to analysis_result.json")

if __name__ == "__main__":
    run_analysis()
