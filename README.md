# �️ JS-Analyser

**Advanced JavaScript Security Analysis Tool**

JS-Analyser is a powerful, high-speed security assessment tool designed to analyze JavaScript files and web endpoints for vulnerabilities, exposed secrets, and security misconfigurations. It performs static analysis on client-side code to uncover sensitive information and potential attack vectors.

## 🚀 Key Features

*   **🔑 Secret Detection**: Automatically identifies exposed API keys, tokens, and credentials for major providers:
    *   AWS, Google Cloud, Azure
    *   Stripe, PayPal, Slack, Firebase
    *   GitHub Tokens, JWTs, and generic private keys
*   **⚠️ Vulnerability Scanning**:
    *   **XSS Detection**: Finds DOM-based XSS sinks (`innerHTML`, `document.write`, etc.) and dangerous function usage.
    *   **Rate Limiting Analysis**: Detects if the target server has rate limiting enabled and identifies the provider (Cloudflare, Nginx, etc.).
    *   **Security Headers**: Analyzes Server headers, CSP (Content Security Policy), and other security configurations.
*   **🌐 Network Intelligence**:
    *   Extracts server IP addresses (optimized with direct socket connection).
    *   Detects Cloudflare protection and WAF presence.
*   **🔍 Deep Analysis**:
    *   Extracts API endpoints, hidden paths, and URL parameters.
    *   Flags interesting/suspicious comments (TODOs, FIXMEs, "password").
    *   Filters out false positives (CSS properties, common non-secret strings).
*   **⚡ High Performance**:
    *   **Parallel Processing**: Analyzes multiple URLs concurrently using threading.
    *   **Optimized Networking**: Bypasses redundant DNS lookups for blazing fast results.
*   **�️ Dynamic Recommendations**: Provides context-aware security advice based on specific findings (e.g., "Rotate AWS Keys", "Implement CSP").

## 🛠️ Installation

### Prerequisites
*   Python 3.8+
*   pip

### Setup
1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/JS-Analyser.git
    cd JS-Analyser
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

### Local Development
Run the Flask application:
```bash
python app.py
```
Access the web interface at `http://localhost:5000`.

### Web Interface
1.  **Enter URL(s)**: Paste one or multiple URLs (one per line).
2.  **Upload File**: Upload a `.js` or text file containing URLs.
3.  **View Results**: Get a real-time report with categorized findings, severity levels, and remediation steps.

### API Usage
You can automate analysis via the API:

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com/script.js"]}'
```

## ☁️ Deployment

### Vercel
This project is configured for easy deployment on Vercel.

1.  Install Vercel CLI: `npm i -g vercel`
2.  Run `vercel` in the project directory.
3.  Your app will be live at `https://your-project.vercel.app`.

## 🏗️ Architecture

*   **Backend**: Python (Flask)
*   **Analysis Engine**: Modular Python system (`analysis_engine/`) handling pattern matching, header analysis, and heuristic detection.
*   **Frontend**: HTML5, CSS3, Vanilla JavaScript (responsive UI with dark/light mode).
*   **Security**: Server-side analysis (safe execution environment), input validation, and output encoding.

---

## 👨‍💻 Author

**Jhonel Alam**
*Security Engineer • Threat Researcher • Secure Software Developer*

I am a cybersecurity practitioner focused on web security, threat analysis, and offensive security research.

**Specializations:**
*   JavaScript Security Analysis
*   Behavioral Threat Detection
*   Attack Surface Mapping
*   Secure Application Development

**Connect:**
*   GitHub: [github.com/jhonelalam](https://github.com/jhonelalam)
