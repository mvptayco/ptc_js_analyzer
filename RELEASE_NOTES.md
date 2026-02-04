# Release v12.91 - Technique Standardization & UI Enhancements

## 🚀 Changes in v12.91

### 🛡️ Technique Standardization
- **Standardized Analysis Categories**: Aligned all findings with the 17 standard security analysis techniques.
- **Renamed Techniques**:
  - "Regex Pattern Matching" → **Pattern / signature matching**
  - "AST Static Analysis" → **Abstract Syntax Tree (AST) analysis**
- **Specific Mappings**:
  - **DOM-based vulnerability analysis** (innerHTML, eval, etc.)
  - **Dependency and supply-chain analysis** (Library detection)
  - **Obfuscation and deobfuscation analysis** (Packed/Encoded code)
- **Consolidated Findings**: Emails, IPs, and generic API keys now correctly report under **Pattern / signature matching** instead of ad-hoc labels.

### ✨ Enhancements
- **UI Visibility**: Improved contrast for "Low Confidence" items in Light Mode (darker green).
- **Techniques Tab**: Fixed grouping logic to prevent raw data types (like "Email") from appearing as technique names.
- **Cache Management**: Updated assets to version `12.91` to ensure fresh loading of CSS/JS.
- **CSP Updates**: Adjusted Content Security Policy to allow necessary CDN resources.

### 🐛 Bug Fixes
- **Credential False Positives**: Removed generic email regex from `credential_patterns` to prevent emails from being misclassified as high-severity credentials.
- **Labeling Fix**: Resolved issue where "Techniques Used" tab displayed "Email Extraction" instead of the actual analysis technique.
