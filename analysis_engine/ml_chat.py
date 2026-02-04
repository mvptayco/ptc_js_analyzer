import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re

class MLChatEngine:
    def __init__(self):
        # Remove stop_words='english' to allow matching phrases like "how are you"
        self.vectorizer = TfidfVectorizer()
        self.knowledge_base = []
        self.corpus = []
        self.vectors = None
        self._initialize_knowledge_base()
        self.fit_model()

    def _initialize_knowledge_base(self):
        """Initialize with static security knowledge"""
        self.knowledge_base = [
            {
                "question": "what is xss",
                "answer": "Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. It can be used to steal session cookies, redirect users, or deface websites.",
                "keywords": "xss cross site scripting injection"
            },
            {
                "question": "how to fix xss",
                "answer": "To fix XSS, ensure all user input is validated and sanitized. Use Content Security Policy (CSP) headers, escape output contextually (HTML, JavaScript, CSS), and use modern frameworks that auto-escape data (like React or Vue).",
                "keywords": "fix xss mitigation solution"
            },
            {
                "question": "what is an api key",
                "answer": "An API key is a unique identifier used to authenticate a user, developer, or calling program to an API. Exposing them in client-side code is a security risk as attackers can steal them to make unauthorized requests.",
                "keywords": "api key secret token credential"
            },
            {
                "question": "how to secure api keys",
                "answer": "Never commit API keys to version control. Use environment variables on the server. For client-side apps, use a proxy server to hide keys, or restrict keys by IP address/referrer if the provider supports it.",
                "keywords": "secure protect api key secrets"
            },
            {
                "question": "what is csrf",
                "answer": "Cross-Site Request Forgery (CSRF) forces an end user to execute unwanted actions on a web application in which they're currently authenticated. Use Anti-CSRF tokens and SameSite cookie attributes to prevent it.",
                "keywords": "csrf forgery cross site request"
            },
             {
                "question": "what is rate limiting",
                "answer": "Rate limiting controls the number of requests a user can make to a server in a given timeframe. It prevents abuse, brute-force attacks, and DoS attacks.",
                "keywords": "rate limit throttling dos brute force"
            },
            {
                "question": "how to use this tool",
                "answer": "Upload a JavaScript file or provide a URL to analyze it. The tool scans for API keys, XSS vulnerabilities, and other security issues. Check the 'Recommendations' tab for fixes.",
                "keywords": "help usage how to use tool guide"
            },
            {
                "question": "who is the author creator developer",
                "answer": "The tool was created by Jhonel Alam, an IT Security Engineer at Philtrust Bank. He is also a Cybersecurity Specialist and Data Analyst based in Manila.",
                "keywords": "author creator developer who made jhonel alam owner"
            },
            {
                "question": "contact linkedin email info",
                "answer": "You can reach Jhonel Alam via email at jhonel.alam1@gmail.com or visit his LinkedIn: https://ph.linkedin.com/in/jhonel-alam-889a9622b",
                "keywords": "contact email linkedin social link"
            },
            {
                "question": "what is the author job description",
                "answer": "Jhonel Alam is an IT Security Engineer at Philtrust Bank. He specializes in Cybersecurity and Data Analysis, with a strong focus on securing applications and infrastructure.",
                "keywords": "job description bio background details"
            },
            {
                "question": "hello hi hey greetings",
                "answer": "Hello! I am your JavaScript Security Assistant. How can I help you analyze your code today?",
                "keywords": "hello hi hey greetings good morning afternoon evening"
            },
            {
                "question": "how are you",
                "answer": "I'm doing great, thank you! I'm ready to help you find security vulnerabilities in your JavaScript files.",
                "keywords": "how are you how do you do status"
            },
            {
                "question": "what can you do help capabilities",
                "answer": "I can analyze JavaScript files for security issues like XSS, API leaks, and hardcoded credentials. I can also explain security concepts and provide remediation advice.",
                "keywords": "help capabilities what can you do features"
            },
            {
                "question": "who are you bot identity",
                "answer": "I am a Machine Learning-powered Security Assistant designed to help you secure your web applications.",
                "keywords": "who are you identity bot what are you"
            }
        ]
        
    def fit_model(self):
        """Train TF-IDF model on current corpus"""
        self.corpus = [item["question"] + " " + item.get("keywords", "") for item in self.knowledge_base]
        if self.corpus:
            self.vectors = self.vectorizer.fit_transform(self.corpus)

    def update_context(self, analysis_results):
        """Update KB with dynamic findings from the latest analysis"""
        # Reset to base KB
        self._initialize_knowledge_base()
        
        if not analysis_results:
            self.fit_model()
            return

        # Flatten findings
        findings = []
        if isinstance(analysis_results, list):
            for file_res in analysis_results:
                findings.extend(file_res.get('findings', []))
        elif isinstance(analysis_results, dict):
             findings.extend(analysis_results.get('findings', []))

        # Add dynamic Q&A
        for f in findings:
            desc = f.get('description', '')
            ftype = f.get('type', '')
            severity = f.get('severity', '')
            
            # Question about specific finding
            self.knowledge_base.append({
                "question": f"tell me about the {severity} {ftype} finding",
                "answer": f"I found a {severity} severity {ftype} issue: {desc}. You should review the code near this finding.",
                "keywords": f"{ftype} {severity} finding issue problem"
            })
            
            # General "what did you find"
            self.knowledge_base.append({
                "question": "what did you find",
                "answer": f"I found several issues, including a {severity} {ftype}. Check the results grid for details.",
                "keywords": "summary findings results report"
            })

        self.fit_model()

    def get_response(self, user_input):
        """Get best matching response using Cosine Similarity"""
        if not self.vectors is not None or not self.corpus:
            return "I'm initializing. Please try again in a moment."

        # Vectorize user input
        user_vec = self.vectorizer.transform([user_input])
        
        # Calculate similarities
        similarities = cosine_similarity(user_vec, self.vectors).flatten()
        
        # Get best match
        best_idx = np.argmax(similarities)
        score = similarities[best_idx]
        
        # Threshold for "I don't know"
        if score < 0.2:
            return "I'm not sure about that. Try asking about XSS, API keys, or specific findings in your code."
            
        return self.knowledge_base[best_idx]["answer"]
