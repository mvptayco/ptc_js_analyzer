import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
import json
import os

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
        """Initialize with static security knowledge from external JSON file"""
        self.knowledge_base = []
        
        # Path to the data file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(current_dir, 'data', 'chatbot_knowledge.json')
        
        try:
            if os.path.exists(data_path):
                with open(data_path, 'r', encoding='utf-8') as f:
                    self.knowledge_base = json.load(f)
            else:
                # Fallback if file doesn't exist (shouldn't happen in normal operation)
                print(f"Warning: Chatbot knowledge base not found at {data_path}")
        except Exception as e:
            print(f"Error loading chatbot knowledge base: {e}")
            self.knowledge_base = []

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
