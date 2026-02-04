import warnings
import logging

# Optional imports for ML components
try:
    import numpy as np
    from sklearn.feature_extraction.text import HashingVectorizer
    from sklearn.linear_model import SGDClassifier
    from sklearn.pipeline import Pipeline
    HAS_ML = True
except ImportError:
    HAS_ML = False
    logging.warning("ML dependencies (numpy/scikit-learn) not found. SmartFilter will run in passthrough mode.")

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

class SmartFilter:
    def __init__(self):
        """
        Initialize a lightweight ML-based filter to quickly decide if a JS file 
        is worth scanning for security issues.
        
        Uses HashingVectorizer (low memory, stateless) + SGDClassifier (fast).
        """
        self.is_trained = False
        
        if HAS_ML:
            self.pipeline = Pipeline([
                ('vectorizer', HashingVectorizer(
                    n_features=2**14, 
                    alternate_sign=False, 
                    norm='l2',
                    binary=True  # We just care about presence of tokens
                )),
                ('clf', SGDClassifier(
                    loss='hinge',   # SVM
                    penalty='l2',
                    alpha=1e-3, 
                    random_state=42,
                    max_iter=5,     # Fast training
                    tol=None
                ))
            ])
            self._train_initial_model()
        else:
            self.pipeline = None

    def _train_initial_model(self):
        """
        Train the model on synthetic data to distinguish between:
        1. Interesting Security/Business Logic (Positive class)
        2. Boring UI/Library/Vendor code (Negative class)
        """
        if not HAS_ML:
            return

        # POSITIVE SAMPLES (Security relevant, API calls, sensitive data)
        positive_samples = [
            "var apiKey = 'AIzaSy...'; const token = 'eyJ...';",
            "function login(user, password) { fetch('/api/auth', ...); }",
            "aws_access_key_id = 'AKIA...'; secret_access_key = '...';",
            "localStorage.setItem('jwt', token);",
            "db.connect('postgres://user:pass@localhost:5432/db');",
            "eval(userInput); document.write(data);",
            "const secret = 'super_secret_key';",
            "Authorization: Bearer <token>",
            "app.post('/login', (req, res) => { ... })",
            "exec('rm -rf /');",
            "process.env.AWS_SECRET",
            "dangerouslySetInnerHTML"
        ]
        
        # NEGATIVE SAMPLES (Minified UI, CSS-in-JS, pure design, generic helpers)
        negative_samples = [
            "import React from 'react'; const Button = () => <div />;",
            "var _0x5f3a = ['\x6c\x6f\x67']; console.log('hello');", # Simple obfuscation might be interesting, but generic packed code isn't always
            "background-color: #fff; color: #000; display: flex;",
            "jquery.min.js: function(e,t){return new r.fn.init(e,t)}",
            "bootstrap.min.css: body{margin:0;font-family:var(--bs-font-sans-serif)}",
            "const uiState = { isOpen: false, toggle: () => {} };",
            "function add(a, b) { return a + b; }",
            "export const ICON_SVG = '<svg>...</svg>';",
            "node_modules/lodash/lodash.js",
            "webpackJsonp([1],{...})",
            "moment().format('MMMM Do YYYY, h:mm:ss a');",
            "document.getElementById('root').render(<App />);"
        ]
        
        X = positive_samples + negative_samples
        y = [1] * len(positive_samples) + [0] * len(negative_samples)
        
        try:
            self.pipeline.fit(X, y)
            self.is_trained = True
        except Exception as e:
            logging.warning(f"Failed to train SmartFilter: {e}")
            self.is_trained = False

    def predict_relevance(self, content: str) -> bool:
        """
        Returns True if the content looks like it contains security-relevant logic.
        Returns False if it looks like generic/library/UI code.
        """
        if not HAS_ML or not self.is_trained or not content:
            return True # Fail open (scan everything) if ML is broken
            
        try:
            # Quick heuristics first
            if len(content) < 50: return False
            if len(content) > 500000: return True # Too big, just scan it to be safe (or skip if perf is key)
            
            prediction = self.pipeline.predict([content])[0]
            return bool(prediction == 1)
        except Exception:
            return True
