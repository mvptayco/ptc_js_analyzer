import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

class SmartFilter:
    def __init__(self):
        """
        Initialize a lightweight ML-based filter to quickly decide if a JS file 
        is worth scanning for security issues.
        
        Uses HashingVectorizer (low memory, stateless) + SGDClassifier (fast).
        """
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
        
        self.is_trained = False
        self._train_initial_model()

    def _train_initial_model(self):
        """
        Train the model on synthetic data to distinguish between:
        1. Interesting Security/Business Logic (Positive class)
        2. Boring UI/Library/Vendor code (Negative class)
        """
        # POSITIVE SAMPLES (Security relevant, API calls, sensitive data)
        positive_samples = [
            "var apiKey = 'AIzaSy...'; const token = 'eyJ...';",
            "function login(user, password) { fetch('/api/auth', ...); }",
            "aws_access_key_id = 'AKIA...'; secret_access_key = '...';",
            "localStorage.setItem('jwt', token);",
            "db.connect('postgres://user:pass@localhost:5432/db');",
            "Authorization: Bearer eyJ...",
            "stripe.confirmCardPayment(clientSecret, { payment_method: ... });",
            "eval(userInput); document.write(params);",
            "const config = { apiUrl: 'https://api.example.com', debug: true };",
            "firebase.initializeApp({ apiKey: '...', authDomain: '...' });",
            "user_id: 123, role: 'admin', is_verified: true",
            "history.pushState(state, title, url); // routing logic often has params",
            "json_response = await fetch(endpoint);",
            "process.env.DB_PASSWORD"
        ] * 20  # Duplicate to give weight

        # NEGATIVE SAMPLES (Minified libs, UI frameworks, Animations, Polyfills)
        negative_samples = [
            "jquery.min.js: function(e,t){return new x.fn.init(e,t)}",
            "react.production.min.js: function(e){for(var r=arguments.length,t=new Array(r>1?r-1:0),n=1;n<r;n++)t[n-1]=arguments[n];}",
            "bootstrap.min.js: if(typeof define==='function'&&define.amd)define(['jquery'],t)else t(jQuery)",
            "animate.css: @keyframes bounce {from, 20%, 53%, 80%, to {animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);transform: translate3d(0,0,0);}}",
            "lodash.js: var _ = runInContext(); return _;",
            "moment.js: return new Date(y, m, d, h, i, s, ms);",
            "chart.js: function draw(ctx, config) { ctx.beginPath(); ... }",
            "three.js: function render() { requestAnimationFrame(render); renderer.render(scene, camera); }",
            "webpackJsonp([1],[function(e,t,n){...}])",
            "var colors = ['#ff0000', '#00ff00', '#0000ff'];",
            "div.style.backgroundColor = 'blue'; span.innerHTML = 'Hello';",
            "console.log('Component mounted');",
            "return (<div><h1>Title</h1></div>);",
            "module.exports = { entry: './index.js', output: { filename: 'bundle.js' } };"
        ] * 20

        X = positive_samples + negative_samples
        y = [1] * len(positive_samples) + [0] * len(negative_samples)

        self.pipeline.fit(X, y)
        self.is_trained = True

    def predict_relevance(self, js_content: str) -> bool:
        """
        Predict if the JS content is relevant for security scanning.
        Returns True if it looks like business logic/security relevant.
        Returns False if it looks like a generic library or UI code.
        """
        if not js_content or len(js_content) < 50:
            return False # Too short to be interesting

        # Quick heuristic override: if it contains very specific strong keywords, always scan
        strong_indicators = ['api_key', 'apikey', 'secret', 'password', 'token', 'auth', 'jwt', 'bearer']
        lower_content = js_content.lower()
        if any(indicator in lower_content for indicator in strong_indicators):
            return True

        # Use ML model for ambiguous cases
        prediction = self.pipeline.predict([js_content])[0]
        return bool(prediction == 1)

    def get_relevance_score(self, js_content: str) -> float:
        """
        Get the decision function score (distance from hyperplane).
        Higher > 0 means more likely to be relevant.
        """
        return self.pipeline.decision_function([js_content])[0]
