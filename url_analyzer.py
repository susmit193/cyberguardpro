import pandas as pd
import numpy as np
import pickle
import re
from urllib.parse import urlparse
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os

class URLAnalyzer:
    def __init__(self, model_path='malware_model.pkl'):
        """
        Initialize the URL Analyzer with a pre-trained model
        """
        self.model_path = os.path.join(os.path.dirname(__file__), model_path)
        self.model = None
        self.vectorizer = None
        self.model_name = "Random Forest Classifier"
        self.model_type = "Ensemble Learning"
        self.load_model()
        
    def load_model(self):
        """
        Load the pre-trained model and vectorizer
        """
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data['model']
                self.vectorizer = model_data['vectorizer']
            print("Model loaded successfully!")
        except Exception as e:
            print(f"Error loading model: {e}")
            # If model loading fails, we'll use rule-based analysis
            self.model = None
            self.vectorizer = None
    
    def extract_features(self, url):
        """
        Extract features from a URL for analysis
        """
        features = {}
        
        # Basic URL parsing
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Extract domain components
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        main_domain = extracted.domain
        tld = extracted.suffix
        
        # Length-based features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        features['subdomain_length'] = len(subdomain)
        
        # Character-based features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_exclamation_marks'] = url.count('!')
        features['num_hash_symbols'] = url.count('#')
        features['num_dollar_signs'] = url.count('$')
        features['num_percent_symbols'] = url.count('%')
        features['num_ampersands'] = url.count('&')
        features['num_tildes'] = url.count('~')
        
        # Special character ratios
        features['special_char_ratio'] = sum([
            features['num_hyphens'], features['num_underscores'], 
            features['num_question_marks'], features['num_equal_signs'],
            features['num_at_symbols'], features['num_exclamation_marks'],
            features['num_hash_symbols'], features['num_dollar_signs'],
            features['num_percent_symbols'], features['num_ampersands'],
            features['num_tildes']
        ]) / max(len(url), 1)
        
        # Domain-based features
        features['has_subdomain'] = 1 if subdomain else 0
        features['subdomain_count'] = len(subdomain.split('.')) if subdomain else 0
        features['domain_word_count'] = len(main_domain.split('-'))
        
        # Suspicious patterns
        features['has_ip_in_domain'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        features['has_suspicious_tld'] = 1 if tld in ['xyz', 'top', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq'] else 0
        features['has_suspicious_keywords'] = 1 if any(keyword in url.lower() for keyword in 
            ['login', 'account', 'verify', 'secure', 'update', 'confirm', 'bank', 'paypal']) else 0
        
        # Entropy-based features (measure of randomness)
        features['url_entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(domain)
        
        # Additional security features
        features['uses_https'] = 1 if url.startswith('https://') else 0
        features['has_redirect'] = 1 if 'redirect' in url.lower() else 0
        features['has_shortener'] = 1 if any(shortener in domain for shortener in 
            ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else 0
        
        return features
    
    def _calculate_entropy(self, text):
        """
        Calculate Shannon entropy of a string
        """
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def predict(self, url):
        """
        Predict if a URL is malicious or benign
        """
        try:
            # Extract features
            features = self.extract_features(url)
            
            # If model is available, use ML prediction
            if self.model is not None and self.vectorizer is not None:
                # Convert features to feature vector
                feature_vector = self._create_feature_vector(features, url)
                
                # Make prediction
                prediction = self.model.predict([feature_vector])[0]
                probability = self.model.predict_proba([feature_vector])[0]
                ml_pred_label = 'malicious' if prediction == 1 else 'benign'
                benign_p = float(probability[0]) if len(probability) > 0 else 0.0
                malicious_p = float(probability[1]) if len(probability) > 1 else 0.0
                ml_confidence = max(benign_p, malicious_p)

                # Blend with rule-based risk to calibrate confidence (no retraining needed)
                rule_result = self._rule_based_analysis(features, url)
                risk_score = rule_result.get('risk_score', 0)
                margin = abs(benign_p - malicious_p)

                # Base calibrated confidence from probability margin
                # 0.5 -> 0.55, 1.0 -> 1.0 (smooth mapping)
                calibrated = 0.5 + 0.5 * margin

                # Strengthen clear signals from heuristics
                if ml_pred_label == 'malicious' and risk_score >= 3:
                    calibrated = min(0.99, calibrated + 0.15)
                if ml_pred_label == 'benign':
                    low_risk_signals = 0
                    if features.get('uses_https', 0):
                        low_risk_signals += 1
                    if features.get('has_ip_in_domain', 0) == 0 and features.get('has_suspicious_tld', 0) == 0:
                        low_risk_signals += 1
                    if features.get('special_char_ratio', 0) < 0.15 and features.get('url_length', 0) < 80:
                        low_risk_signals += 1
                    if low_risk_signals >= 2:
                        calibrated = min(0.98, calibrated + 0.1)

                # Avoid inflating confidence when signals conflict
                if (ml_pred_label == 'malicious' and risk_score <= 0) or (ml_pred_label == 'benign' and risk_score >= 3):
                    calibrated = max(0.55, calibrated - 0.1)

                return {
                    'prediction': ml_pred_label,
                    'confidence': float(round(calibrated, 4)),
                    'malicious_probability': malicious_p,
                    'benign_probability': benign_p,
                    'method': 'ml+rule_blend',
                    'model_name': self.model_name,
                    'model_type': self.model_type,
                    'raw_ml_confidence': float(round(ml_confidence, 4)),
                    'risk_score': risk_score
                }
            else:
                # Fallback to rule-based analysis
                return self._rule_based_analysis(features, url)
                
        except Exception as e:
            print(f"Error in prediction: {e}")
            return {
                'prediction': 'unknown',
                'confidence': 0,
                'malicious_probability': 0,
                'benign_probability': 0,
                'method': 'error',
                'model_name': 'Error',
                'model_type': 'Error',
                'error': str(e)
            }
    
    def _create_feature_vector(self, features, url):
        """
        Create a feature vector for ML model input
        """
        # Create feature vector from extracted features
        feature_vector = []
        
        # Add numerical features
        numerical_features = [
            features['url_length'], features['domain_length'], features['path_length'],
            features['query_length'], features['subdomain_length'], features['num_dots'],
            features['num_hyphens'], features['num_underscores'], features['num_slashes'],
            features['num_question_marks'], features['num_equal_signs'], features['num_at_symbols'],
            features['num_exclamation_marks'], features['num_hash_symbols'], features['num_dollar_signs'],
            features['num_percent_symbols'], features['num_ampersands'], features['num_tildes'],
            features['special_char_ratio'], features['has_subdomain'], features['subdomain_count'],
            features['domain_word_count'], features['has_ip_in_domain'], features['has_suspicious_tld'],
            features['has_suspicious_keywords'], features['url_entropy'], features['domain_entropy'],
            features['uses_https'], features['has_redirect'], features['has_shortener']
        ]
        
        feature_vector.extend(numerical_features)
        
        # Add TF-IDF features if vectorizer is available
        if self.vectorizer is not None:
            try:
                tfidf_features = self.vectorizer.transform([url]).toarray()[0]
                feature_vector.extend(tfidf_features)
            except:
                # If TF-IDF fails, add zeros
                feature_vector.extend([0] * 100)  # Assuming 100 TF-IDF features
        
        return feature_vector
    
    def _rule_based_analysis(self, features, url):
        """
        Rule-based analysis as fallback when ML model is not available
        """
        risk_score = 0
        
        # High-risk indicators
        if features['has_ip_in_domain']:
            risk_score += 3
        if features['has_suspicious_tld']:
            risk_score += 2
        if features['has_suspicious_keywords']:
            risk_score += 2
        if features['num_at_symbols'] > 0:
            risk_score += 2
        if features['special_char_ratio'] > 0.3:
            risk_score += 1
        if features['url_length'] > 100:
            risk_score += 1
        if features['subdomain_count'] > 2:
            risk_score += 1
        if features['has_shortener']:
            risk_score += 1
        
        # Low-risk indicators
        if features['uses_https']:
            risk_score -= 1
        if features['domain_length'] < 20:
            risk_score -= 1
        
        # Determine prediction based on risk score
        if risk_score >= 3:
            prediction = 'malicious'
            confidence = min(0.9, 0.5 + (risk_score * 0.1))
        elif risk_score >= 1:
            prediction = 'suspicious'
            confidence = 0.6
        else:
            prediction = 'benign'
            confidence = 0.8
        
        return {
            'prediction': prediction,
            'confidence': confidence,
            'malicious_probability': confidence if prediction in ['malicious', 'suspicious'] else 1 - confidence,
            'benign_probability': confidence if prediction == 'benign' else 1 - confidence,
            'method': 'rule_based',
            'model_name': 'Rule-Based Heuristics',
            'model_type': 'Expert System',
            'risk_score': risk_score
        }
    
    def get_detailed_analysis(self, url):
        """
        Get detailed analysis with feature explanations
        """
        features = self.extract_features(url)
        prediction_result = self.predict(url)
        
        # Create detailed analysis
        analysis = {
            'url': url,
            'ml_analysis': prediction_result,
            'features': features,
            'feature_explanations': self._explain_features(features)
        }
        
        return analysis
    
    def _explain_features(self, features):
        """
        Provide categorized explanations for extracted features
        """
        explanations = {
            'URL Structure': [],
            'Security Features': [],
            'Domain Analysis': [],
            'Character Patterns': [],
            'Content Analysis': [],
            'Entropy Analysis': [],
            'Risk Indicators': []
        }
        
        # URL Structure Analysis
        if features['url_length'] > 100:
            explanations['URL Structure'].append(" Very long URL (potential obfuscation)")
        elif features['url_length'] < 20:
            explanations['URL Structure'].append(" Very short URL (suspicious)")
        else:
            explanations['URL Structure'].append(f" URL length: {features['url_length']} characters (normal range)")
        
        if features['domain_length'] > 50:
            explanations['URL Structure'].append(" Very long domain name (suspicious)")
        elif features['domain_length'] < 10:
            explanations['URL Structure'].append(" Very short domain name (suspicious)")
        else:
            explanations['URL Structure'].append(f" Domain length: {features['domain_length']} characters (normal)")
        
        # Security Features
        if features['uses_https']:
            explanations['Security Features'].append(" Uses HTTPS encryption (good security practice)")
        else:
            explanations['Security Features'].append(" Uses HTTP (no encryption - security risk)")
        
        # Domain Analysis
        if features['has_ip_in_domain']:
            explanations['Domain Analysis'].append(" Contains IP address in domain (highly suspicious)")
        
        if features['has_suspicious_tld']:
            explanations['Domain Analysis'].append(" Uses suspicious top-level domain (.xyz, .top, .cc, etc.)")
        
        if features['subdomain_count'] > 3:
            explanations['Domain Analysis'].append(" Multiple subdomains detected (potential obfuscation)")
        elif features['subdomain_count'] > 0:
            explanations['Domain Analysis'].append(f" Has {features['subdomain_count']} subdomain(s)")
        else:
            explanations['Domain Analysis'].append(" No subdomains (clean domain structure)")
        
        # Character Analysis
        if features['num_at_symbols'] > 0:
            explanations['Character Patterns'].append(" Contains @ symbols (potential email spoofing)")
        
        if features['num_hyphens'] > 3:
            explanations['Character Patterns'].append(" Multiple hyphens in URL (suspicious pattern)")
        
        if features['num_underscores'] > 2:
            explanations['Character Patterns'].append(" Multiple underscores in URL (unusual pattern)")
        
        if features['special_char_ratio'] > 0.4:
            explanations['Character Patterns'].append(" Very high ratio of special characters (suspicious)")
        elif features['special_char_ratio'] > 0.2:
            explanations['Character Patterns'].append(" High ratio of special characters (moderate risk)")
        else:
            explanations['Character Patterns'].append(" Normal special character ratio")
        
        # Content Analysis
        if features['has_suspicious_keywords']:
            explanations['Content Analysis'].append(" Contains suspicious keywords (login, account, verify, etc.)")
        
        if features['has_shortener']:
            explanations['Content Analysis'].append(" Uses URL shortener service (hides true destination)")
        
        if features['has_redirect']:
            explanations['Content Analysis'].append(" Contains redirect functionality (potential redirection attack)")
        
        # Entropy Analysis
        if features['url_entropy'] > 4.5:
            explanations['Entropy Analysis'].append(" High URL entropy (random-looking, suspicious)")
        elif features['url_entropy'] > 3.5:
            explanations['Entropy Analysis'].append(" Moderate URL entropy (some randomness)")
        else:
            explanations['Entropy Analysis'].append(" Low URL entropy (predictable pattern)")
        
        if features['domain_entropy'] > 4.0:
            explanations['Entropy Analysis'].append(" High domain entropy (random domain name)")
        elif features['domain_entropy'] > 3.0:
            explanations['Entropy Analysis'].append(" Moderate domain entropy")
        else:
            explanations['Entropy Analysis'].append(" Low domain entropy (predictable domain)")
        
        # Risk Indicators Summary
        risk_count = 0
        for category, items in explanations.items():
            if category != 'Risk Indicators':
                for item in items:
                    if item.startswith(''):
                        risk_count += 1
        
        
        
        # Remove empty categories
        explanations = {k: v for k, v in explanations.items() if v}
        
        return explanations
