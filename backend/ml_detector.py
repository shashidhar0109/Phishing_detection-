"""
Advanced ML-based Phishing Detection Engine
Implements multiple ML models for sophisticated phishing detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
from typing import Dict, List, Tuple, Any
import logging
from datetime import datetime
import re
import hashlib
from urllib.parse import urlparse
import dns.resolver
import socket

logger = logging.getLogger(__name__)

class MLPhishingDetector:
    """
    Advanced ML-based phishing detection using ensemble methods
    """
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        os.makedirs(model_path, exist_ok=True)
        
        # Initialize models
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.feature_names = []
        
        # Initialize ensemble model
        self.ensemble_model = None
        self.is_trained = False
        
        # Feature extraction parameters
        self.max_features = 10000
        self.n_gram_range = (1, 3)
        
    def extract_domain_features(self, domain: str, cse_domain: str = None) -> Dict[str, Any]:
        """
        Extract comprehensive features from domain for ML classification
        """
        features = {}
        
        # Basic domain features
        features['domain_length'] = len(domain)
        features['subdomain_count'] = len(domain.split('.')) - 2
        features['has_hyphen'] = 1 if '-' in domain else 0
        features['has_number'] = 1 if any(c.isdigit() for c in domain) else 0
        features['has_mixed_case'] = 1 if any(c.isupper() for c in domain) and any(c.islower() for c in domain) else 0
        
        # TLD analysis
        tld = domain.split('.')[-1] if '.' in domain else ''
        features['tld_length'] = len(tld)
        features['is_common_tld'] = 1 if tld in ['com', 'org', 'net', 'co', 'in'] else 0
        
        # Character analysis
        features['vowel_ratio'] = sum(1 for c in domain.lower() if c in 'aeiou') / len(domain) if domain else 0
        features['consonant_ratio'] = sum(1 for c in domain.lower() if c.isalpha() and c not in 'aeiou') / len(domain) if domain else 0
        features['digit_ratio'] = sum(1 for c in domain if c.isdigit()) / len(domain) if domain else 0
        features['special_char_ratio'] = sum(1 for c in domain if not c.isalnum() and c != '.') / len(domain) if domain else 0
        
        # Entropy calculation
        features['entropy'] = self._calculate_entropy(domain)
        
        # Similarity to CSE domain
        if cse_domain:
            features['levenshtein_distance'] = self._levenshtein_distance(domain, cse_domain)
            features['jaccard_similarity'] = self._jaccard_similarity(domain, cse_domain)
            features['cosine_similarity'] = self._cosine_similarity(domain, cse_domain)
        else:
            features['levenshtein_distance'] = 0
            features['jaccard_similarity'] = 0
            features['cosine_similarity'] = 0
        
        # Suspicious patterns
        features['has_suspicious_words'] = self._has_suspicious_words(domain)
        features['has_typo_patterns'] = self._has_typo_patterns(domain)
        features['has_homograph_patterns'] = self._has_homograph_patterns(domain)
        
        # Domain age estimation (based on TLD and patterns)
        features['estimated_age_score'] = self._estimate_domain_age_score(domain)
        
        # URL structure analysis
        features['has_subdomain'] = 1 if len(domain.split('.')) > 2 else 0
        features['subdomain_length'] = len(domain.split('.')[0]) if len(domain.split('.')) > 2 else 0
        
        return features
    
    def extract_content_features(self, content: str) -> Dict[str, Any]:
        """
        Extract features from webpage content
        """
        features = {}
        
        if not content:
            content = ""
        
        content_lower = content.lower()
        
        # Content length and structure
        features['content_length'] = len(content)
        features['word_count'] = len(content.split())
        features['sentence_count'] = content.count('.') + content.count('!') + content.count('?')
        
        # Suspicious keywords
        phishing_keywords = [
            'verify', 'update', 'suspended', 'expired', 'urgent', 'immediate',
            'security', 'account', 'login', 'password', 'confirm', 'validate',
            'click here', 'download', 'free', 'win', 'congratulations'
        ]
        
        features['phishing_keyword_count'] = sum(1 for keyword in phishing_keywords if keyword in content_lower)
        features['phishing_keyword_ratio'] = features['phishing_keyword_count'] / max(features['word_count'], 1)
        
        # Form analysis
        features['has_login_form'] = 1 if any(form in content_lower for form in ['login', 'sign in', 'username', 'password']) else 0
        features['has_payment_form'] = 1 if any(form in content_lower for form in ['payment', 'credit card', 'billing', 'checkout']) else 0
        
        # Language analysis
        features['has_grammatical_errors'] = self._detect_grammatical_errors(content)
        features['has_urgent_language'] = 1 if any(word in content_lower for word in ['urgent', 'immediate', 'asap', 'now']) else 0
        
        # Technical indicators
        features['has_external_links'] = content.count('http') - content.count('https')
        features['has_redirects'] = 1 if 'redirect' in content_lower or 'location.href' in content_lower else 0
        
        return features
    
    def extract_network_features(self, domain: str) -> Dict[str, Any]:
        """
        Extract network-related features
        """
        features = {}
        
        try:
            # DNS resolution
            ip_addresses = []
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ip_addresses = [str(answer) for answer in answers]
            except:
                pass
            
            features['has_valid_dns'] = 1 if ip_addresses else 0
            features['ip_count'] = len(ip_addresses)
            
            # IP analysis
            if ip_addresses:
                ip = ip_addresses[0]
                features['is_private_ip'] = 1 if self._is_private_ip(ip) else 0
                features['ip_reputation_score'] = self._get_ip_reputation_score(ip)
            else:
                features['is_private_ip'] = 0
                features['ip_reputation_score'] = 0
            
            # SSL certificate analysis
            features['has_ssl'] = self._check_ssl_certificate(domain)
            features['ssl_validity_score'] = self._get_ssl_validity_score(domain)
            
        except Exception as e:
            logger.warning(f"Error extracting network features for {domain}: {e}")
            features = {
                'has_valid_dns': 0,
                'ip_count': 0,
                'is_private_ip': 0,
                'ip_reputation_score': 0,
                'has_ssl': 0,
                'ssl_validity_score': 0
            }
        
        return features
    
    def create_feature_vector(self, domain: str, content: str = "", cse_domain: str = None) -> np.ndarray:
        """
        Create complete feature vector for ML model
        """
        # Extract all features
        domain_features = self.extract_domain_features(domain, cse_domain)
        content_features = self.extract_content_features(content)
        network_features = self.extract_network_features(domain)
        
        # Combine all features
        all_features = {**domain_features, **content_features, **network_features}
        
        # Convert to numpy array
        feature_vector = np.array([all_features.get(feature, 0) for feature in self.feature_names])
        
        return feature_vector
    
    def train_models(self, training_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Train multiple ML models on training data
        """
        logger.info(f"Training ML models on {len(training_data)} samples")
        
        # Prepare data
        X = []
        y = []
        
        for sample in training_data:
            domain = sample.get('domain', '')
            content = sample.get('content', '')
            cse_domain = sample.get('cse_domain', '')
            is_phishing = sample.get('is_phishing', 0)
            
            # Create feature vector
            feature_vector = self.create_feature_vector(domain, content, cse_domain)
            X.append(feature_vector)
            y.append(is_phishing)
        
        X = np.array(X)
        y = np.array(y)
        
        # Store feature names for later use
        if not self.feature_names:
            sample_features = self.create_feature_vector("example.com", "example content", "example.org")
            self.feature_names = [f"feature_{i}" for i in range(len(sample_features))]
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        self.scalers['main'] = StandardScaler()
        X_train_scaled = self.scalers['main'].fit_transform(X_train)
        X_test_scaled = self.scalers['main'].transform(X_test)
        
        # Train individual models
        models_config = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'logistic_regression': LogisticRegression(random_state=42, max_iter=1000),
            'svm': SVC(probability=True, random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42, max_iter=1000)
        }
        
        model_scores = {}
        
        for name, model in models_config.items():
            logger.info(f"Training {name}...")
            model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            model_scores[name] = accuracy
            
            # Save model
            self.models[name] = model
            joblib.dump(model, os.path.join(self.model_path, f"{name}_model.pkl"))
            
            logger.info(f"{name} accuracy: {accuracy:.4f}")
        
        # Create ensemble model
        self.ensemble_model = VotingClassifier(
            estimators=list(self.models.items()),
            voting='soft'
        )
        self.ensemble_model.fit(X_train_scaled, y_train)
        
        # Evaluate ensemble
        y_pred_ensemble = self.ensemble_model.predict(X_test_scaled)
        ensemble_accuracy = accuracy_score(y_test, y_pred_ensemble)
        model_scores['ensemble'] = ensemble_accuracy
        
        # Save ensemble model
        joblib.dump(self.ensemble_model, os.path.join(self.model_path, "ensemble_model.pkl"))
        joblib.dump(self.scalers['main'], os.path.join(self.model_path, "scaler.pkl"))
        
        self.is_trained = True
        logger.info(f"Ensemble model accuracy: {ensemble_accuracy:.4f}")
        
        return model_scores
    
    def predict_phishing_probability(self, domain: str, content: str = "", cse_domain: str = None) -> Dict[str, Any]:
        """
        Predict phishing probability using trained models
        """
        if not self.is_trained:
            # Load pre-trained models if available
            self._load_models()
        
        if not self.is_trained:
            logger.warning("No trained models available, using fallback scoring")
            return self._fallback_scoring(domain, content, cse_domain)
        
        try:
            # Create feature vector
            feature_vector = self.create_feature_vector(domain, content, cse_domain)
            
            # Scale features
            if 'main' in self.scalers:
                feature_vector = self.scalers['main'].transform(feature_vector.reshape(1, -1))
            else:
                feature_vector = feature_vector.reshape(1, -1)
            
            # Get predictions from all models
            predictions = {}
            for name, model in self.models.items():
                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(feature_vector)[0]
                    predictions[name] = prob[1] if len(prob) > 1 else prob[0]
                else:
                    pred = model.predict(feature_vector)[0]
                    predictions[name] = float(pred)
            
            # Get ensemble prediction
            if self.ensemble_model:
                ensemble_prob = self.ensemble_model.predict_proba(feature_vector)[0]
                ensemble_score = ensemble_prob[1] if len(ensemble_prob) > 1 else ensemble_prob[0]
            else:
                ensemble_score = np.mean(list(predictions.values()))
            
            return {
                'phishing_probability': float(ensemble_score),
                'individual_predictions': predictions,
                'confidence': self._calculate_confidence(predictions),
                'feature_importance': self._get_feature_importance(domain, content, cse_domain)
            }
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return self._fallback_scoring(domain, content, cse_domain)
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            # Load scaler
            scaler_path = os.path.join(self.model_path, "scaler.pkl")
            if os.path.exists(scaler_path):
                self.scalers['main'] = joblib.load(scaler_path)
            
            # Load individual models
            for model_name in ['random_forest', 'gradient_boosting', 'logistic_regression', 'svm', 'neural_network']:
                model_path = os.path.join(self.model_path, f"{model_name}_model.pkl")
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
            
            # Load ensemble model
            ensemble_path = os.path.join(self.model_path, "ensemble_model.pkl")
            if os.path.exists(ensemble_path):
                self.ensemble_model = joblib.load(ensemble_path)
            
            if self.models:
                self.is_trained = True
                logger.info("Successfully loaded pre-trained models")
                
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
    
    def _fallback_scoring(self, domain: str, content: str, cse_domain: str) -> Dict[str, Any]:
        """Fallback scoring when ML models are not available"""
        # Basic rule-based scoring
        score = 0.0
        
        # Domain length penalty
        if len(domain) > 20:
            score += 0.1
        
        # Suspicious patterns
        if any(word in domain.lower() for word in ['secure', 'verify', 'update', 'login']):
            score += 0.2
        
        # Content analysis
        if content:
            if any(word in content.lower() for word in ['urgent', 'immediate', 'click here']):
                score += 0.3
        
        return {
            'phishing_probability': min(score, 1.0),
            'individual_predictions': {'fallback': min(score, 1.0)},
            'confidence': 0.5,
            'feature_importance': {}
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _jaccard_similarity(self, s1: str, s2: str) -> float:
        """Calculate Jaccard similarity between two strings"""
        set1 = set(s1.lower())
        set2 = set(s2.lower())
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0.0
    
    def _cosine_similarity(self, s1: str, s2: str) -> float:
        """Calculate cosine similarity between two strings"""
        # Simple character-based cosine similarity
        chars1 = s1.lower()
        chars2 = s2.lower()
        
        # Create character frequency vectors
        all_chars = set(chars1 + chars2)
        vec1 = [chars1.count(c) for c in all_chars]
        vec2 = [chars2.count(c) for c in all_chars]
        
        # Calculate cosine similarity
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = sum(a * a for a in vec1) ** 0.5
        magnitude2 = sum(b * b for b in vec2) ** 0.5
        
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
        
        return dot_product / (magnitude1 * magnitude2)
    
    def _has_suspicious_words(self, domain: str) -> int:
        """Check if domain contains suspicious words"""
        suspicious_words = [
            'secure', 'verify', 'update', 'login', 'account', 'bank',
            'payment', 'confirm', 'validate', 'urgent', 'immediate'
        ]
        return 1 if any(word in domain.lower() for word in suspicious_words) else 0
    
    def _has_typo_patterns(self, domain: str) -> int:
        """Check for common typo patterns"""
        typo_patterns = [
            r'[aeiou]{3,}',  # Multiple vowels
            r'[bcdfghjklmnpqrstvwxyz]{4,}',  # Multiple consonants
            r'[0-9]{3,}',  # Multiple numbers
        ]
        return 1 if any(re.search(pattern, domain.lower()) for pattern in typo_patterns) else 0
    
    def _has_homograph_patterns(self, domain: str) -> int:
        """Check for homograph attack patterns"""
        # Check for mixed scripts (Latin + Cyrillic, etc.)
        has_latin = any(ord(c) < 128 for c in domain)
        has_non_latin = any(ord(c) >= 128 for c in domain)
        return 1 if has_latin and has_non_latin else 0
    
    def _estimate_domain_age_score(self, domain: str) -> float:
        """Estimate domain age based on patterns (0-1 scale)"""
        # Newer domains are more suspicious
        score = 0.5  # Default
        
        # TLD-based scoring
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in ['tk', 'ml', 'ga', 'cf']:  # Free TLDs
            score += 0.3
        elif tld in ['com', 'org', 'net']:  # Established TLDs
            score -= 0.2
        
        # Pattern-based scoring
        if any(char.isdigit() for char in domain):
            score += 0.1  # Numbers suggest newer domains
        
        return min(max(score, 0.0), 1.0)
    
    def _detect_grammatical_errors(self, content: str) -> int:
        """Simple grammatical error detection"""
        if not content:
            return 0
        
        # Check for common phishing grammatical errors
        error_patterns = [
            r'\b(click here|click this|click below)\b',
            r'\b(urgent|immediate|asap)\b',
            r'\b(verify your account|update your information)\b',
            r'\b(security alert|suspicious activity)\b'
        ]
        
        return 1 if any(re.search(pattern, content.lower()) for pattern in error_patterns) else 0
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _get_ip_reputation_score(self, ip: str) -> float:
        """Get IP reputation score (0-1, higher is more suspicious)"""
        # This is a simplified version - in production, you'd use real reputation services
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Private IPs are more suspicious
            if ip_obj.is_private:
                return 0.8
            
            # Check for known suspicious IP ranges (simplified)
            if str(ip_obj).startswith('192.168.') or str(ip_obj).startswith('10.'):
                return 0.7
            
            return 0.3  # Default for public IPs
            
        except:
            return 0.5
    
    def _check_ssl_certificate(self, domain: str) -> int:
        """Check if domain has valid SSL certificate"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return 1
        except:
            return 0
    
    def _get_ssl_validity_score(self, domain: str) -> float:
        """Get SSL certificate validity score"""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        return 0.8  # Expiring soon
                    elif days_until_expiry < 90:
                        return 0.5  # Expiring in 3 months
                    else:
                        return 0.1  # Valid for long time
                        
        except:
            return 0.5  # Default if can't check
    
    def _calculate_confidence(self, predictions: Dict[str, float]) -> float:
        """Calculate confidence based on prediction agreement"""
        if not predictions:
            return 0.0
        
        values = list(predictions.values())
        mean_pred = np.mean(values)
        std_pred = np.std(values)
        
        # Higher confidence when predictions agree (low std)
        confidence = max(0.0, 1.0 - std_pred)
        return confidence
    
    def _get_feature_importance(self, domain: str, content: str, cse_domain: str) -> Dict[str, float]:
        """Get feature importance for the prediction"""
        # This is a simplified version - in production, you'd use SHAP or similar
        importance = {}
        
        # Domain length importance
        importance['domain_length'] = min(len(domain) / 50.0, 1.0)
        
        # Suspicious words importance
        suspicious_count = sum(1 for word in ['secure', 'verify', 'update', 'login'] if word in domain.lower())
        importance['suspicious_words'] = min(suspicious_count / 3.0, 1.0)
        
        # Content urgency importance
        if content:
            urgent_words = ['urgent', 'immediate', 'asap', 'now']
            urgent_count = sum(1 for word in urgent_words if word in content.lower())
            importance['urgent_language'] = min(urgent_count / 2.0, 1.0)
        
        return importance
