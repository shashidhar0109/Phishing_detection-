"""
Advanced Ensemble Methods for Phishing Detection
Combines multiple ML models and techniques for superior accuracy
"""

import numpy as np
import logging
from typing import Dict, List, Any, Tuple
from datetime import datetime
import warnings
from pathlib import Path

try:
    import joblib
    JOBLIB_AVAILABLE = True
except Exception:
    JOBLIB_AVAILABLE = False

# Suppress warnings
warnings.filterwarnings("ignore")

# Optional imports with fallbacks
try:
    from sklearn.ensemble import RandomForestClassifier, VotingClassifier, BaggingClassifier
    from sklearn.ensemble import AdaBoostClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import SVC
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.naive_bayes import GaussianNB
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

logger = logging.getLogger(__name__)

class EnsemblePhishingDetector:
    """
    Advanced ensemble detector combining multiple ML models
    for superior phishing detection accuracy
    """
    
    def __init__(self):
        self.models = {}
        self.ensemble_model = None
        self.scaler = StandardScaler()
        self.feature_importance = {}
        self.model_weights = {}
        self.is_trained = False
        self.model_dir = Path("./logs/models")
        
        # Initialize individual models
        self._initialize_models()
        
        # Initialize ensemble
        self._initialize_ensemble()

        # Try auto-load persisted models
        try:
            self.load_models()
        except Exception:
            pass
    
    def _initialize_models(self):
        """Initialize individual ML models"""
        if not SKLEARN_AVAILABLE:
            logger.warning("Scikit-learn not available, ensemble methods disabled")
            return
        
        # Base models
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'logistic_regression': LogisticRegression(
                max_iter=1000,
                random_state=42,
                solver='liblinear'
            ),
            'svm': SVC(
                kernel='rbf',
                probability=True,
                random_state=42
            ),
            'knn': KNeighborsClassifier(
                n_neighbors=5,
                weights='distance'
            ),
            'naive_bayes': GaussianNB(),
            'decision_tree': DecisionTreeClassifier(
                max_depth=10,
                random_state=42
            ),
            'ada_boost': AdaBoostClassifier(
                n_estimators=50,
                random_state=42
            ),
            'gradient_boost': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )
        }
        
        # Add XGBoost if available
        if XGBOOST_AVAILABLE:
            self.models['xgboost'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric='logloss'
            )
        
        # Add LightGBM if available
        if LIGHTGBM_AVAILABLE:
            self.models['lightgbm'] = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                verbose=-1
            )
        
        logger.info(f"Initialized {len(self.models)} individual models")
    
    def _initialize_ensemble(self):
        """Initialize ensemble voting classifier"""
        if not SKLEARN_AVAILABLE or not self.models:
            logger.warning("Cannot initialize ensemble without base models")
            return
        
        # Create voting classifier with all available models
        estimators = [(name, model) for name, model in self.models.items()]
        
        self.ensemble_model = VotingClassifier(
            estimators=estimators,
            voting='soft',  # Use predicted probabilities
            n_jobs=-1
        )
        
        logger.info("Ensemble voting classifier initialized")

    def save_models(self) -> bool:
        """Persist ensemble, base models, and scaler to disk"""
        if not JOBLIB_AVAILABLE:
            logger.warning("joblib not available; skipping model persistence")
            return False
        try:
            self.model_dir.mkdir(parents=True, exist_ok=True)
            # Save scaler and ensemble
            if self.ensemble_model:
                joblib.dump(self.ensemble_model, self.model_dir / "ensemble.joblib")
            if self.scaler:
                joblib.dump(self.scaler, self.model_dir / "scaler.joblib")
            # Save base models
            for name, model in self.models.items():
                try:
                    joblib.dump(model, self.model_dir / f"{name}.joblib")
                except Exception as e:
                    logger.warning(f"Failed to save {name}: {e}")
            # Save weights metadata
            joblib.dump(self.model_weights, self.model_dir / "weights.joblib")
            logger.info(f"Models persisted to {self.model_dir}")
            return True
        except Exception as e:
            logger.warning(f"Model persistence failed: {e}")
            return False

    def load_models(self) -> bool:
        """Load ensemble, base models, and scaler from disk if present"""
        if not JOBLIB_AVAILABLE:
            return False
        try:
            if not self.model_dir.exists():
                return False
            # Load scaler and ensemble
            ensemble_path = self.model_dir / "ensemble.joblib"
            scaler_path = self.model_dir / "scaler.joblib"
            if ensemble_path.exists():
                self.ensemble_model = joblib.load(ensemble_path)
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
            # Load base models if available
            loaded_any = False
            for name in list(self.models.keys()):
                p = self.model_dir / f"{name}.joblib"
                if p.exists():
                    try:
                        self.models[name] = joblib.load(p)
                        loaded_any = True
                    except Exception as e:
                        logger.warning(f"Failed to load {name}: {e}")
            # Load weights
            weights_path = self.model_dir / "weights.joblib"
            if weights_path.exists():
                try:
                    self.model_weights = joblib.load(weights_path)
                except Exception:
                    pass
            # Set trained flag if ensemble loaded
            if ensemble_path.exists() and scaler_path.exists():
                self.is_trained = True
            return self.is_trained or loaded_any
        except Exception as e:
            logger.warning(f"Model load failed: {e}")
            return False
    
    def _extract_advanced_features(self, domain: str, content: str, legitimate_domain: str) -> Dict[str, Any]:
        """Extract comprehensive features for ensemble models"""
        features = {}
        
        # Domain-based features
        features.update(self._extract_domain_features(domain, legitimate_domain))
        
        # Content-based features
        features.update(self._extract_content_features(content))
        
        # URL-based features
        features.update(self._extract_url_features(domain, content))
        
        # Statistical features
        features.update(self._extract_statistical_features(domain, content))
        
        # Security features
        features.update(self._extract_security_features(domain, content))
        
        return features
    
    def _extract_domain_features(self, domain: str, legitimate_domain: str) -> Dict[str, Any]:
        """Extract domain-specific features"""
        return {
            'domain_length': len(domain),
            'subdomain_count': domain.count('.'),
            'has_hyphen': 1 if '-' in domain else 0,
            'has_number': 1 if any(char.isdigit() for char in domain) else 0,
            'has_mixed_case': 1 if any(c.islower() for c in domain) and any(c.isupper() for c in domain) else 0,
            'tld_length': len(domain.split('.')[-1]) if '.' in domain else 0,
            'digit_count': sum(c.isdigit() for c in domain),
            'vowel_ratio': sum(1 for c in domain if c in 'aeiou') / len(domain) if len(domain) > 0 else 0,
            'consonant_ratio': sum(1 for c in domain if c.isalpha() and c not in 'aeiou') / len(domain) if len(domain) > 0 else 0,
            'special_char_count': sum(1 for c in domain if not c.isalnum() and c != '.'),
            'domain_entropy': self._calculate_entropy(domain),
            'legitimate_domain_similarity': self._calculate_string_similarity(domain, legitimate_domain),
            'has_ip_address': 1 if self._has_ip_address(domain) else 0,
            'has_shortening_service': 1 if any(s in domain for s in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']) else 0,
            'has_uncommon_tld': 1 if domain.split('.')[-1] not in ['com', 'org', 'net', 'in', 'co.in'] else 0,
            'has_at_symbol': 1 if '@' in domain else 0,
            'has_double_slash': 1 if '//' in domain else 0,
            'port_present': 1 if ':' in domain else 0,
            'punycode_present': 1 if 'xn--' in domain else 0,
            'brand_keyword_in_domain': 1 if self._has_brand_keywords(domain) else 0,
            'suspicious_tld': 1 if domain.split('.')[-1] in ['tk', 'ml', 'ga', 'cf'] else 0,
            'domain_age_indicators': self._get_domain_age_indicators(domain),
            'typosquatting_score': self._calculate_typosquatting_score(domain, legitimate_domain)
        }
    
    def _extract_content_features(self, content: str) -> Dict[str, Any]:
        """Extract content-based features"""
        if not content:
            content = ""
        
        content_lower = content.lower()
        
        # Phishing indicators
        phishing_keywords = [
            'urgent', 'immediately', 'verify', 'suspended', 'compromised',
            'expire', 'limited time', 'click here', 'update', 'confirm',
            'security alert', 'unusual activity', 'payment failed'
        ]
        
        # Brand keywords
        brand_keywords = ['sbi', 'hdfc', 'icici', 'google', 'apple', 'microsoft', 'amazon']
        
        # Suspicious patterns
        suspicious_patterns = [
            r'\b(?:urgent|immediate|verify|suspended|compromised)\b',
            r'\b(?:click here|update now|confirm details)\b',
            r'\b(?:security alert|unusual activity)\b',
            r'\b(?:payment failed|transaction declined)\b'
        ]
        
        return {
            'content_length': len(content),
            'phishing_keyword_count': sum(1 for keyword in phishing_keywords if keyword in content_lower),
            'brand_keyword_count': sum(1 for keyword in brand_keywords if keyword in content_lower),
            'suspicious_pattern_count': sum(1 for pattern in suspicious_patterns if __import__('re').search(pattern, content_lower)),
            'has_forms': 1 if any(form in content_lower for form in ['<form', 'input', 'password', 'login']) else 0,
            'has_links': 1 if '<a href' in content_lower else 0,
            'has_images': 1 if '<img' in content_lower else 0,
            'has_scripts': 1 if '<script' in content_lower else 0,
            'has_iframes': 1 if '<iframe' in content_lower else 0,
            'exclamation_count': content.count('!'),
            'question_count': content.count('?'),
            'uppercase_ratio': sum(1 for c in content if c.isupper()) / len(content) if content else 0,
            'digit_ratio': sum(1 for c in content if c.isdigit()) / len(content) if content else 0,
            'special_char_ratio': sum(1 for c in content if not c.isalnum() and not c.isspace()) / len(content) if content else 0
        }
    
    def _extract_url_features(self, domain: str, content: str) -> Dict[str, Any]:
        """Extract URL-specific features"""
        url = content if content.startswith('http') else f"https://{domain}"
        
        return {
            'url_length': len(url),
            'path_depth': url.count('/') - 2 if '//' in url else 0,
            'query_params_count': url.count('?') + url.count('&'),
            'has_https': 1 if 'https://' in url else 0,
            'has_http': 1 if 'http://' in url else 0,
            'has_www': 1 if 'www.' in url else 0,
            'has_redirect': 1 if any(redirect in url for redirect in ['redirect', 'goto', 'link']) else 0,
            'has_encoded_chars': 1 if '%' in url else 0,
            'has_unicode': 1 if any(ord(c) > 127 for c in url) else 0
        }
    
    def _extract_statistical_features(self, domain: str, content: str) -> Dict[str, Any]:
        """Extract statistical features"""
        return {
            'domain_entropy': self._calculate_entropy(domain),
            'content_entropy': self._calculate_entropy(content),
            'domain_variance': np.var([ord(c) for c in domain]) if domain else 0,
            'content_variance': np.var([ord(c) for c in content]) if content else 0,
            'domain_std': np.std([ord(c) for c in domain]) if domain else 0,
            'content_std': np.std([ord(c) for c in content]) if content else 0,
            'domain_mean': np.mean([ord(c) for c in domain]) if domain else 0,
            'content_mean': np.mean([ord(c) for c in content]) if content else 0
        }
    
    def _extract_security_features(self, domain: str, content: str) -> Dict[str, Any]:
        """Extract security-related features"""
        return {
            'has_ssl_indicators': 1 if any(ssl in content.lower() for ssl in ['ssl', 'https', 'secure']) else 0,
            'has_certificate_indicators': 1 if any(cert in content.lower() for cert in ['certificate', 'cert', 'verisign']) else 0,
            'has_trust_indicators': 1 if any(trust in content.lower() for trust in ['trusted', 'verified', 'secure']) else 0,
            'has_privacy_indicators': 1 if any(privacy in content.lower() for privacy in ['privacy', 'policy', 'terms']) else 0,
            'has_contact_info': 1 if any(contact in content.lower() for contact in ['contact', 'support', 'help']) else 0,
            'has_legitimate_indicators': 1 if any(legit in content.lower() for legit in ['official', 'legitimate', 'authorized']) else 0
        }
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0
        probabilities = [s.count(c) / len(s) for c in set(s)]
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy
    
    def _calculate_string_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity between two strings"""
        if not s1 or not s2:
            return 0.0
        
        # Simple Jaccard similarity
        set1 = set(s1.lower())
        set2 = set(s2.lower())
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain contains IP address"""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, domain))
    
    def _has_brand_keywords(self, domain: str) -> bool:
        """Check if domain contains brand keywords"""
        brand_keywords = ['sbi', 'hdfc', 'icici', 'google', 'apple', 'microsoft', 'amazon']
        domain_lower = domain.lower()
        return any(keyword in domain_lower for keyword in brand_keywords)
    
    def _get_domain_age_indicators(self, domain: str) -> int:
        """Get domain age indicators (simplified)"""
        # This would typically involve WHOIS lookup
        # For now, return based on domain characteristics
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            return 1  # Newer TLDs often used for phishing
        return 0
    
    def _calculate_typosquatting_score(self, domain: str, legitimate_domain: str) -> float:
        """Calculate typosquatting score"""
        if not legitimate_domain:
            return 0.0
        
        # Simple edit distance based score
        return self._calculate_string_similarity(domain, legitimate_domain)
    
    def train_ensemble(self, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train the ensemble model"""
        if not SKLEARN_AVAILABLE or not self.ensemble_model:
            logger.error("Cannot train ensemble without sklearn or ensemble model")
            return {'success': False, 'error': 'Missing dependencies'}
        
        try:
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_val_scaled = self.scaler.transform(X_val) if X_val is not None else None
            
            # Train individual models and get their performance
            individual_scores = {}
            for name, model in self.models.items():
                try:
                    model.fit(X_train_scaled, y_train)
                    
                    if X_val is not None:
                        y_pred = model.predict(X_val_scaled)
                        score = accuracy_score(y_val, y_pred)
                        individual_scores[name] = score
                        logger.info(f"{name} accuracy: {score:.4f}")
                    
                except Exception as e:
                    logger.warning(f"Failed to train {name}: {e}")
                    individual_scores[name] = 0.0
            
            # Calculate model weights based on performance
            if individual_scores:
                total_score = sum(individual_scores.values())
                self.model_weights = {name: score/total_score for name, score in individual_scores.items()}
            else:
                # Equal weights if no validation data
                self.model_weights = {name: 1.0/len(self.models) for name in self.models.keys()}
            
            # Train ensemble model
            self.ensemble_model.fit(X_train_scaled, y_train)
            
            # Evaluate ensemble
            ensemble_score = 0.0
            if X_val is not None:
                y_pred_ensemble = self.ensemble_model.predict(X_val_scaled)
                ensemble_score = accuracy_score(y_val, y_pred_ensemble)
            
            self.is_trained = True
            
            return {
                'success': True,
                'individual_scores': individual_scores,
                'model_weights': self.model_weights,
                'ensemble_score': ensemble_score,
                'models_trained': len(self.models)
            }
            
        except Exception as e:
            logger.error(f"Ensemble training failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def predict_phishing_probability(self, domain: str, content: str, legitimate_domain: str) -> Dict[str, Any]:
        """Predict phishing probability using ensemble methods"""
        if not self.is_trained:
            logger.warning("Ensemble not trained, using fallback prediction")
            return self._fallback_prediction(domain, content, legitimate_domain)
        
        try:
            # Extract features
            features = self._extract_advanced_features(domain, content, legitimate_domain)
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Get individual model predictions
            individual_predictions = {}
            for name, model in self.models.items():
                try:
                    pred = model.predict_proba(feature_vector_scaled)[0][1]  # Probability of phishing
                    individual_predictions[name] = pred
                except Exception as e:
                    logger.warning(f"Prediction failed for {name}: {e}")
                    individual_predictions[name] = 0.5
            
            # Get ensemble prediction
            ensemble_pred = self.ensemble_model.predict_proba(feature_vector_scaled)[0][1]
            
            # Calculate weighted average
            weighted_pred = sum(
                pred * self.model_weights.get(name, 0.0) 
                for name, pred in individual_predictions.items()
            )
            
            # Calculate confidence based on agreement between models
            predictions = list(individual_predictions.values())
            confidence = 1.0 - np.std(predictions) if len(predictions) > 1 else 0.5
            
            return {
                'phishing_probability': float(ensemble_pred),
                'weighted_probability': float(weighted_pred),
                'confidence': float(confidence),
                'individual_predictions': individual_predictions,
                'model_weights': self.model_weights,
                'feature_importance': {name: float(value) for name, value in features.items()}
            }
            
        except Exception as e:
            logger.error(f"Ensemble prediction failed: {e}")
            return self._fallback_prediction(domain, content, legitimate_domain)
    
    def _fallback_prediction(self, domain: str, content: str, legitimate_domain: str) -> Dict[str, Any]:
        """Fallback prediction when ensemble is not available"""
        # Simple heuristic-based prediction
        score = 0.0
        
        # Domain-based scoring
        if '-' in domain:
            score += 0.1
        if any(char.isdigit() for char in domain):
            score += 0.1
        if len(domain) > 20:
            score += 0.1
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            score += 0.3
        
        # Content-based scoring
        if content:
            content_lower = content.lower()
            phishing_keywords = ['urgent', 'verify', 'suspended', 'click here']
            score += sum(0.1 for keyword in phishing_keywords if keyword in content_lower)
        
        return {
            'phishing_probability': min(score, 1.0),
            'weighted_probability': min(score, 1.0),
            'confidence': 0.3,
            'individual_predictions': {},
            'model_weights': {},
            'feature_importance': {}
        }
    
    def get_model_performance(self) -> Dict[str, Any]:
        """Get performance metrics for all models"""
        if not self.is_trained:
            return {'error': 'Models not trained'}
        
        return {
            'is_trained': self.is_trained,
            'models_count': len(self.models),
            'model_weights': self.model_weights,
            'available_models': list(self.models.keys()),
            'ensemble_type': 'VotingClassifier (Soft)',
            'feature_scaling': 'StandardScaler'
        }
