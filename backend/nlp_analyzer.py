"""
Advanced NLP-based Content Analysis for Phishing Detection
Uses transformers, NLTK, and spaCy for sophisticated content analysis
"""

import re
import numpy as np
from typing import Dict, List, Tuple, Any
import logging
from datetime import datetime
import warnings

# Suppress warnings
warnings.filterwarnings("ignore")

# Optional imports with fallbacks
try:
    import nltk
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False

try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

class NLPContentAnalyzer:
    """
    Advanced NLP-based content analysis for phishing detection
    """
    
    def __init__(self):
        self.nlp = None
        self.sentiment_analyzer = None
        self.text_classifier = None
        self.tokenizer = None
        self.model = None
        self.tfidf_vectorizer = None
        
        # Initialize models
        self._initialize_models()
        
        # Phishing-specific patterns
        self.phishing_patterns = {
            'urgency': [
                r'\b(urgent|immediate|asap|now|quickly|hurry)\b',
                r'\b(expires?|expiring|deadline|limited time)\b',
                r'\b(act now|don\'t wait|last chance)\b'
            ],
            'authority': [
                r'\b(verify|confirm|validate|update|secure)\b',
                r'\b(account|profile|information|details)\b',
                r'\b(security|safety|protection|suspicious)\b'
            ],
            'action': [
                r'\b(click here|click below|click this|click now)\b',
                r'\b(download|install|update|upgrade)\b',
                r'\b(enter|submit|provide|fill)\b'
            ],
            'threat': [
                r'\b(suspended|blocked|locked|terminated)\b',
                r'\b(penalty|fine|charge|fee)\b',
                r'\b(legal|lawsuit|court|police)\b'
            ],
            'reward': [
                r'\b(free|gift|prize|win|congratulations)\b',
                r'\b(discount|offer|deal|sale)\b',
                r'\b(bonus|reward|cash|money)\b'
            ]
        }
        
        # Suspicious keywords with weights
        self.suspicious_keywords = {
            'high_risk': {
                'verify your account': 0.9,
                'update your information': 0.9,
                'click here to verify': 0.9,
                'urgent security alert': 0.9,
                'suspended account': 0.9,
                'immediate action required': 0.9
            },
            'medium_risk': {
                'login to your account': 0.6,
                'security notification': 0.6,
                'unusual activity': 0.6,
                'confirm your identity': 0.6,
                'update payment method': 0.6
            },
            'low_risk': {
                'welcome': 0.3,
                'thank you': 0.3,
                'newsletter': 0.3,
                'reminder': 0.3
            }
        }
    
    def _initialize_models(self):
        """Initialize NLP models with fallbacks"""
        try:
            # Initialize spaCy
            if SPACY_AVAILABLE:
                try:
                    self.nlp = spacy.load("en_core_web_sm")
                except OSError:
                    logger.warning("spaCy English model not found, using fallback")
                    self.nlp = None
            else:
                logger.warning("spaCy not available, using fallback")
                self.nlp = None
            
            # Initialize NLTK
            if NLTK_AVAILABLE:
                try:
                    nltk.data.find('tokenizers/punkt')
                except LookupError:
                    nltk.download('punkt')
                
                try:
                    nltk.data.find('corpora/stopwords')
                except LookupError:
                    nltk.download('stopwords')
                
                try:
                    nltk.data.find('vader_lexicon')
                except LookupError:
                    nltk.download('vader_lexicon')
                
                # Initialize sentiment analyzer
                from nltk.sentiment import SentimentIntensityAnalyzer
                self.sentiment_analyzer = SentimentIntensityAnalyzer()
            else:
                logger.warning("NLTK not available, using fallback")
                self.sentiment_analyzer = None
            
            # Initialize text classification pipeline
            if TRANSFORMERS_AVAILABLE:
                try:
                    self.text_classifier = pipeline(
                        "text-classification",
                        model="microsoft/DialoGPT-medium",
                        return_all_scores=True
                    )
                except Exception as e:
                    logger.warning(f"Could not load transformer model: {e}")
                    self.text_classifier = None
            else:
                logger.warning("Transformers not available, using fallback")
                self.text_classifier = None
            
            # Initialize TF-IDF vectorizer
            if SKLEARN_AVAILABLE:
                self.tfidf_vectorizer = TfidfVectorizer(
                    max_features=5000,
                    stop_words='english',
                    ngram_range=(1, 3)
                )
            else:
                logger.warning("scikit-learn not available, using fallback")
                self.tfidf_vectorizer = None
            
            logger.info("NLP models initialized with available components")
            
        except Exception as e:
            logger.error(f"Error initializing NLP models: {e}")
    
    def analyze_content(self, content: str, domain: str = "") -> Dict[str, Any]:
        """
        Comprehensive content analysis for phishing detection
        """
        if not content:
            return self._get_empty_analysis()
        
        try:
            # Basic text preprocessing
            cleaned_content = self._preprocess_text(content)
            
            # Perform various analyses
            analysis = {
                'text_length': len(content),
                'word_count': len(content.split()),
                'sentence_count': len(re.split(r'[.!?]+', content)),
                'paragraph_count': len(content.split('\n\n')),
                
                # Pattern analysis
                'phishing_patterns': self._analyze_phishing_patterns(cleaned_content),
                'suspicious_keywords': self._analyze_suspicious_keywords(cleaned_content),
                'grammatical_errors': self._detect_grammatical_errors(cleaned_content),
                'language_quality': self._analyze_language_quality(cleaned_content),
                
                # Sentiment analysis
                'sentiment': self._analyze_sentiment(cleaned_content),
                
                # Technical analysis
                'technical_indicators': self._analyze_technical_indicators(content),
                'form_analysis': self._analyze_forms(content),
                'link_analysis': self._analyze_links(content),
                
                # Advanced NLP features
                'named_entities': self._extract_named_entities(cleaned_content),
                'pos_analysis': self._analyze_pos_tags(cleaned_content),
                'readability': self._calculate_readability(cleaned_content),
                
                # Domain-specific analysis
                'domain_consistency': self._analyze_domain_consistency(content, domain),
                'brand_impersonation': self._detect_brand_impersonation(cleaned_content, domain),
                
                # Overall risk score
                'risk_score': 0.0,
                'confidence': 0.0
            }
            
            # Calculate overall risk score
            analysis['risk_score'] = self._calculate_risk_score(analysis)
            analysis['confidence'] = self._calculate_confidence(analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in content analysis: {e}")
            return self._get_empty_analysis()
    
    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for analysis"""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep punctuation
        text = re.sub(r'[^\w\s.,!?;:]', ' ', text)
        
        return text.strip()
    
    def _analyze_phishing_patterns(self, content: str) -> Dict[str, Any]:
        """Analyze content for phishing patterns"""
        pattern_scores = {}
        total_matches = 0
        
        for category, patterns in self.phishing_patterns.items():
            matches = 0
            for pattern in patterns:
                pattern_matches = len(re.findall(pattern, content, re.IGNORECASE))
                matches += pattern_matches
                total_matches += pattern_matches
            
            pattern_scores[category] = {
                'count': matches,
                'score': min(matches / 10.0, 1.0)  # Normalize to 0-1
            }
        
        return {
            'category_scores': pattern_scores,
            'total_matches': total_matches,
            'overall_score': min(total_matches / 20.0, 1.0)
        }
    
    def _analyze_suspicious_keywords(self, content: str) -> Dict[str, Any]:
        """Analyze content for suspicious keywords"""
        content_lower = content.lower()
        keyword_scores = {}
        total_score = 0.0
        
        for risk_level, keywords in self.suspicious_keywords.items():
            level_score = 0.0
            level_count = 0
            
            for keyword, weight in keywords.items():
                if keyword in content_lower:
                    level_score += weight
                    level_count += 1
            
            keyword_scores[risk_level] = {
                'count': level_count,
                'score': level_score,
                'max_possible': len(keywords)
            }
            total_score += level_score
        
        return {
            'level_scores': keyword_scores,
            'total_score': total_score,
            'overall_risk': min(total_score / 5.0, 1.0)
        }
    
    def _detect_grammatical_errors(self, content: str) -> Dict[str, Any]:
        """Detect grammatical errors and inconsistencies"""
        errors = {
            'spelling_errors': 0,
            'grammar_errors': 0,
            'punctuation_errors': 0,
            'capitalization_errors': 0,
            'overall_score': 0.0
        }
        
        # Simple spelling error detection (basic implementation)
        words = content.split()
        for word in words:
            # Check for repeated characters
            if re.search(r'(.)\1{2,}', word):
                errors['spelling_errors'] += 1
            
            # Check for missing vowels in long words
            if len(word) > 6 and not re.search(r'[aeiou]', word.lower()):
                errors['spelling_errors'] += 1
        
        # Grammar error detection
        sentences = re.split(r'[.!?]+', content)
        for sentence in sentences:
            sentence = sentence.strip()
            if sentence:
                # Check for missing articles
                if re.search(r'\b(account|information|details)\b', sentence) and not re.search(r'\b(the|a|an)\b', sentence):
                    errors['grammar_errors'] += 1
                
                # Check for sentence structure
                if len(sentence.split()) < 3:
                    errors['grammar_errors'] += 1
        
        # Punctuation errors
        errors['punctuation_errors'] = len(re.findall(r'[!]{2,}|[?]{2,}', content))
        
        # Capitalization errors
        errors['capitalization_errors'] = len(re.findall(r'\b[a-z][A-Z]', content))
        
        # Calculate overall score
        total_errors = sum(errors.values()) - errors['overall_score']
        errors['overall_score'] = min(total_errors / max(len(words), 1), 1.0)
        
        return errors
    
    def _analyze_language_quality(self, content: str) -> Dict[str, Any]:
        """Analyze language quality and sophistication"""
        quality = {
            'avg_word_length': 0.0,
            'avg_sentence_length': 0.0,
            'vocabulary_diversity': 0.0,
            'formality_score': 0.0,
            'overall_score': 0.0
        }
        
        if not content:
            return quality
        
        words = content.split()
        sentences = re.split(r'[.!?]+', content)
        
        if words:
            # Average word length
            quality['avg_word_length'] = sum(len(word) for word in words) / len(words)
            
            # Vocabulary diversity (unique words / total words)
            unique_words = len(set(word.lower() for word in words))
            quality['vocabulary_diversity'] = unique_words / len(words)
        
        if sentences:
            # Average sentence length
            quality['avg_sentence_length'] = sum(len(sentence.split()) for sentence in sentences) / len(sentences)
        
        # Formality score (based on formal vs informal words)
        formal_words = ['please', 'thank you', 'regards', 'sincerely', 'respectfully']
        informal_words = ['hey', 'hi', 'thanks', 'cheers', 'bye']
        
        formal_count = sum(1 for word in words if word.lower() in formal_words)
        informal_count = sum(1 for word in words if word.lower() in informal_words)
        
        if formal_count + informal_count > 0:
            quality['formality_score'] = formal_count / (formal_count + informal_count)
        
        # Overall quality score
        quality['overall_score'] = (
            min(quality['avg_word_length'] / 8.0, 1.0) * 0.3 +
            min(quality['vocabulary_diversity'], 1.0) * 0.3 +
            min(quality['formality_score'], 1.0) * 0.4
        )
        
        return quality
    
    def _analyze_sentiment(self, content: str) -> Dict[str, Any]:
        """Analyze sentiment of content"""
        if not self.sentiment_analyzer:
            return {'compound': 0.0, 'positive': 0.0, 'negative': 0.0, 'neutral': 0.0}
        
        try:
            scores = self.sentiment_analyzer.polarity_scores(content)
            return scores
        except Exception as e:
            logger.warning(f"Error in sentiment analysis: {e}")
            return {'compound': 0.0, 'positive': 0.0, 'negative': 0.0, 'neutral': 0.0}
    
    def _analyze_technical_indicators(self, content: str) -> Dict[str, Any]:
        """Analyze technical indicators of phishing"""
        indicators = {
            'has_redirects': 0,
            'has_popups': 0,
            'has_auto_downloads': 0,
            'has_external_scripts': 0,
            'has_suspicious_meta': 0,
            'overall_score': 0.0
        }
        
        content_lower = content.lower()
        
        # Check for redirects
        if any(redirect in content_lower for redirect in ['location.href', 'window.location', 'redirect']):
            indicators['has_redirects'] = 1
        
        # Check for popup indicators
        if any(popup in content_lower for popup in ['popup', 'alert(', 'confirm(', 'prompt(']):
            indicators['has_popups'] = 1
        
        # Check for auto-download indicators
        if any(download in content_lower for download in ['download', 'auto-download', 'click to download']):
            indicators['has_auto_downloads'] = 1
        
        # Check for external scripts
        if re.search(r'<script[^>]*src=["\'][^"\']*["\']', content):
            indicators['has_external_scripts'] = 1
        
        # Check for suspicious meta tags
        if re.search(r'<meta[^>]*(refresh|redirect)', content_lower):
            indicators['has_suspicious_meta'] = 1
        
        # Calculate overall score
        indicators['overall_score'] = sum(indicators.values()) / 5.0
        
        return indicators
    
    def _analyze_forms(self, content: str) -> Dict[str, Any]:
        """Analyze forms in content"""
        forms = {
            'login_forms': 0,
            'payment_forms': 0,
            'contact_forms': 0,
            'suspicious_forms': 0,
            'overall_score': 0.0
        }
        
        content_lower = content.lower()
        
        # Check for login forms
        if any(form in content_lower for form in ['username', 'password', 'login', 'sign in']):
            forms['login_forms'] = 1
        
        # Check for payment forms
        if any(form in content_lower for form in ['credit card', 'payment', 'billing', 'checkout']):
            forms['payment_forms'] = 1
        
        # Check for contact forms
        if any(form in content_lower for form in ['contact', 'message', 'feedback', 'inquiry']):
            forms['contact_forms'] = 1
        
        # Check for suspicious form patterns
        if re.search(r'<form[^>]*action=["\'][^"\']*["\']', content):
            forms['suspicious_forms'] = 1
        
        # Calculate overall score
        forms['overall_score'] = sum(forms.values()) / 4.0
        
        return forms
    
    def _analyze_links(self, content: str) -> Dict[str, Any]:
        """Analyze links in content"""
        links = {
            'total_links': 0,
            'external_links': 0,
            'suspicious_links': 0,
            'shortened_links': 0,
            'overall_score': 0.0
        }
        
        # Find all links
        link_pattern = r'<a[^>]*href=["\']([^"\']*)["\'][^>]*>'
        found_links = re.findall(link_pattern, content)
        
        links['total_links'] = len(found_links)
        
        for link in found_links:
            # Check for external links
            if link.startswith('http') and not link.startswith('https'):
                links['external_links'] += 1
            
            # Check for suspicious patterns
            if any(suspicious in link.lower() for suspicious in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
                links['shortened_links'] += 1
            
            # Check for suspicious domains
            if any(suspicious in link.lower() for suspicious in ['secure-', 'verify-', 'update-']):
                links['suspicious_links'] += 1
        
        # Calculate overall score
        if links['total_links'] > 0:
            links['overall_score'] = (
                links['external_links'] * 0.3 +
                links['suspicious_links'] * 0.5 +
                links['shortened_links'] * 0.2
            ) / links['total_links']
        
        return links
    
    def _extract_named_entities(self, content: str) -> Dict[str, Any]:
        """Extract named entities using spaCy"""
        if not self.nlp:
            return {'entities': [], 'count': 0, 'suspicious_entities': 0}
        
        try:
            doc = self.nlp(content)
            entities = []
            suspicious_entities = 0
            
            for ent in doc.ents:
                entities.append({
                    'text': ent.text,
                    'label': ent.label_,
                    'start': ent.start_char,
                    'end': ent.end_char
                })
                
                # Check for suspicious entity types
                if ent.label_ in ['PERSON', 'ORG', 'GPE'] and len(ent.text) > 3:
                    suspicious_entities += 1
            
            return {
                'entities': entities,
                'count': len(entities),
                'suspicious_entities': suspicious_entities
            }
            
        except Exception as e:
            logger.warning(f"Error in named entity extraction: {e}")
            return {'entities': [], 'count': 0, 'suspicious_entities': 0}
    
    def _analyze_pos_tags(self, content: str) -> Dict[str, Any]:
        """Analyze part-of-speech tags"""
        if not self.nlp:
            return {'tags': {}, 'suspicious_patterns': 0}
        
        try:
            doc = self.nlp(content)
            pos_tags = {}
            
            for token in doc:
                tag = token.pos_
                pos_tags[tag] = pos_tags.get(tag, 0) + 1
            
            # Check for suspicious POS patterns
            suspicious_patterns = 0
            
            # High frequency of imperative verbs
            if pos_tags.get('VERB', 0) > len(doc) * 0.3:
                suspicious_patterns += 1
            
            # High frequency of pronouns
            if pos_tags.get('PRON', 0) > len(doc) * 0.2:
                suspicious_patterns += 1
            
            return {
                'tags': pos_tags,
                'suspicious_patterns': suspicious_patterns
            }
            
        except Exception as e:
            logger.warning(f"Error in POS analysis: {e}")
            return {'tags': {}, 'suspicious_patterns': 0}
    
    def _calculate_readability(self, content: str) -> Dict[str, Any]:
        """Calculate readability scores"""
        readability = {
            'flesch_score': 0.0,
            'flesch_kincaid': 0.0,
            'overall_score': 0.0
        }
        
        if not content:
            return readability
        
        try:
            sentences = re.split(r'[.!?]+', content)
            words = content.split()
            
            if not sentences or not words:
                return readability
            
            # Calculate Flesch Reading Ease Score
            avg_sentence_length = len(words) / len(sentences)
            avg_syllables_per_word = sum(self._count_syllables(word) for word in words) / len(words)
            
            flesch_score = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)
            readability['flesch_score'] = max(0, min(100, flesch_score))
            
            # Calculate Flesch-Kincaid Grade Level
            fk_grade = (0.39 * avg_sentence_length) + (11.8 * avg_syllables_per_word) - 15.59
            readability['flesch_kincaid'] = max(0, fk_grade)
            
            # Overall readability score (0-1, higher is more readable)
            readability['overall_score'] = min(flesch_score / 100.0, 1.0)
            
        except Exception as e:
            logger.warning(f"Error calculating readability: {e}")
        
        return readability
    
    def _count_syllables(self, word: str) -> int:
        """Count syllables in a word"""
        word = word.lower()
        vowels = 'aeiouy'
        syllable_count = 0
        prev_was_vowel = False
        
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not prev_was_vowel:
                syllable_count += 1
            prev_was_vowel = is_vowel
        
        # Handle silent 'e'
        if word.endswith('e') and syllable_count > 1:
            syllable_count -= 1
        
        return max(1, syllable_count)
    
    def _analyze_domain_consistency(self, content: str, domain: str) -> Dict[str, Any]:
        """Analyze consistency between content and domain"""
        consistency = {
            'domain_mentioned': 0,
            'brand_consistency': 0.0,
            'overall_score': 0.0
        }
        
        if not domain:
            return consistency
        
        content_lower = content.lower()
        domain_lower = domain.lower()
        
        # Check if domain is mentioned in content
        if domain_lower in content_lower:
            consistency['domain_mentioned'] = 1
        
        # Check for brand consistency
        domain_parts = domain_lower.split('.')
        if len(domain_parts) > 1:
            main_domain = domain_parts[0]
            if main_domain in content_lower:
                consistency['brand_consistency'] = 0.8
        
        consistency['overall_score'] = (
            consistency['domain_mentioned'] * 0.5 +
            consistency['brand_consistency'] * 0.5
        )
        
        return consistency
    
    def _detect_brand_impersonation(self, content: str, domain: str) -> Dict[str, Any]:
        """Detect potential brand impersonation"""
        impersonation = {
            'suspicious_brands': [],
            'logo_mentions': 0,
            'official_language': 0,
            'overall_score': 0.0
        }
        
        content_lower = content.lower()
        
        # Common brands that are often impersonated
        common_brands = [
            'google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter',
            'paypal', 'ebay', 'netflix', 'spotify', 'instagram', 'linkedin'
        ]
        
        for brand in common_brands:
            if brand in content_lower and brand not in domain.lower():
                impersonation['suspicious_brands'].append(brand)
        
        # Check for logo mentions
        if any(logo in content_lower for logo in ['logo', 'brand', 'trademark']):
            impersonation['logo_mentions'] = 1
        
        # Check for official language
        official_terms = ['official', 'authorized', 'certified', 'verified']
        if any(term in content_lower for term in official_terms):
            impersonation['official_language'] = 1
        
        # Calculate overall score
        impersonation['overall_score'] = min(
            len(impersonation['suspicious_brands']) * 0.3 +
            impersonation['logo_mentions'] * 0.3 +
            impersonation['official_language'] * 0.4,
            1.0
        )
        
        return impersonation
    
    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall risk score from analysis"""
        risk_factors = [
            analysis['phishing_patterns']['overall_score'],
            analysis['suspicious_keywords']['overall_risk'],
            analysis['grammatical_errors']['overall_score'],
            1.0 - analysis['language_quality']['overall_score'],  # Lower quality = higher risk
            analysis['technical_indicators']['overall_score'],
            analysis['forms']['overall_score'],
            analysis['links']['overall_score'],
            analysis['brand_impersonation']['overall_score']
        ]
        
        # Weighted average
        weights = [0.2, 0.2, 0.15, 0.1, 0.15, 0.1, 0.05, 0.05]
        
        risk_score = sum(weight * factor for weight, factor in zip(weights, risk_factors))
        return min(risk_score, 1.0)
    
    def _calculate_confidence(self, analysis: Dict[str, Any]) -> float:
        """Calculate confidence in the analysis"""
        confidence_factors = [
            min(analysis['text_length'] / 1000.0, 1.0),  # More content = higher confidence
            min(analysis['word_count'] / 100.0, 1.0),    # More words = higher confidence
            analysis['language_quality']['overall_score'],  # Better language = higher confidence
        ]
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def _get_empty_analysis(self) -> Dict[str, Any]:
        """Return empty analysis structure"""
        return {
            'text_length': 0,
            'word_count': 0,
            'sentence_count': 0,
            'paragraph_count': 0,
            'phishing_patterns': {'overall_score': 0.0},
            'suspicious_keywords': {'overall_risk': 0.0},
            'grammatical_errors': {'overall_score': 0.0},
            'language_quality': {'overall_score': 0.0},
            'sentiment': {'compound': 0.0},
            'technical_indicators': {'overall_score': 0.0},
            'forms': {'overall_score': 0.0},
            'links': {'overall_score': 0.0},
            'named_entities': {'count': 0},
            'pos_analysis': {'suspicious_patterns': 0},
            'readability': {'overall_score': 0.0},
            'domain_consistency': {'overall_score': 0.0},
            'brand_impersonation': {'overall_score': 0.0},
            'risk_score': 0.0,
            'confidence': 0.0
        }
