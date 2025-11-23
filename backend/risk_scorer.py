from typing import Dict, Any, Optional
from datetime import datetime
from backend.config import settings


class RiskScorer:
    """Calculate risk score for potential phishing sites"""
    
    # Weight for each factor (total = 100%)
    WEIGHTS = {
        'domain_age': 0.40,          # 40% - Newer domains are riskier
        'visual_similarity': 0.25,    # 25% - High visual similarity is suspicious
        'content_analysis': 0.15,     # 15% - Login forms, etc.
        'ssl_certificate': 0.10,      # 10% - SSL quality
        'blacklist_check': 0.10,      # 10% - External verification
    }
    
    def __init__(self):
        self.threshold_high = settings.RISK_THRESHOLD_HIGH
        self.threshold_medium = settings.RISK_THRESHOLD_MEDIUM
    
    def calculate_risk_score(
        self,
        domain_age_days: Optional[int],
        visual_similarity: Optional[float],
        content_similarity: Optional[float],
        has_login_form: Optional[bool],
        has_payment_form: Optional[bool],
        ssl_info: Optional[Dict[str, Any]],
        blacklist_results: Optional[Dict[str, Any]],
        whois_info: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score
        Returns score (0-100) and risk level
        """
        
        # Calculate individual component scores
        domain_age_score = self._score_domain_age(domain_age_days)
        visual_similarity_score = self._score_visual_similarity(visual_similarity)
        content_score = self._score_content(
            content_similarity, 
            has_login_form, 
            has_payment_form
        )
        ssl_score = self._score_ssl(ssl_info)
        blacklist_score = self._score_blacklists(blacklist_results)
        
        # Calculate weighted total score
        total_score = (
            domain_age_score * self.WEIGHTS['domain_age'] +
            visual_similarity_score * self.WEIGHTS['visual_similarity'] +
            content_score * self.WEIGHTS['content_analysis'] +
            ssl_score * self.WEIGHTS['ssl_certificate'] +
            blacklist_score * self.WEIGHTS['blacklist_check']
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_score)
        
        return {
            'total_score': round(total_score, 2),
            'risk_level': risk_level,
            'components': {
                'domain_age': {
                    'score': round(domain_age_score, 2),
                    'weight': self.WEIGHTS['domain_age'],
                    'contribution': round(domain_age_score * self.WEIGHTS['domain_age'], 2)
                },
                'visual_similarity': {
                    'score': round(visual_similarity_score, 2),
                    'weight': self.WEIGHTS['visual_similarity'],
                    'contribution': round(visual_similarity_score * self.WEIGHTS['visual_similarity'], 2)
                },
                'content_analysis': {
                    'score': round(content_score, 2),
                    'weight': self.WEIGHTS['content_analysis'],
                    'contribution': round(content_score * self.WEIGHTS['content_analysis'], 2)
                },
                'ssl_certificate': {
                    'score': round(ssl_score, 2),
                    'weight': self.WEIGHTS['ssl_certificate'],
                    'contribution': round(ssl_score * self.WEIGHTS['ssl_certificate'], 2)
                },
                'blacklist': {
                    'score': round(blacklist_score, 2),
                    'weight': self.WEIGHTS['blacklist_check'],
                    'contribution': round(blacklist_score * self.WEIGHTS['blacklist_check'], 2)
                }
            }
        }
    
    def _score_domain_age(self, age_days: Optional[int]) -> float:
        """
        Score domain age (0-100, higher = more risky)
        New domains are more suspicious
        """
        if age_days is None:
            return 50.0  # Unknown age = medium risk
        
        if age_days < 7:
            return 100.0  # Less than a week = very high risk
        elif age_days < 30:
            return 90.0   # Less than a month = high risk
        elif age_days < 90:
            return 70.0   # Less than 3 months = moderate-high risk
        elif age_days < 180:
            return 50.0   # Less than 6 months = medium risk
        elif age_days < 365:
            return 30.0   # Less than a year = low-medium risk
        else:
            return 10.0   # Over a year = low risk
    
    def _score_visual_similarity(self, similarity: Optional[float]) -> float:
        """
        Score visual similarity (0-100, higher = more risky)
        High similarity to legitimate site is suspicious
        """
        if similarity is None:
            return 50.0  # Unknown similarity = medium risk
        
        if similarity >= 80:
            return 95.0   # Very high similarity = very suspicious
        elif similarity >= 60:
            return 75.0   # High similarity = suspicious
        elif similarity >= 40:
            return 50.0   # Medium similarity = somewhat suspicious
        elif similarity >= 20:
            return 25.0   # Low similarity = less suspicious
        else:
            return 10.0   # Very low similarity = not very suspicious
    
    def _score_content(
        self, 
        content_similarity: Optional[float], 
        has_login_form: Optional[bool], 
        has_payment_form: Optional[bool]
    ) -> float:
        """
        Score content analysis (0-100, higher = more risky)
        Login/payment forms on suspicious domain are red flags
        """
        score = content_similarity if content_similarity is not None else 50.0
        
        # Increase score if credential harvesting forms present
        if has_login_form:
            score += 30
        
        if has_payment_form:
            score += 40
        
        # Cap at 100
        return min(score, 100.0)
    
    def _score_ssl(self, ssl_info: Optional[Dict[str, Any]]) -> float:
        """
        Score SSL certificate (0-100, higher = more risky)
        Poor SSL = more risky
        """
        if ssl_info is None or 'error' in ssl_info or not ssl_info:
            return 80.0  # No SSL = high risk
        
        score = 20.0  # Base score for having SSL
        
        # Check issuer
        issuer = ssl_info.get('issuer', {})
        if isinstance(issuer, dict):
            org = issuer.get('organizationName', '').lower()
        else:
            org = str(issuer).lower()
        
        # Free/automated certificates are more commonly used by phishers
        if any(free_ca in org for free_ca in ['let\'s encrypt', 'cloudflare']):
            score += 30
        
        # Check certificate age
        try:
            not_before = ssl_info.get('not_before')
            if not_before:
                # Parse date and check if very new
                # This is simplified - would need proper parsing
                score += 10  # Newly issued cert slightly suspicious
        except:
            pass
        
        return min(score, 100.0)
    
    def _score_blacklists(self, blacklist_results: Optional[Dict[str, Any]]) -> float:
        """
        Score blacklist presence (0-100, higher = more risky)
        Presence in blacklists = very high risk
        """
        if blacklist_results is None or 'error' in blacklist_results:
            return 0.0  # Can't check = no score
        
        score = 0.0
        
        # Each blacklist hit adds to score
        if blacklist_results.get('phishtank'):
            score = 100.0  # PhishTank hit = definite phishing
        
        if blacklist_results.get('openphish'):
            score = 100.0  # OpenPhish hit = definite phishing
        
        if blacklist_results.get('urlhaus'):
            score = 100.0  # URLhaus hit = malicious
        
        return score
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= self.threshold_high:
            return 'HIGH'
        elif score >= self.threshold_medium:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def is_phishing(self, risk_score: float) -> bool:
        """Determine if domain should be classified as phishing"""
        # Consider it phishing if score is above medium threshold
        return risk_score >= self.threshold_medium


# Helper function
def calculate_risk(
    domain_age_days: Optional[int] = None,
    visual_similarity: float = 0.0,
    content_similarity: float = 0.0,
    has_login_form: bool = False,
    has_payment_form: bool = False,
    ssl_info: Dict[str, Any] = None,
    blacklist_results: Dict[str, Any] = None,
    whois_info: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Calculate risk score for a domain"""
    scorer = RiskScorer()
    return scorer.calculate_risk_score(
        domain_age_days,
        visual_similarity,
        content_similarity,
        has_login_form,
        has_payment_form,
        ssl_info or {},
        blacklist_results or {},
        whois_info or {}
    )

