"""
Input Domain Classifier - Binary Classification
Determines if input domain is MALICIOUS or LEGITIMATE CSE
"""

import re
from typing import Tuple, Dict
from datetime import datetime, timedelta
import whois
import dns.resolver
from urllib.parse import urlparse

class InputDomainClassifier:
    """
    Binary classifier for input domain screening
    Separates malicious domains from legitimate CSE domains
    """
    
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click']
        self.phishing_keywords = [
            'verify', 'secure', 'login', 'account', 'update', 'confirm',
            'validate', 'suspended', 'locked', 'urgent', 'expire'
        ]
        
    def classify(self, domain: str) -> Tuple[str, float, str]:
        """
        Classify domain as MALICIOUS or CSE
        
        Returns:
            (classification, confidence, reason)
            classification: 'MALICIOUS' or 'CSE'
            confidence: 0.0 to 1.0
            reason: Explanation
        """
        domain = domain.strip().lower()
        
        # Check 1: Suspicious TLD
        tld = domain.split('.')[-1]
        if tld in self.suspicious_tlds:
            return ('MALICIOUS', 0.85, f'Suspicious TLD: .{tld}')
        
        # Check 2: IP address format
        if self._is_ip_format(domain):
            return ('MALICIOUS', 0.95, 'IP address format')
        
        # Check 3: Excessive hyphens
        if domain.count('-') > 2:
            return ('MALICIOUS', 0.75, 'Excessive hyphens (suspicious pattern)')
        
        # Check 4: Excessive numbers
        digit_count = sum(c.isdigit() for c in domain)
        if digit_count > 5:
            return ('MALICIOUS', 0.70, 'Excessive numbers in domain')
        
        # Check 5: Phishing keywords in domain
        for keyword in self.phishing_keywords:
            if keyword in domain:
                return ('MALICIOUS', 0.80, f'Phishing keyword detected: {keyword}')
        
        # Check 6: Domain length anomaly
        if len(domain) > 50:
            return ('MALICIOUS', 0.65, 'Unusually long domain')
        
        # Check 7: Multiple subdomains
        parts = domain.split('.')
        if len(parts) > 4:
            return ('MALICIOUS', 0.70, 'Excessive subdomain depth')
        
        # Check 8: Domain age (SKIP for performance - too slow)
        # Commenting out to avoid WHOIS timeout during bulk processing
        # try:
        #     age_score, age_reason = self._check_domain_age(domain)
        #     if age_score < 0:  # Newly registered
        #         return ('MALICIOUS', 0.75, age_reason)
        # except:
        #     pass
        
        # If no suspicious indicators, classify as CSE
        return ('CSE', 0.80, 'Appears legitimate - no suspicious indicators')
    
    def _is_ip_format(self, domain: str) -> bool:
        """Check if domain is in IP address format"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _check_domain_age(self, domain: str) -> Tuple[float, str]:
        """
        Check domain age via WHOIS
        Returns negative score if newly registered
        """
        try:
            w = whois.whois(domain)
            if hasattr(w, 'creation_date') and w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age = datetime.now() - creation_date
                
                if age.days < 30:
                    return (-1, f'Newly registered ({age.days} days old)')
                elif age.days < 90:
                    return (0, f'Recent registration ({age.days} days old)')
                else:
                    return (1, f'Established domain ({age.days} days old)')
        except:
            pass
        
        return (0, 'Domain age unknown')
    
    def extract_features(self, domain: str) -> Dict:
        """
        Extract features for ML classification
        """
        features = {
            'domain_length': len(domain),
            'subdomain_depth': len(domain.split('.')) - 2,
            'has_hyphen': 1 if '-' in domain else 0,
            'hyphen_count': domain.count('-'),
            'digit_count': sum(c.isdigit() for c in domain),
            'special_char_count': sum(not c.isalnum() and c != '.' for c in domain),
            'tld_suspicious': 1 if domain.split('.')[-1] in self.suspicious_tlds else 0,
            'has_phishing_keyword': any(kw in domain for kw in self.phishing_keywords),
            'is_ip_format': 1 if self._is_ip_format(domain) else 0,
        }
        
        return features
    
    def batch_classify(self, domains: list) -> Dict:
        """
        Classify multiple domains
        
        Returns:
            {
                'malicious': [(domain, confidence, reason), ...],
                'cse': [(domain, confidence, reason), ...]
            }
        """
        results = {
            'malicious': [],
            'cse': []
        }
        
        for domain in domains:
            classification, confidence, reason = self.classify(domain)
            
            if classification == 'MALICIOUS':
                results['malicious'].append((domain, confidence, reason))
            else:
                results['cse'].append((domain, confidence, reason))
        
        return results


# Quick test function
if __name__ == "__main__":
    classifier = InputDomainClassifier()
    
    test_domains = [
        'sbi.co.in',  # Legitimate
        'secure-sbi-login.tk',  # Malicious
        'verify-account-icici.xyz',  # Malicious
        'icicibank.com',  # Legitimate
        '192.168.1.100',  # Malicious (IP)
        'bank-login-urgent.com',  # Malicious
    ]
    
    print("Domain Classification Test:\n")
    for domain in test_domains:
        classification, confidence, reason = classifier.classify(domain)
        print(f"{domain}")
        print(f"  → {classification} ({confidence*100:.0f}% confidence)")
        print(f"  → Reason: {reason}\n")
