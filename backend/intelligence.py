import dns.resolver
import whois
import requests
import socket
import ssl
from datetime import datetime
from typing import Optional, Dict, Any
import json
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
from backend.config import settings


class IntelligenceGatherer:
    """Gather intelligence about domains without API keys"""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
    def gather_all(self, domain: str) -> Dict[str, Any]:
        """Gather all available intelligence for a domain"""
        result = {
            'domain': domain,
            'whois': self.get_whois_info(domain),
            'dns': self.get_dns_records(domain),
            'ssl': self.get_ssl_info(domain),
            'ip_info': self.get_ip_info(domain),
            'blacklists': self.check_blacklists(domain),
            'cert_transparency': self.check_cert_transparency(domain)
        }
        return result
    
    def get_ps02_formatted_data(self, domain: str) -> Dict[str, Any]:
        """
        Gather intelligence in PS-02 submission format
        Returns data formatted for AI Grand Challenge submission
        """
        intel = self.gather_all(domain)
        
        # Extract WHOIS data
        whois_data = intel.get('whois', {})
        dns_data = intel.get('dns', {})
        ip_data = intel.get('ip_info', {})
        
        # Format name servers
        name_servers_list = whois_data.get('name_servers', [])
        if isinstance(name_servers_list, list):
            name_servers_text = ', '.join(name_servers_list) if name_servers_list else 'N/A'
        else:
            name_servers_text = str(name_servers_list) if name_servers_list else 'N/A'
        
        # Format DNS records
        dns_records_formatted = {
            'A': dns_data.get('a_records', []),
            'AAAA': dns_data.get('aaaa_records', []),
            'MX': dns_data.get('mx_records', []),
            'NS': dns_data.get('ns_records', []),
            'TXT': dns_data.get('txt_records', [])
        }
        dns_records_text = json.dumps(dns_records_formatted)
        
        return {
            # WHOIS Information
            'domain_registration_date': whois_data.get('creation_date'),
            'registrar_name': whois_data.get('registrar', 'N/A'),
            'registrant_name': whois_data.get('name', 'N/A'),
            'registrant_organization': whois_data.get('org', 'N/A'),
            'registrant_country': whois_data.get('country', 'N/A'),
            
            # DNS Information
            'name_servers': name_servers_text,
            'dns_records': dns_records_formatted,
            'dns_records_text': dns_records_text,
            
            # Hosting Information
            'hosting_ip': dns_data.get('a_records', ['N/A'])[0] if dns_data.get('a_records') else 'N/A',
            'hosting_isp': ip_data.get('isp', 'N/A'),
            'hosting_country': ip_data.get('country', 'N/A'),
            
            # Additional data
            'ip_info': ip_data,
            'ssl_info': intel.get('ssl', {}),
            'blacklist_info': intel.get('blacklists', {})
        }
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'domain_name': w.domain_name if hasattr(w, 'domain_name') else None,
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else [],
                'org': w.org if hasattr(w, 'org') else None,
                'country': w.country if hasattr(w, 'country') else None,
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records"""
        records = {}
        
        try:
            # A records
            try:
                a_records = self.dns_resolver.resolve(domain, 'A')
                records['a_records'] = [str(r) for r in a_records]
            except:
                records['a_records'] = []
            
            # AAAA records (IPv6)
            try:
                aaaa_records = self.dns_resolver.resolve(domain, 'AAAA')
                records['aaaa_records'] = [str(r) for r in aaaa_records]
            except:
                records['aaaa_records'] = []
            
            # MX records
            try:
                mx_records = self.dns_resolver.resolve(domain, 'MX')
                records['mx_records'] = [{'priority': r.preference, 'host': str(r.exchange)} 
                                        for r in mx_records]
            except:
                records['mx_records'] = []
            
            # NS records
            try:
                ns_records = self.dns_resolver.resolve(domain, 'NS')
                records['ns_records'] = [str(r) for r in ns_records]
            except:
                records['ns_records'] = []
            
            # TXT records
            try:
                txt_records = self.dns_resolver.resolve(domain, 'TXT')
                records['txt_records'] = [str(r) for r in txt_records]
            except:
                records['txt_records'] = []
                
        except Exception as e:
            records['error'] = str(e)
        
        return records
    
    def get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'sans': cert.get('subjectAltName', []),
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def get_ip_info(self, domain: str) -> Dict[str, Any]:
        """Get IP and geolocation info using free APIs"""
        try:
            # Get IP address
            ip_address = socket.gethostbyname(domain)
            
            # Use ip-api.com (free, no API key, 45 requests/minute)
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip_address,
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'asn': data.get('as'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                }
            else:
                return {'ip': ip_address, 'error': 'Geolocation lookup failed'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def check_blacklists(self, domain: str) -> Dict[str, Any]:
        """Check domain against public blacklists (no API key needed)"""
        results = {
            'phishtank': False,
            'openphish': False,
            'urlhaus': False,
        }
        
        try:
            # Check PhishTank (scrape public submissions)
            # Note: In production, download and cache the database
            results['phishtank'] = self._check_phishtank(domain)
            
            # Check OpenPhish feed
            results['openphish'] = self._check_openphish(domain)
            
            # Check URLhaus
            results['urlhaus'] = self._check_urlhaus(domain)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_phishtank(self, domain: str) -> bool:
        """Check PhishTank (would need to download database periodically)"""
        # In production: download https://data.phishtank.com/data/online-valid.json
        # and check locally. For now, return False
        return False
    
    def _check_openphish(self, domain: str) -> bool:
        """Check OpenPhish feed"""
        try:
            # OpenPhish provides a free feed
            response = requests.get(
                'https://openphish.com/feed.txt',
                timeout=10
            )
            if response.status_code == 200:
                return domain in response.text
        except:
            pass
        return False
    
    def _check_urlhaus(self, domain: str) -> bool:
        """Check URLhaus (abuse.ch)"""
        try:
            # URLhaus API (free, no key needed)
            response = requests.post(
                'https://urlhaus-api.abuse.ch/v1/host/',
                data={'host': domain},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('query_status') == 'ok'
        except:
            pass
        return False
    
    def analyze_domain_for_phishing_characteristics(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a domain for phishing characteristics WITHOUT needing a comparison domain
        Uses ML/AI detection to check if the domain itself exhibits phishing behavior
        """
        from backend.risk_scorer import RiskScorer
        
        result = {
            'is_phishing': False,
            'risk_score': 0.0,
            'risk_level': 'LOW',
            'indicators': [],
            'reason': None
        }
        
        try:
            print(f"[ML DETECTION] Analyzing domain for phishing characteristics: {domain}")
            
            # Gather comprehensive intelligence
            intel = self.gather_all(domain)
            
            # Extract key metrics
            whois_info = intel.get('whois', {})
            dns_info = intel.get('dns', {})
            ssl_info = intel.get('ssl', {})
            blacklist_results = intel.get('blacklists', {})
            
            # Check if domain is accessible
            is_accessible = self.is_domain_registered(domain)
            
            if not is_accessible:
                result['indicators'].append('Domain is not registered or inaccessible')
                return result
            
            # Get domain age
            domain_age = self.get_domain_age_days(whois_info)
            
            # Analyze content (check for phishing indicators)
            content_analysis = self._analyze_domain_content(domain)
            has_login_form = content_analysis.get('has_login_form', False)
            has_payment_form = content_analysis.get('has_payment_form', False)
            suspicious_keywords = content_analysis.get('suspicious_keywords', [])
            
            # Calculate risk score using ML model
            scorer = RiskScorer()
            risk_result = scorer.calculate_risk_score(
                domain_age_days=domain_age,
                visual_similarity=0.0,  # Not comparing to another domain
                content_similarity=content_analysis.get('suspicious_content_score', 0.0),
                has_login_form=has_login_form,
                has_payment_form=has_payment_form,
                ssl_info=ssl_info,
                blacklist_results=blacklist_results,
                whois_info=whois_info
            )
            
            result['risk_score'] = risk_result['total_score']
            result['risk_level'] = risk_result['risk_level']
            
            # Build indicators list
            if domain_age is not None and domain_age < 30:
                result['indicators'].append(f'Very new domain ({domain_age} days old)')
            
            if has_login_form:
                result['indicators'].append('Contains login/credential form')
            
            if has_payment_form:
                result['indicators'].append('Contains payment/financial form')
            
            if suspicious_keywords and isinstance(suspicious_keywords, list):
                result['indicators'].append(f'Contains suspicious keywords: {", ".join(suspicious_keywords[:3])}')
            
            if blacklist_results.get('phishtank') or blacklist_results.get('openphish') or blacklist_results.get('urlhaus'):
                result['indicators'].append('Listed in phishing/malware databases')
            
            if 'error' in ssl_info or not ssl_info:
                result['indicators'].append('No valid SSL certificate')
            
            # Determine if it's phishing based on risk score
            # Using medium threshold (typically 40-50)
            if result['risk_score'] >= 50:  # Medium to High risk
                result['is_phishing'] = True
                result['reason'] = f"ML model detected phishing characteristics (Risk Score: {result['risk_score']}/100, Level: {result['risk_level']})"
            
            print(f"[ML DETECTION] Risk Score: {result['risk_score']}/100, Level: {result['risk_level']}, Phishing: {result['is_phishing']}")
            
        except Exception as e:
            print(f"[ML DETECTION] Error analyzing domain: {e}")
            result['reason'] = f"Error during analysis: {str(e)}"
        
        return result
    
    def _analyze_domain_content(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain content for phishing indicators
        """
        result = {
            'has_login_form': False,
            'has_payment_form': False,
            'has_binary_hosting': False,
            'has_download_page': False,
            'suspicious_keywords': [],
            'suspicious_content_score': 0.0
        }
        
        try:
            # Try to fetch and analyze the page
            url = f'https://{domain}' if not domain.startswith('http') else domain
            
            import requests
            from bs4 import BeautifulSoup
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for login forms
                login_indicators = ['password', 'passwd', 'pwd', 'login', 'signin', 'user', 'email']
                password_inputs = soup.find_all('input', {'type': 'password'})
                if password_inputs:
                    result['has_login_form'] = True
                
                # Check for payment forms
                payment_indicators = ['credit', 'card', 'cvv', 'payment', 'billing']
                for indicator in payment_indicators:
                    if soup.find('input', {'name': lambda x: x and indicator in x.lower()}):
                        result['has_payment_form'] = True
                        break
                
                # Check for binary hosting indicators
                binary_indicators = [
                    'download', 'exe', 'zip', 'rar', '7z', 'tar', 'gz',
                    'installer', 'setup', 'update', 'patch', 'crack',
                    'keygen', 'serial', 'license', 'activation'
                ]
                
                # Check for download links
                download_links = soup.find_all('a', href=True)
                for link in download_links:
                    href = link.get('href', '').lower()
                    if any(indicator in href for indicator in binary_indicators):
                        result['has_download_page'] = True
                        break
                
                # Check for binary hosting in content
                text_content = soup.get_text()
                if text_content is None:
                    text_content = ""
                text_content = text_content.lower()
                
                if any(indicator in text_content for indicator in binary_indicators):
                    result['has_binary_hosting'] = True
                
                phishing_keywords = [
                    'verify account', 'suspended account', 'confirm identity',
                    'update payment', 'unusual activity', 'verify identity',
                    'limited time', 'act now', 'urgent action', 'account locked'
                ]
                
                for keyword in phishing_keywords:
                    if keyword in text_content:
                        result['suspicious_keywords'].append(keyword)
                
                # Calculate suspicious content score
                score = 0
                if result['has_login_form']:
                    score += 30
                if result['has_payment_form']:
                    score += 40
                if result['has_binary_hosting']:
                    score += 25
                if result['has_download_page']:
                    score += 20
                score += min(len(result['suspicious_keywords']) * 10, 30)
                
                result['suspicious_content_score'] = min(score, 100)
                
        except Exception as e:
            print(f"[CONTENT ANALYSIS] Error analyzing content: {e}")
        
        return result
    
    def is_domain_malicious(self, domain: str, existing_cse_domains: list = None) -> Dict[str, Any]:
        """
        Comprehensive check if a domain is malicious or suspicious
        Uses ML detection + pattern matching + blacklists + checks against existing CSE domains
        
        Args:
            domain: The domain to check
            existing_cse_domains: List of existing legitimate CSE domains to check for typosquatting
        
        Returns dict with 'is_malicious', 'reason', 'typosquatting_target' and 'checks' fields
        """
        result = {
            'is_malicious': False,
            'reason': None,
            'found_in': [],
            'suspicious_indicators': [],
            'checks_performed': [],
            'ml_detection': None,
            'typosquatting_target': None
        }
        
        # Known legitimate brands/companies to protect against typosquatting
        KNOWN_LEGITIMATE_BRANDS = [
            # Indian Banks
            'airtel', 'jio', 'vodafone', 'bsnl', 'idea',
            'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'canara', 'bob',
            # Tech companies
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix',
            'twitter', 'instagram', 'whatsapp', 'linkedin', 'youtube',
            # Payment/Finance
            'paytm', 'phonepe', 'gpay', 'bhim', 'paypal', 'razorpay',
            # Government
            'uidai', 'epfo', 'nsdl', 'irctc', 'nic',
            # Others
            'flipkart', 'myntra', 'swiggy', 'zomato', 'ola', 'uber'
        ]
        
        try:
            # Clean domain
            domain = domain.lower().strip()
            if domain.startswith('http'):
                domain = urlparse(domain).netloc
            
            print(f"[VALIDATION] Checking domain: {domain}")
            
            # STEP 0: ML-Based Phishing Detection (CRITICAL - Run First)
            print(f"[VALIDATION] Running ML phishing detection...")
            result['checks_performed'].append('ml_phishing_detection')
            ml_result = self.analyze_domain_for_phishing_characteristics(domain)
            result['ml_detection'] = ml_result
            
            if ml_result['is_phishing']:
                result['is_malicious'] = True
                indicators_str = "\n".join([f"  • {ind}" for ind in ml_result['indicators']])
                result['reason'] = f"❌ PHISHING DOMAIN DETECTED BY ML MODEL\n\n" \
                                 f"Risk Score: {ml_result['risk_score']}/100 ({ml_result['risk_level']} Risk)\n\n" \
                                 f"Phishing Indicators Detected:\n{indicators_str}\n\n" \
                                 f"⚠️  This domain exhibits characteristics typical of phishing sites and cannot be added as a CSE domain."
                print(f"[VALIDATION] 🚫 REJECTED: ML model detected phishing (score: {ml_result['risk_score']})")
                return result
            elif ml_result['risk_score'] >= 40:  # Medium risk
                print(f"[VALIDATION] ⚠️  Medium risk domain (score: {ml_result['risk_score']}), continuing with additional checks...")
                result['suspicious_indicators'].append(f"Medium risk domain (ML score: {ml_result['risk_score']}/100)")
            
            print(f"[VALIDATION] ✓ ML detection passed (score: {ml_result['risk_score']}/100)")
            
            # 1. Check blacklists (most critical)
            print(f"[VALIDATION] Checking blacklists...")
            blacklists = self.check_blacklists(domain)
            result['checks_performed'].append('blacklists')
            
            if blacklists.get('phishtank'):
                result['is_malicious'] = True
                result['found_in'].append('PhishTank')
            
            if blacklists.get('openphish'):
                result['is_malicious'] = True
                result['found_in'].append('OpenPhish')
            
            if blacklists.get('urlhaus'):
                result['is_malicious'] = True
                result['found_in'].append('URLhaus')
            
            if result['is_malicious']:
                found_in = result.get('found_in', [])
                if isinstance(found_in, list):
                    result['reason'] = f"❌ Domain found in known malicious databases: {', '.join(found_in)}"
                else:
                    result['reason'] = f"❌ Domain found in known malicious databases: {str(found_in)}"
                return result
            
            # 2. Check suspicious TLDs
            print(f"[VALIDATION] Checking TLD...")
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', 
                             '.work', '.click', '.link', '.download', '.stream']
            result['checks_performed'].append('suspicious_tld')
            
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    result['suspicious_indicators'].append(f'Suspicious TLD: {tld}')
            
            # 3. Check for suspicious patterns in domain name
            print(f"[VALIDATION] Checking suspicious patterns...")
            suspicious_patterns = [
                'paypal', 'banking', 'secure', 'account', 'verify', 
                'login', 'signin', 'update', 'suspended', 'limited',
                'authentication', 'verify', 'confirmer', 'wallet',
                'password', 'credential', 'alert', 'notification'
            ]
            result['checks_performed'].append('suspicious_patterns')
            
            domain_lower = domain.lower()
            for pattern in suspicious_patterns:
                if pattern in domain_lower and pattern != domain_lower:
                    result['suspicious_indicators'].append(f'Contains suspicious keyword: {pattern}')
            
            # 4. Check for excessive hyphens (common in phishing)
            if domain.count('-') > 3:
                result['suspicious_indicators'].append(f'Excessive hyphens ({domain.count("-")})')
            
            # 5. Check for numbers mixed with letters (typosquatting)
            import re
            if re.search(r'\d+[a-z]+\d+', domain) or re.search(r'[a-z]+\d+[a-z]+', domain):
                result['suspicious_indicators'].append('Mixed numbers and letters pattern')
            
            # 6. Check domain age (if very new, it's suspicious)
            print(f"[VALIDATION] Checking domain age...")
            result['checks_performed'].append('domain_age')
            try:
                whois_info = self.get_whois_info(domain)
                if whois_info and 'error' not in whois_info:
                    age = self.get_domain_age_days(whois_info)
                    if age is not None and age < 30:  # Less than 30 days old
                        result['suspicious_indicators'].append(f'Very new domain (only {age} days old)')
            except Exception as e:
                print(f"[VALIDATION] Could not check domain age: {e}")
            
            # 7. Check if domain is actually registered (unregistered = suspicious)
            print(f"[VALIDATION] Checking if domain is registered...")
            result['checks_performed'].append('registration_check')
            if not self.is_domain_registered(domain):
                result['suspicious_indicators'].append('Domain is not registered or does not resolve')
            
            # 8. Check for homograph/IDN attacks
            if any(ord(char) > 127 for char in domain):
                result['suspicious_indicators'].append('Contains non-ASCII characters (possible homograph attack)')
            
            # 8.5. Check for typosquatting (similarity to known brands) - CRITICAL CHECK
            print(f"[VALIDATION] Checking for typosquatting...")
            result['checks_performed'].append('typosquatting_check')
            
            domain_base = domain.split('.')[0]  # Get just the domain name without TLD
            typosquatting_detected = False
            typosquatting_brand = None
            
            for brand in KNOWN_LEGITIMATE_BRANDS:
                # Check if domain is very similar to a known brand but not exact match
                if domain_base != brand:  # Not exact match
                    similarity_score = self._calculate_similarity(domain_base, brand)
                    
                    # If very similar (80%+ similarity), it's likely typosquatting
                    if similarity_score >= 0.80:
                        typosquatting_detected = True
                        typosquatting_brand = brand
                        print(f"[VALIDATION] ⚠️  Typosquatting detected: {domain_base} ≈ {brand} ({int(similarity_score*100)}% similar)")
                        break  # Exit early if found
                    
                    # Also check for common typosquatting techniques
                    if self._is_typosquatting(domain_base, brand):
                        typosquatting_detected = True
                        typosquatting_brand = brand
                        print(f"[VALIDATION] ⚠️  Typosquatting pattern: {domain_base} mimics {brand}")
                        break  # Exit early if found
            
            # If typosquatting detected, REJECT IMMEDIATELY (critical security issue)
            if typosquatting_detected:
                result['is_malicious'] = True
                result['typosquatting_target'] = typosquatting_brand
                result['reason'] = f"❌ TYPOSQUATTING DETECTED\n\n" \
                                 f'The domain "{domain_base}" appears to be a typosquatting attempt mimicking the legitimate brand "{typosquatting_brand}".\n\n' \
                                 f"Typosquatting is a technique where attackers register domains with intentional typos of popular brands to deceive users.\n\n" \
                                 f"Examples: 'airtell.com' mimicking 'airtel.com', 'gooogle.com' mimicking 'google.com'\n\n" \
                                 f"⚠️  This domain cannot be added as it appears to be attempting brand impersonation."
                print(f"[VALIDATION] 🚫 REJECTED: Typosquatting of {typosquatting_brand}")
                return result
            
            # 8.6. Check for typosquatting against existing CSE domains - CRITICAL CHECK
            if existing_cse_domains:
                print(f"[VALIDATION] Checking for typosquatting against {len(existing_cse_domains)} existing CSE domains...")
                result['checks_performed'].append('cse_typosquatting_check')
                
                for cse_domain in existing_cse_domains:
                    cse_base = cse_domain.split('.')[0].lower()
                    
                    # Skip if it's the same domain
                    if domain_base == cse_base:
                        continue
                    
                    # Calculate similarity
                    similarity_score = self._calculate_similarity(domain_base, cse_base)
                    
                    # If very similar (80%+ similarity), it's likely typosquatting
                    if similarity_score >= 0.80:
                        result['is_malicious'] = True
                        result['typosquatting_target'] = cse_domain
                        result['reason'] = f"❌ TYPOSQUATTING DETECTED\n\n" \
                                         f'The domain "{domain}" is {int(similarity_score*100)}% similar to the existing CSE domain "{cse_domain}".\n\n' \
                                         f"This appears to be a typosquatting variant attempting to mimic a legitimate domain that is already being monitored.\n\n" \
                                         f"⚠️  This domain cannot be added as it appears to be impersonating: {cse_domain}"
                        print(f"[VALIDATION] 🚫 REJECTED: Typosquatting of existing CSE domain {cse_domain} ({int(similarity_score*100)}% similar)")
                        return result
                    
                    # Also check for common typosquatting techniques
                    if self._is_typosquatting(domain_base, cse_base):
                        result['is_malicious'] = True
                        result['typosquatting_target'] = cse_domain
                        result['reason'] = f"❌ TYPOSQUATTING DETECTED\n\n" \
                                         f'The domain "{domain}" appears to be a typosquatting variant of the existing CSE domain "{cse_domain}".\n\n' \
                                         f"Common typosquatting techniques detected (e.g., doubled letters, missing letters, transpositions).\n\n" \
                                         f"Example: 'ircctc.co.in' mimicking 'irctc.co.in'\n\n" \
                                         f"⚠️  This domain cannot be added as it appears to be impersonating: {cse_domain}"
                        print(f"[VALIDATION] 🚫 REJECTED: Typosquatting pattern detected - mimics {cse_domain}")
                        return result
            
            # 9. Check SSL certificate (if available)
            print(f"[VALIDATION] Checking SSL certificate...")
            result['checks_performed'].append('ssl_check')
            try:
                ssl_info = self.get_ssl_info(domain)
                if ssl_info and 'error' not in ssl_info:
                    # Check if SSL issuer is suspicious (not Let's Encrypt, not major CA)
                    issuer = str(ssl_info.get('issuer', '')).lower()
                    trusted_cas = ['letsencrypt', 'digicert', 'comodo', 'godaddy', 
                                  'sectigo', 'globalsign', 'entrust', 'thawte']
                    if not any(ca in issuer for ca in trusted_cas):
                        result['suspicious_indicators'].append('Unknown or suspicious SSL certificate issuer')
                else:
                    result['suspicious_indicators'].append('No valid SSL certificate found')
            except Exception as e:
                print(f"[VALIDATION] Could not check SSL: {e}")
            
            # Final decision: If 3+ suspicious indicators, reject it
            if len(result['suspicious_indicators']) >= 3:
                result['is_malicious'] = True
                indicators = result.get('suspicious_indicators', [])
                if isinstance(indicators, list):
                    result['reason'] = f"❌ Domain has multiple suspicious indicators:\n" + "\n".join([f"  • {ind}" for ind in indicators])
                else:
                    result['reason'] = f"❌ Domain has multiple suspicious indicators: {str(indicators)}"
            elif len(result['suspicious_indicators']) > 0:
                print(f"[VALIDATION] ⚠️  Found {len(result['suspicious_indicators'])} suspicious indicators but allowing domain")
                result['reason'] = f"✓ Domain passed validation (found {len(result['suspicious_indicators'])} minor indicators)"
            else:
                result['reason'] = "✓ Domain passed all validation checks"
                
            print(f"[VALIDATION] Result: {'REJECTED' if result['is_malicious'] else 'ACCEPTED'}")
            checks = result.get('checks_performed', [])
            if isinstance(checks, list):
                print(f"[VALIDATION] Checks performed: {', '.join(checks)}")
            else:
                print(f"[VALIDATION] Checks performed: {str(checks)}")
            if result.get('suspicious_indicators'):
                print(f"[VALIDATION] Suspicious indicators: {len(result['suspicious_indicators'])}")
        
        except Exception as e:
            print(f"[VALIDATION] Error checking domain: {e}")
            result['reason'] = f"⚠️  Could not fully validate domain: {str(e)}"
        
        return result
    
    def check_cert_transparency(self, domain: str) -> Dict[str, Any]:
        """Check Certificate Transparency logs via crt.sh"""
        try:
            # crt.sh provides free CT log search
            response = requests.get(
                f'https://crt.sh/?q=%.{domain}&output=json',
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant info
                certs = []
                for cert in data[:10]:  # Limit to 10 most recent
                    certs.append({
                        'logged_at': cert.get('entry_timestamp'),
                        'not_before': cert.get('not_before'),
                        'common_name': cert.get('common_name'),
                        'issuer': cert.get('issuer_name'),
                    })
                
                return {
                    'found': True,
                    'count': len(data),
                    'recent_certs': certs
                }
            else:
                return {'found': False}
                
        except Exception as e:
            return {'error': str(e)}
    
    def is_domain_registered(self, domain: str) -> bool:
        """Quick check if domain is registered"""
        try:
            # Try to resolve A record
            self.dns_resolver.resolve(domain, 'A')
            return True
        except:
            try:
                # Try AAAA record (IPv6) as fallback
                self.dns_resolver.resolve(domain, 'AAAA')
                return True
            except:
                try:
                    # Try MX record as fallback
                    self.dns_resolver.resolve(domain, 'MX')
                    return True
                except:
                    return False
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate similarity between two strings using Levenshtein distance
        Returns value between 0 (no similarity) and 1 (identical)
        """
        # Simple implementation of Levenshtein distance
        if str1 == str2:
            return 1.0
        
        len1, len2 = len(str1), len(str2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        # Create distance matrix
        distances = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        
        for i in range(len1 + 1):
            distances[i][0] = i
        for j in range(len2 + 1):
            distances[0][j] = j
        
        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if str1[i-1] == str2[j-1] else 1
                distances[i][j] = min(
                    distances[i-1][j] + 1,      # deletion
                    distances[i][j-1] + 1,      # insertion
                    distances[i-1][j-1] + cost  # substitution
                )
        
        # Convert distance to similarity score
        max_len = max(len1, len2)
        similarity = 1 - (distances[len1][len2] / max_len)
        return similarity
    
    def _is_typosquatting(self, domain: str, brand: str) -> bool:
        """
        Check for common typosquatting techniques
        """
        # Technique 1: Character substitution (e.g., "rn" looks like "m", "l" vs "1")
        substitutions = {
            'rn': 'm', 'm': 'rn',
            'l': '1', '1': 'l',
            'o': '0', '0': 'o',
            'i': '1', '1': 'i',
            'vv': 'w', 'w': 'vv'
        }
        
        # Technique 2: Missing character (e.g., "gogle" vs "google")
        if len(domain) == len(brand) - 1:
            for i in range(len(brand)):
                if brand[:i] + brand[i+1:] == domain:
                    return True
        
        # Technique 3: Extra character (e.g., "gooogle" vs "google")
        if len(domain) == len(brand) + 1:
            for i in range(len(domain)):
                if domain[:i] + domain[i+1:] == brand:
                    return True
        
        # Technique 4: Transposition (e.g., "googel" vs "google")
        if len(domain) == len(brand):
            for i in range(len(domain) - 1):
                if (domain[:i] + domain[i+1] + domain[i] + domain[i+2:]) == brand:
                    return True
        
        # Technique 5: Double character (e.g., "airtell" vs "airtel")
        for i in range(len(domain) - 1):
            if domain[i] == domain[i+1]:
                test = domain[:i] + domain[i+1:]
                if test == brand:
                    return True
        
        # Technique 6: Homoglyph substitution (visually similar characters)
        # Already checked with similarity score
        
            return False
    
    def get_domain_age_days(self, whois_info: Dict[str, Any]) -> Optional[int]:
        """Calculate domain age in days from WHOIS info"""
        try:
            if 'creation_date' in whois_info and whois_info['creation_date']:
                creation_date_str = whois_info['creation_date']
                
                # Handle list of dates (some WHOIS returns lists)
                if isinstance(creation_date_str, list):
                    creation_date_str = creation_date_str[0]
                
                # Parse date
                if isinstance(creation_date_str, str):
                    # Try common date formats
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%m-%Y']:
                        try:
                            creation_date = datetime.strptime(creation_date_str.split('.')[0], fmt)
                            age = (datetime.now() - creation_date).days
                            return age
                        except:
                            continue
        except:
            pass
        return None
    
    def scan_twitter_for_domain(self, domain: str) -> Dict[str, Any]:
        """
        Scan Twitter for mentions of the domain
        Returns social media detection data
        """
        if not settings.TWITTER_BEARER_TOKEN:
            print(f"⚠️ Twitter API not configured - skipping social media scan for {domain}")
            return {
                'found': False,
                'platform': 'twitter',
                'error': 'Twitter API not configured - add TWITTER_BEARER_TOKEN to .env'
            }
        
        try:
            headers = {
                'Authorization': f'Bearer {settings.TWITTER_BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            
            # Search for tweets containing the domain
            search_url = "https://api.twitter.com/2/tweets/search/recent"
            params = {
                'query': f'"{domain}" -is:retweet lang:en',
                'max_results': 10,
                'tweet.fields': 'created_at,author_id,public_metrics'
            }
            
            response = requests.get(search_url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                tweets = data.get('data', [])
                
                if tweets:
                    # Get the most recent tweet
                    latest_tweet = tweets[0]
                    created_at = latest_tweet.get('created_at', '')
                    
                    return {
                        'found': True,
                        'platform': 'twitter',
                        'post_count': len(tweets),
                        'latest_post_date': created_at,
                        'latest_post_url': f"https://twitter.com/i/web/status/{latest_tweet.get('id', '')}",
                        'engagement': latest_tweet.get('public_metrics', {}),
                        'tweets': tweets[:5]  # First 5 tweets
                    }
                else:
                    return {
                        'found': False,
                        'platform': 'twitter',
                        'post_count': 0
                    }
            else:
                return {
                    'found': False,
                    'platform': 'twitter',
                    'error': f'API error: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'found': False,
                'platform': 'twitter',
                'error': str(e)
            }


# Helper function
def gather_domain_intelligence(domain: str) -> Dict[str, Any]:
    """Gather all intelligence for a domain"""
    gatherer = IntelligenceGatherer()
    return gatherer.gather_all(domain)

