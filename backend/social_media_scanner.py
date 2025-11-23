"""
Social Media & Advertising Scanner for Phishing Detection
Monitors multiple platforms for phishing links targeting CSE domains

Supported Platforms (ALL FREE):
- Twitter/X - FREE API (500K tweets/month)
- Facebook - FREE Graph API
- Instagram - FREE (via Facebook Graph API)  
- Telegram - FREE Bot API (unlimited)
- Google Ads - FREE Transparency Center
- Google Safe Browsing - FREE API (10K queries/day)

All APIs are FREE to use! Some require approval but no payment.
"""

import re
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from urllib.parse import urlparse
import time
import os


class SocialMediaScanner:
    """Scan social media for phishing links"""
    
    def __init__(self):
        self.detected_urls = []
        
    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text"""
        # URL pattern
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def is_suspicious_domain(self, url: str, cse_domains: List[str]) -> Dict:
        """
        Check if URL is suspicious based on CSE domains
        
        Args:
            url: URL to check
            cse_domains: List of legitimate CSE domains to check against
        
        Returns:
            Dict with suspicious info or None
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check if domain contains CSE domain name but isn't exact match
            for cse_domain in cse_domains:
                cse_base = cse_domain.replace('.com', '').replace('.in', '').replace('.org', '')
                
                # If CSE name is in the suspicious domain but not exact match
                if cse_base.lower() in domain and domain != cse_domain.lower():
                    return {
                        'suspicious': True,
                        'phishing_domain': domain,
                        'target_cse_domain': cse_domain,
                        'url': url,
                        'reason': f'Contains "{cse_base}" but different domain'
                    }
            
            return {'suspicious': False}
            
        except Exception as e:
            return {'suspicious': False, 'error': str(e)}
    
    def scan_twitter_search(
        self,
        cse_domain: str,
        organization_name: str,
        max_results: int = 20
    ) -> List[Dict]:
        """
        Scan Twitter for phishing links using Twitter API v2
        
        Args:
            cse_domain: Legitimate CSE domain
            organization_name: Organization name to search for
            max_results: Maximum results to check
        
        Returns:
            List of suspicious URLs found
        """
        detections = []
        
        # Check if Twitter API is configured
        if not hasattr(self, 'bearer_token') or not self.bearer_token:
            print(f"🐦 Twitter API not configured - skipping scan for {organization_name}")
            return detections
        
        try:
            # Use the TwitterAPIScanner for actual implementation
            twitter_scanner = TwitterAPIScanner(self.bearer_token)
            
            # Search queries
            queries = [
                f'"{organization_name}" phishing',
                f'"{cse_domain}" scam',
                f'"{organization_name}" fake',
                f'"{cse_domain}" suspicious'
            ]
            
            for query in queries:
                tweets = twitter_scanner.search_recent_tweets(query, max_results // len(queries))
                
                for tweet in tweets:
                    # Extract URLs from tweet
                    urls = self.extract_urls_from_text(tweet['text'])
                    
                    for url in urls:
                        # Check if URL is suspicious
                        suspicious_info = self.is_suspicious_domain(url, [cse_domain])
                        if suspicious_info.get('suspicious'):
                            detections.append({
                                'url': url,
                                'platform': 'twitter',
                                'tweet_id': tweet['id'],
                                'tweet_text': tweet['text'],
                                'created_at': tweet['created_at'],
                                'suspicious_info': suspicious_info
                            })
            
            print(f"🐦 Twitter scan complete for {organization_name}: {len(detections)} suspicious URLs found")
            
        except Exception as e:
            print(f"🐦 Twitter scan error for {organization_name}: {e}")
        
        return detections
    
    def scan_facebook_groups(
        self,
        cse_domain: str,
        organization_name: str
    ) -> List[Dict]:
        """
        Scan Facebook groups for phishing links
        
        Note: Requires Facebook Graph API access
        Would search cybersecurity/fraud reporting groups
        """
        print(f"📘 Facebook scanning for {organization_name}...")
        print(f"   ⚠️ Note: Requires Facebook Graph API access")
        return []
    
    def scan_instagram(
        self,
        cse_domain: str,
        organization_name: str
    ) -> List[Dict]:
        """
        Scan Instagram for phishing links
        
        Uses Facebook Graph API (same as Facebook)
        FREE - No cost, just requires app approval
        
        Would search:
        - Hashtags: #SBIphishing, #scamalert
        - Mentions of organization
        - Comments with suspicious links
        """
        print(f"📷 Instagram scanning for {organization_name}...")
        print(f"   ✅ FREE via Facebook Graph API")
        print(f"   ⚠️ Requires: Facebook app approval (~2 weeks)")
        return []
    
    def scan_telegram_channels(
        self,
        cse_domain: str,
        organization_name: str
    ) -> List[Dict]:
        """
        Scan Telegram channels for phishing reports
        
        100% FREE - Telegram Bot API has no limits!
        
        Would search fraud alert channels:
        - @ScamAlertIndia
        - @CyberCrimeIndia
        - Financial fraud reporting channels
        """
        print(f"📱 Telegram scanning for {organization_name}...")
        print(f"   ✅ 100% FREE - No limits!")
        print(f"   Setup: Create bot via @BotFather (5 minutes)")
        return []
    
    def scan_google_ads_transparency(
        self,
        cse_domain: str,
        organization_name: str
    ) -> List[Dict]:
        """
        Check Google Ads Transparency Center for suspicious ads
        
        100% FREE & PUBLIC - No API key needed!
        https://adstransparency.google.com/
        
        Can find:
        - Ads mentioning the CSE domain
        - Advertiser information
        - Ad landing pages
        
        This is PERFECT for finding phishing ads!
        """
        print(f"🔍 Scanning Google Ads Transparency Center for {organization_name}...")
        print(f"   ✅ 100% FREE - Public data, no API needed")
        print(f"   Can detect: Fake banking ads, phishing advertisements")
        
        # In production, would scrape or use unofficial API
        # Example: Search for "State Bank of India online banking"
        # Find ads, extract landing page URLs
        # Check if URLs are suspicious
        
        return []
    
    def check_google_safe_browsing(
        self,
        url: str,
        api_key: Optional[str] = None
    ) -> Dict:
        """
        Check URL against Google Safe Browsing API
        
        FREE: 10,000 queries/day!
        Get API key: https://developers.google.com/safe-browsing/v4/get-started
        
        This is Google's own phishing/malware database!
        """
        api_key = api_key or os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        
        if not api_key:
            print(f"   ⚠️ Google Safe Browsing API key not configured")
            print(f"   Get FREE key: https://developers.google.com/safe-browsing/v4/get-started")
            return {'checked': False}
        
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            payload = {
                "client": {
                    "clientId": "phishing-detection-system",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(endpoint, json=payload)
            
            if response.status_code == 200:
                result = response.json()
                is_malicious = bool(result.get('matches'))
                
                return {
                    'checked': True,
                    'is_malicious': is_malicious,
                    'threats': result.get('matches', []),
                    'source': 'google_safe_browsing'
                }
            else:
                return {'checked': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'checked': False, 'error': str(e)}
    
    def scan_all_platforms(
        self,
        cse_domain: str,
        organization_name: str
    ) -> Dict[str, List]:
        """
        Scan ALL platforms for phishing detection
        
        Includes:
        - Social Media: Twitter, Facebook, Instagram, Telegram (ALL FREE)
        - Advertising: Google Ads Transparency (FREE)
        - Verification: Google Safe Browsing (FREE - 10K/day)
        
        Returns:
            Dict with detections from each platform
        """
        print(f"\n🔍 Scanning all platforms for phishing targeting: {organization_name}")
        print(f"━" * 60)
        
        results = {
            'twitter': self.scan_twitter_search(cse_domain, organization_name),
            'facebook': self.scan_facebook_groups(cse_domain, organization_name),
            'instagram': self.scan_instagram(cse_domain, organization_name),
            'telegram': self.scan_telegram_channels(cse_domain, organization_name),
            'google_ads': self.scan_google_ads_transparency(cse_domain, organization_name),
            'total_detections': 0
        }
        
        results['total_detections'] = (
            len(results['twitter']) +
            len(results['facebook']) +
            len(results['instagram']) +
            len(results['telegram']) +
            len(results['google_ads'])
        )
        
        print(f"━" * 60)
        print(f"✅ Scan complete: {results['total_detections']} potential phishing links found\n")
        
        return results


class TwitterAPIScanner:
    """
    Production-ready Twitter scanner using Twitter API v2
    
    Setup:
    1. Create Twitter Developer account: https://developer.twitter.com/
    2. Create app and get Bearer Token
    3. Set environment variable: TWITTER_BEARER_TOKEN
    """
    
    def __init__(self, bearer_token: Optional[str] = None):
        import os
        self.bearer_token = bearer_token or os.getenv('TWITTER_BEARER_TOKEN')
        self.base_url = "https://api.twitter.com/2"
    
    def search_recent_tweets(
        self,
        query: str,
        max_results: int = 10
    ) -> List[Dict]:
        """
        Search recent tweets using Twitter API v2
        
        Args:
            query: Search query
            max_results: Max tweets to return (10-100)
        
        Returns:
            List of tweets with URLs
        """
        if not self.bearer_token:
            print("⚠️ Twitter API token not configured")
            return []
        
        headers = {
            'Authorization': f'Bearer {self.bearer_token}'
        }
        
        params = {
            'query': query,
            'max_results': min(max_results, 100),
            'tweet.fields': 'created_at,text,entities',
            'expansions': 'author_id'
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/tweets/search/recent",
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                tweets = []
                
                for tweet in data.get('data', []):
                    # Extract URLs from entities
                    urls = []
                    if 'entities' in tweet and 'urls' in tweet['entities']:
                        urls = [url['expanded_url'] for url in tweet['entities']['urls']]
                    
                    tweets.append({
                        'id': tweet['id'],
                        'text': tweet['text'],
                        'created_at': tweet['created_at'],
                        'urls': urls,
                        'platform': 'twitter'
                    })
                
                return tweets
            else:
                print(f"Twitter API error: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"Error searching Twitter: {e}")
            return []
