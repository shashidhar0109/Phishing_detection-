"""
Advanced Threat Intelligence Integration
Fetches data from PhishTank, OpenPhish, URLhaus, and enriches with IP/ASN/DNS data
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import time
import hashlib
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelData:
    """Structured threat intelligence data"""
    domain: str
    in_phishtank: bool = False
    in_openphish: bool = False
    in_urlhaus: bool = False
    blacklist_hits: int = 0
    phishtank_verified: bool = False
    phishtank_url: Optional[str] = None
    openphish_url: Optional[str] = None
    urlhaus_url: Optional[str] = None
    enrichment_data: Dict[str, Any] = None
    last_updated: datetime = None

class ThreatIntelligenceGatherer:
    """Gathers threat intelligence from multiple sources"""
    
    def __init__(self):
        self.cache_dir = Path("./logs/threat_intel_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = 3600  # 1 hour cache
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingDetectionSystem/1.0'
        })
        
        # API endpoints (all free and open-source)
        self.phishtank_url = "http://data.phishtank.com/data/online-valid.json"
        self.openphish_url = "https://openphish.com/feed.txt"
        self.urlhaus_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"  # Free CSV download
        
        # Cache files
        self.phishtank_cache = self.cache_dir / "phishtank.json"
        self.openphish_cache = self.cache_dir / "openphish.txt"
        self.urlhaus_cache = self.cache_dir / "urlhaus.json"
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_file.exists():
            return False
        age = time.time() - cache_file.stat().st_mtime
        return age < self.cache_ttl
    
    def _load_from_cache(self, cache_file: Path) -> Optional[Any]:
        """Load data from cache file"""
        try:
            if cache_file.suffix == '.json':
                with open(cache_file, 'r') as f:
                    return json.load(f)
            else:
                with open(cache_file, 'r') as f:
                    return f.read().strip().split('\n')
        except Exception as e:
            logger.warning(f"Failed to load cache {cache_file}: {e}")
            return None
    
    def _save_to_cache(self, data: Any, cache_file: Path):
        """Save data to cache file"""
        try:
            if cache_file.suffix == '.json':
                with open(cache_file, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(cache_file, 'w') as f:
                    if isinstance(data, list):
                        f.write('\n'.join(data))
                    else:
                        f.write(str(data))
        except Exception as e:
            logger.warning(f"Failed to save cache {cache_file}: {e}")
    
    def fetch_phishtank_data(self) -> List[Dict[str, Any]]:
        """Fetch PhishTank data"""
        try:
            if self._is_cache_valid(self.phishtank_cache):
                logger.info("Using cached PhishTank data")
                return self._load_from_cache(self.phishtank_cache) or []
            
            logger.info("Fetching PhishTank data...")
            response = self.session.get(self.phishtank_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            self._save_to_cache(data, self.phishtank_cache)
            logger.info(f"Fetched {len(data)} PhishTank entries")
            return data
            
        except Exception as e:
            logger.error(f"Failed to fetch PhishTank data: {e}")
            return self._load_from_cache(self.phishtank_cache) or []
    
    def fetch_openphish_data(self) -> List[str]:
        """Fetch OpenPhish data"""
        try:
            if self._is_cache_valid(self.openphish_cache):
                logger.info("Using cached OpenPhish data")
                return self._load_from_cache(self.openphish_cache) or []
            
            logger.info("Fetching OpenPhish data...")
            response = self.session.get(self.openphish_url, timeout=30)
            response.raise_for_status()
            
            data = response.text.strip().split('\n')
            self._save_to_cache(data, self.openphish_cache)
            logger.info(f"Fetched {len(data)} OpenPhish URLs")
            return data
            
        except Exception as e:
            logger.error(f"Failed to fetch OpenPhish data: {e}")
            return self._load_from_cache(self.openphish_cache) or []
    
    def fetch_urlhaus_data(self) -> List[Dict[str, Any]]:
        """Fetch URLhaus data from free CSV feed"""
        try:
            if self._is_cache_valid(self.urlhaus_cache):
                logger.info("Using cached URLhaus data")
                return self._load_from_cache(self.urlhaus_cache) or []
            
            logger.info("Fetching URLhaus data...")
            response = self.session.get(self.urlhaus_url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV data
            import csv
            import io
            csv_data = response.text
            csv_reader = csv.DictReader(io.StringIO(csv_data))
            urls = list(csv_reader)
            
            self._save_to_cache(urls, self.urlhaus_cache)
            logger.info(f"Fetched {len(urls)} URLhaus entries")
            return urls
            
        except Exception as e:
            logger.error(f"Failed to fetch URLhaus data: {e}")
            return self._load_from_cache(self.urlhaus_cache) or []
    
    def enrich_domain_data(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with IP, ASN, DNS, and other data"""
        enrichment = {
            'ip_address': None,
            'asn': None,
            'asn_org': None,
            'country': None,
            'isp': None,
            'dns_records': {},
            'whois_data': {},
            'ssl_info': {},
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            # Basic DNS resolution
            import socket
            try:
                ip = socket.gethostbyname(domain)
                enrichment['ip_address'] = ip
            except:
                pass
            
            # IP geolocation (using free service)
            if enrichment['ip_address']:
                try:
                    geo_response = self.session.get(
                        f"http://ip-api.com/json/{enrichment['ip_address']}",
                        timeout=10
                    )
                    if geo_response.status_code == 200:
                        geo_data = geo_response.json()
                        enrichment.update({
                            'country': geo_data.get('country'),
                            'isp': geo_data.get('isp'),
                            'asn': geo_data.get('as'),
                            'asn_org': geo_data.get('org')
                        })
                except:
                    pass
            
            # DNS records
            try:
                import dns.resolver
                records = {}
                for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        records[record_type] = [str(r) for r in answers]
                    except:
                        pass
                enrichment['dns_records'] = records
            except ImportError:
                logger.warning("dnspython not available, skipping DNS enrichment")
            
        except Exception as e:
            logger.warning(f"Domain enrichment failed for {domain}: {e}")
        
        return enrichment
    
    def check_domain_in_feeds(self, domain: str) -> ThreatIntelData:
        """Check if domain appears in threat intelligence feeds"""
        ti_data = ThreatIntelData(domain=domain, last_updated=datetime.now())
        
        try:
            # Check PhishTank
            phishtank_data = self.fetch_phishtank_data()
            for entry in phishtank_data:
                if domain in entry.get('url', ''):
                    ti_data.in_phishtank = True
                    ti_data.phishtank_verified = entry.get('verified', False)
                    ti_data.phishtank_url = entry.get('url')
                    break
            
            # Check OpenPhish
            openphish_data = self.fetch_openphish_data()
            for url in openphish_data:
                if domain in url:
                    ti_data.in_openphish = True
                    ti_data.openphish_url = url
                    break
            
            # Check URLhaus
            urlhaus_data = self.fetch_urlhaus_data()
            for entry in urlhaus_data:
                if domain in entry.get('url', ''):
                    ti_data.in_urlhaus = True
                    ti_data.urlhaus_url = entry.get('url')
                    break
            
            # Calculate blacklist hits
            ti_data.blacklist_hits = sum([
                ti_data.in_phishtank,
                ti_data.in_openphish,
                ti_data.in_urlhaus
            ])
            
            # Enrich with additional data
            ti_data.enrichment_data = self.enrich_domain_data(domain)
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed for {domain}: {e}")
        
        return ti_data
    
    def batch_check_domains(self, domains: List[str]) -> List[ThreatIntelData]:
        """Check multiple domains for threat intelligence"""
        results = []
        
        logger.info(f"Checking {len(domains)} domains for threat intelligence...")
        
        for i, domain in enumerate(domains):
            if i % 100 == 0:
                logger.info(f"Processed {i}/{len(domains)} domains")
            
            try:
                ti_data = self.check_domain_in_feeds(domain)
                results.append(ti_data)
            except Exception as e:
                logger.warning(f"Failed to check {domain}: {e}")
                results.append(ThreatIntelData(domain=domain))
        
        logger.info(f"Completed threat intelligence check for {len(domains)} domains")
        return results
    
    def get_feed_statistics(self) -> Dict[str, Any]:
        """Get statistics about threat intelligence feeds"""
        stats = {
            'phishtank_count': 0,
            'openphish_count': 0,
            'urlhaus_count': 0,
            'cache_status': {},
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            # PhishTank stats
            phishtank_data = self.fetch_phishtank_data()
            stats['phishtank_count'] = len(phishtank_data)
            stats['cache_status']['phishtank'] = self._is_cache_valid(self.phishtank_cache)
            
            # OpenPhish stats
            openphish_data = self.fetch_openphish_data()
            stats['openphish_count'] = len(openphish_data)
            stats['cache_status']['openphish'] = self._is_cache_valid(self.openphish_cache)
            
            # URLhaus stats
            urlhaus_data = self.fetch_urlhaus_data()
            stats['urlhaus_count'] = len(urlhaus_data)
            stats['cache_status']['urlhaus'] = self._is_cache_valid(self.urlhaus_cache)
            
        except Exception as e:
            logger.error(f"Failed to get feed statistics: {e}")
        
        return stats

class ThreatIntelProcessor:
    """Processes threat intelligence data and updates database"""
    
    def __init__(self, db_session):
        self.db = db_session
        self.ti_gatherer = ThreatIntelligenceGatherer()
    
    def update_detection_with_ti(self, detection_id: int, ti_data: ThreatIntelData):
        """Update detection record with threat intelligence data"""
        try:
            from backend.models import PhishingDetection
            
            detection = self.db.query(PhishingDetection).filter(
                PhishingDetection.id == detection_id
            ).first()
            
            if not detection:
                logger.warning(f"Detection {detection_id} not found")
                return False
            
            # Update threat intelligence fields
            detection.in_phishtank = ti_data.in_phishtank
            detection.in_openphish = ti_data.in_openphish
            detection.in_urlhaus = ti_data.in_urlhaus
            
            # Update enrichment data
            if ti_data.enrichment_data:
                enrichment = ti_data.enrichment_data
                detection.ip_address = enrichment.get('ip_address')
                detection.country = enrichment.get('country')
                detection.hosting_isp = enrichment.get('isp')
                detection.asn = enrichment.get('asn')
                
                # Store DNS records
                dns_records = enrichment.get('dns_records', {})
                detection.dns_records = json.dumps(dns_records)
                detection.ns_records = json.dumps(dns_records.get('NS', []))
                detection.mx_records = json.dumps(dns_records.get('MX', []))
            
            # Update risk score based on threat intelligence
            if ti_data.blacklist_hits > 0:
                detection.risk_score = min(100, detection.risk_score + (ti_data.blacklist_hits * 20))
                if detection.risk_score >= 80:
                    detection.risk_level = "Critical"
                elif detection.risk_score >= 60:
                    detection.risk_level = "High"
                elif detection.risk_score >= 40:
                    detection.risk_level = "Medium"
                else:
                    detection.risk_level = "Low"
            
            self.db.commit()
            logger.info(f"Updated detection {detection_id} with threat intelligence")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update detection {detection_id}: {e}")
            self.db.rollback()
            return False
    
    def process_new_detections(self, limit: int = 100):
        """Process new detections that haven't been enriched yet"""
        try:
            from backend.models import PhishingDetection
            
            # Get detections without threat intelligence data
            detections = self.db.query(PhishingDetection).filter(
                PhishingDetection.is_active == True,
                PhishingDetection.in_phishtank == None
            ).limit(limit).all()
            
            if not detections:
                logger.info("No new detections to process")
                return 0
            
            domains = [d.phishing_domain for d in detections]
            ti_results = self.ti_gatherer.batch_check_domains(domains)
            
            updated_count = 0
            for detection, ti_data in zip(detections, ti_results):
                if self.update_detection_with_ti(detection.id, ti_data):
                    updated_count += 1
            
            logger.info(f"Processed {updated_count}/{len(detections)} detections")
            return updated_count
            
        except Exception as e:
            logger.error(f"Failed to process new detections: {e}")
            return 0
