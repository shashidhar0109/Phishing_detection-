from celery import Celery
from celery.schedules import crontab
from sqlalchemy.orm import Session
from datetime import datetime
import os
import time

from backend.config import settings
from backend.database import SessionLocal
from backend.models import CSEDomain, PhishingDetection, DomainVariation, ScanHistory
from backend.domain_generator import generate_variations_for_domain
from backend.intelligence import IntelligenceGatherer
from backend.detector import PhishingDetector
from backend.risk_scorer import RiskScorer
from backend.report_generator import generate_phishing_report
from backend.logging_config import (
    log_monitoring_cycle_start, log_monitoring_cycle_end,
    log_cse_domain_scan_start, log_cse_domain_scan_end,
    log_variation_check, log_new_detection,
    log_intelligence_gathering, log_social_media_scan,
    log_error, log_performance, log_warning, log_info,
    log_system_startup
)


def is_legitimate_domain(suspicious_domain: str, cse_domain: str) -> bool:
    """
    Check if a suspicious domain is actually legitimate to prevent false positives.
    
    Args:
        suspicious_domain: The domain being analyzed (e.g., www.yonobusiness.sbi)
        cse_domain: The original CSE domain (e.g., yonobusiness.sbi)
    
    Returns:
        True if the domain should be whitelisted, False otherwise
    """
    # Remove www. prefix for comparison
    suspicious_clean = suspicious_domain.replace('www.', '')
    cse_clean = cse_domain.replace('www.', '')
    
    # If they're the same domain (ignoring www), it's legitimate
    if suspicious_clean == cse_clean:
        return True
    
    # Check for common legitimate subdomains that shouldn't be flagged
    legitimate_subdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'store', 'app', 'api', 'admin']
    
    # Extract subdomain and main domain
    parts = suspicious_domain.split('.')
    if len(parts) >= 3:
        subdomain = parts[0]
        main_domain = '.'.join(parts[1:])
        
        # If it's a legitimate subdomain of the CSE domain
        if subdomain in legitimate_subdomains and main_domain == cse_domain:
            return True
    
    return False
from backend.long_term_monitor import LongTermMonitor
from backend.models import MonitoringSchedule

# Initialize Celery
celery_app = Celery(
    'phishing_detection',
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    # Worker configuration for stability
    worker_hijack_root_logger=False,
    worker_log_color=False,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=50,
    worker_disable_rate_limits=True,
    task_reject_on_worker_lost=True,
    # Connection settings
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    # Task settings
    task_soft_time_limit=300,
    task_time_limit=600,
    task_ignore_result=True,
    # Error handling
    task_annotations={
        '*': {'rate_limit': '10/s'},
        'backend.worker.continuous_scan': {'rate_limit': '1/m'},
    }
)

# Periodic task schedule
celery_app.conf.beat_schedule = {
    'scan-for-phishing-every-15-minutes': {
        'task': 'backend.worker.continuous_scan',
        'schedule': crontab(minute=f'*/{settings.SCAN_INTERVAL_MINUTES}'),
    },
    'update-blacklist-feeds-hourly': {
        'task': 'backend.worker.update_blacklist_feeds',
        'schedule': crontab(minute=0),  # Every hour
    },
    'long-term-monitoring-every-hour': {
        'task': 'backend.worker.long_term_monitoring_cycle',
        'schedule': crontab(minute=0),  # Every hour
    },
    'cleanup-expired-monitoring-daily': {
        'task': 'backend.worker.cleanup_expired_monitoring',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
    },
}


@celery_app.task(name='backend.worker.continuous_scan')
def continuous_scan():
    """Continuous scanning task - runs periodically"""
    db = SessionLocal()
    scan_start_time = time.time()
    
    try:
        # Create scan history record
        scan = ScanHistory(
            scan_type='continuous_scan',
            started_at=datetime.utcnow(),
            status='running'
        )
        db.add(scan)
        db.commit()
        
        # Get all active CSE domains
        cse_domains = db.query(CSEDomain).filter(CSEDomain.is_active == True).all()
        
        # Log monitoring cycle start
        log_monitoring_cycle_start(scan.id, len(cse_domains))
        
        domains_checked = 0
        phishing_found = 0
        
        for cse_domain in cse_domains:
            cse_scan_start = time.time()
            variations_in_this_domain = 0
            detections_in_this_domain = 0
            
            try:
                # Generate or get existing variations
                existing_variations = db.query(DomainVariation).filter(
                    DomainVariation.cse_domain_id == cse_domain.id
                ).all()
                
                # Log CSE domain scan start
                log_cse_domain_scan_start(cse_domain.domain, cse_domain.organization_name)
                print(f"[DEBUG] Starting scan for {cse_domain.domain} - Found {len(existing_variations)} existing variations")
                
                if not existing_variations or len(existing_variations) < 1000:
                    # Generate new variations (comprehensive - all TLDs + look-alikes)
                    variations = generate_variations_for_domain(cse_domain.domain, max_variations=100000)
                    
                    for var in variations:
                        # Check if variation already exists
                        exists = db.query(DomainVariation).filter(
                            DomainVariation.variation == var['domain']
                        ).first()
                        
                        if not exists:
                            new_var = DomainVariation(
                                cse_domain_id=cse_domain.id,
                                variation=var['domain'],
                                variation_type=var['type'],
                                is_registered=False
                            )
                            db.add(new_var)
                    
                    db.commit()
                    existing_variations = db.query(DomainVariation).filter(
                        DomainVariation.cse_domain_id == cse_domain.id
                    ).all()
                
                # Check variations for registration
                gatherer = IntelligenceGatherer()
                
                # Check up to 50000 variations per scan cycle (rotates through all variations over multiple cycles)
                variations_to_check = min(len(existing_variations), 50000)
                for variation in existing_variations[:variations_to_check]:
                    try:
                        domains_checked += 1
                        variations_in_this_domain += 1
                        
                        # Check if variation still exists in database
                        if not db.query(DomainVariation).filter(DomainVariation.id == variation.id).first():
                            print(f"[DEBUG] Variation {variation.variation} was deleted, skipping")
                            continue
                        
                        # Check if registered
                        is_registered = gatherer.is_domain_registered(variation.variation)
                        
                        # Debug logging for first few variations
                        if variations_in_this_domain <= 5:
                            print(f"[DEBUG] Checking {variation.variation} - Registered: {is_registered}")
                        
                        # Log variation check
                        log_variation_check(variation.variation, variation.variation_type, is_registered)
                    except Exception as e:
                        print(f"[ERROR] Error processing variation {variation.variation}: {e}")
                        continue
                    
                    if is_registered and not variation.is_registered:
                        # Newly registered domain detected!
                        print(f"[DEBUG] 🔴 NEW REGISTERED DOMAIN: {variation.variation} (Type: {variation.variation_type})")
                        log_warning(f"🔴 NEW REGISTERED DOMAIN: {variation.variation} (Type: {variation.variation_type})")
                        
                        variation.is_registered = True
                        variation.last_checked = datetime.utcnow()
                        
                        # Check if already detected
                        existing_detection = db.query(PhishingDetection).filter(
                            PhishingDetection.phishing_domain == variation.variation
                        ).first()
                        
                        if not existing_detection:
                            # Analyze the domain
                            result = analyze_and_store_phishing(
                                db,
                                cse_domain,
                                variation.variation,
                                variation.variation_type
                            )
                            
                            if result:
                                phishing_found += 1
                                detections_in_this_domain += 1
                    
                    variation.last_checked = datetime.utcnow()
                
                db.commit()
                
                # Log CSE domain scan completion
                cse_scan_duration = time.time() - cse_scan_start
                print(f"[DEBUG] Completed scan for {cse_domain.domain} - Checked {variations_in_this_domain} variations, Found {detections_in_this_domain} detections")
                log_cse_domain_scan_end(cse_domain.domain, variations_in_this_domain, detections_in_this_domain)
                log_performance(f"Scan {cse_domain.domain}", cse_scan_duration, 
                              f"{variations_in_this_domain} variations checked")
                
            except Exception as e:
                log_error(f"Scanning {cse_domain.domain}", e, cse_domain.domain)
                continue
        
        # Update scan history
        scan.completed_at = datetime.utcnow()
        scan.domains_checked = domains_checked
        scan.phishing_found = phishing_found
        scan.status = 'completed'
        db.commit()
        
        # Log monitoring cycle completion
        scan_duration = time.time() - scan_start_time
        log_monitoring_cycle_end(scan.id, domains_checked, phishing_found, scan_duration)
        
        # Add delay to prevent continuous scanning
        remaining_time = (settings.SCAN_INTERVAL_MINUTES * 60) - scan_duration
        if remaining_time > 0:
            log_info(f"⏳ Waiting {remaining_time:.1f}s until next scan cycle...")
            time.sleep(remaining_time)
        
        return {
            'status': 'completed',
            'domains_checked': domains_checked,
            'phishing_found': phishing_found,
            'duration': scan_duration
        }
        
    except Exception as e:
        scan.status = 'failed'
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        log_error("Continuous scan", e)
        raise
    finally:
        db.close()


def analyze_and_store_phishing(
    db: Session,
    cse_domain: CSEDomain,
    suspicious_domain: str,
    variation_type: str
) -> bool:
    """Analyze a suspicious domain and store if phishing detected"""
    try:
        # Validate inputs
        if not suspicious_domain or not cse_domain:
            print(f"[ERROR] Invalid inputs for analysis: domain={suspicious_domain}, cse={cse_domain}")
            return False
        # WHITELIST CHECK - Prevent false positives for legitimate domains
        if is_legitimate_domain(suspicious_domain, cse_domain.domain):
            log_info(f"✅ Whitelisted legitimate domain: {suspicious_domain}")
            return False
        
        log_info(f"🔬 Analyzing suspicious domain: {suspicious_domain}")
        analysis_start = time.time()
        
        # Gather intelligence with error handling
        try:
            gatherer = IntelligenceGatherer()
            intel = gatherer.gather_all(suspicious_domain)
        except Exception as e:
            print(f"[ERROR] Intelligence gathering failed for {suspicious_domain}: {e}")
            intel = {}
        
        # Scan Twitter for domain mentions with error handling
        try:
            twitter_data = gatherer.scan_twitter_for_domain(suspicious_domain)
        except Exception as e:
            print(f"[ERROR] Twitter scan failed for {suspicious_domain}: {e}")
            twitter_data = {}
        
        # Detect phishing (screenshots + visual analysis) with error handling
        try:
            detector = PhishingDetector()
            detection_result = detector.analyze_domain(cse_domain.domain, suspicious_domain)
        except Exception as e:
            print(f"[ERROR] Phishing detection failed for {suspicious_domain}: {e}")
            detection_result = {
                'visual_similarity_score': 0.0,
                'content_similarity_score': 0.0,
                'has_login_form': False,
                'has_payment_form': False
            }
        
        # Calculate risk score with error handling
        try:
            scorer = RiskScorer()
            
            # Get domain age
            domain_age = gatherer.get_domain_age_days(intel.get('whois', {}))
            
            risk_result = scorer.calculate_risk_score(
                domain_age_days=domain_age,
                visual_similarity=detection_result.get('visual_similarity_score', 0),
                content_similarity=detection_result.get('content_similarity_score', 0),
                has_login_form=detection_result.get('has_login_form', False),
                has_payment_form=detection_result.get('has_payment_form', False),
                ssl_info=intel.get('ssl', {}),
                blacklist_results=intel.get('blacklists', {}),
                whois_info=intel.get('whois', {})
            )
        except Exception as e:
            print(f"[ERROR] Risk scoring failed for {suspicious_domain}: {e}")
            risk_result = {
                'total_score': 0,
                'risk_level': 'LOW',
                'component_scores': {}
            }
        
        # Store ALL detections (even low risk) for visibility
        if risk_result['total_score'] >= 0:  # Changed from RISK_THRESHOLD_MEDIUM to 0 to show all
            print(f"[DETECTION] Domain analyzed: {suspicious_domain} (Score: {risk_result['total_score']})")
            
            # Parse intelligence data
            whois_info = intel.get('whois', {})
            dns_info = intel.get('dns', {})
            ssl_info = intel.get('ssl', {})
            ip_info = intel.get('ip_info', {})
            blacklists = intel.get('blacklists', {})
            cert_trans = intel.get('cert_transparency', {})
            
            # Create phishing detection record
            subnet_str = None
            if ip_info.get('ip'):
                try:
                    subnet_parts = ip_info.get('ip', '').split('.')[:3]
                    subnet_str = '.'.join(subnet_parts) + '.0/24'
                except:
                    subnet_str = None
            
            phishing_detection = PhishingDetection(
                cse_domain_id=cse_domain.id,
                phishing_domain=suspicious_domain,
                variation_type=variation_type,
                detected_at=datetime.utcnow(),
                
                # Domain info
                domain_created_at=_parse_date(whois_info.get('creation_date')),
                registrar=whois_info.get('registrar'),
                registrant=str(whois_info) if whois_info else None,
                
                # Network info
                ip_address=ip_info.get('ip'),
                subnet=subnet_str,
                asn=ip_info.get('asn'),
                country=ip_info.get('country'),
                
                # DNS
                mx_records=dns_info.get('mx_records'),
                ns_records=dns_info.get('ns_records'),
                
                # SSL
                ssl_issuer=str(ssl_info.get('issuer')) if ssl_info.get('issuer') else None,
                ssl_valid_from=_parse_date(ssl_info.get('not_before')),
                ssl_valid_to=_parse_date(ssl_info.get('not_after')),
                cert_transparency_logs=cert_trans.get('recent_certs', []) if cert_trans else None,
                
                # Analysis (convert numpy types to Python types)
                visual_similarity_score=float(detection_result.get('visual_similarity_score', 0)),
                content_similarity_score=float(detection_result.get('content_similarity_score', 0)),
                has_login_form=detection_result.get('has_login_form', False),
                has_payment_form=detection_result.get('has_payment_form', False),
                
                # Blacklists
                in_phishtank=blacklists.get('phishtank', False),
                in_openphish=blacklists.get('openphish', False),
                in_urlhaus=blacklists.get('urlhaus', False),
                
                # Risk (convert to Python float)
                risk_score=float(risk_result['total_score']),
                risk_level=risk_result['risk_level'],
                
                # Files
                screenshot_path=detection_result.get('screenshot_path'),
                report_path=None,  # Will be generated later
                
                # Metadata
                detection_metadata=risk_result,
                
                # PS-02 Additional Fields
                registrant_organization=whois_info.get('org'),
                registrant_country=whois_info.get('country'),
                hosting_isp=ip_info.get('isp'),
                hosting_country=ip_info.get('country'),
                name_servers=','.join(whois_info.get('name_servers', [])),
                dns_records_text=str(dns_info),
                source_of_detection=variation_type,
                detection_method=f"Visual Similarity: {detection_result.get('visual_similarity_score', 0):.1f}%",
                social_media_post_date=twitter_data.get('latest_post_date') if twitter_data.get('found') else None,
                social_media_platform=twitter_data.get('platform') if twitter_data.get('found') else None,
                social_media_post_url=twitter_data.get('latest_post_url') if twitter_data.get('found') else None
            )
            
            db.add(phishing_detection)
            db.commit()
            db.refresh(phishing_detection)
            
            # Send real-time notification
            try:
                from backend.main import manager
                import asyncio
                
                # Create notification data
                notification_data = {
                    "type": "new_detection",
                    "data": {
                        "id": phishing_detection.id,
                        "phishing_domain": phishing_detection.phishing_domain,
                        "legitimate_domain": cse_domain.domain,
                        "organization_name": cse_domain.organization_name,
                        "risk_score": phishing_detection.risk_score,
                        "risk_level": phishing_detection.risk_level,
                        "detected_at": phishing_detection.detected_at.isoformat(),
                        "variation_type": phishing_detection.variation_type
                    }
                }
                
                # Send notification asynchronously
                asyncio.create_task(manager.broadcast(notification_data))
                
            except Exception as e:
                print(f"[ERROR] Failed to send real-time notification: {e}")
            
            # Log new detection
            log_new_detection(
                suspicious_domain,
                cse_domain.domain,
                phishing_detection.risk_level,
                phishing_detection.risk_score,
                variation_type
            )
            
            # Log intelligence gathered
            log_intelligence_gathering(suspicious_domain, {
                'ip': ip_info.get('ip'),
                'country': ip_info.get('country'),
                'registrar': whois_info.get('registrar')
            })
            
            # Log social media scan if applicable
            if twitter_data.get('found'):
                log_social_media_scan(suspicious_domain, 'Twitter', True)
            
            # Generate PDF report
            try:
                report_data = {
                    'id': phishing_detection.id,
                    'phishing_domain': suspicious_domain,
                    'legitimate_domain': cse_domain.domain,
                    'variation_type': variation_type,
                    'detected_at': str(phishing_detection.detected_at),
                    'domain_created_at': str(phishing_detection.domain_created_at) if phishing_detection.domain_created_at else 'Unknown',
                    'registrar': phishing_detection.registrar or 'Unknown',
                    'ip_address': phishing_detection.ip_address or 'Unknown',
                    'country': phishing_detection.country or 'Unknown',
                    'asn': phishing_detection.asn or 'Unknown',
                    'subnet': phishing_detection.subnet or 'Unknown',
                    'ssl_issuer': phishing_detection.ssl_issuer or 'None',
                    'mx_records': phishing_detection.mx_records or [],
                    'visual_similarity_score': phishing_detection.visual_similarity_score,
                    'has_login_form': phishing_detection.has_login_form,
                    'has_payment_form': phishing_detection.has_payment_form,
                    'risk_score': phishing_detection.risk_score,
                    'risk_level': phishing_detection.risk_level,
                    'screenshot_path': phishing_detection.screenshot_path,
                }
                
                report_path = generate_phishing_report(report_data)
                phishing_detection.report_path = report_path
                db.commit()
                
                log_info(f"📄 Generated PDF report: {report_path}")
                
            except Exception as e:
                log_error("PDF report generation", e, suspicious_domain)
            
            # Log analysis performance
            analysis_duration = time.time() - analysis_start
            log_performance(f"Analyze {suspicious_domain}", analysis_duration, 
                          f"Risk: {phishing_detection.risk_level} ({phishing_detection.risk_score})")
            
            return True
        else:
            log_info(f"ℹ️  Low risk domain (not stored): {suspicious_domain} (Score: {risk_result['total_score']})")
            return False
            
    except Exception as e:
        log_error(f"Analysis of {suspicious_domain}", e, suspicious_domain)
        return False


def _parse_date(date_str):
    """Parse date string to datetime"""
    if not date_str:
        return None
    
    try:
        if isinstance(date_str, datetime):
            return date_str
        
        if isinstance(date_str, str):
            # Try common formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%b %d %H:%M:%S %Y %Z']:
                try:
                    return datetime.strptime(date_str.split('.')[0], fmt)
                except:
                    continue
    except:
        pass
    
    return None


@celery_app.task(name='backend.worker.check_single_domain')
def check_single_domain(domain: str):
    """Check a single domain manually"""
    db = SessionLocal()
    
    try:
        print(f"[MANUAL CHECK] Checking {domain}")
        
        # Try to find matching CSE domain
        # For manual checks, we'll compare against all CSE domains
        cse_domains = db.query(CSEDomain).filter(CSEDomain.is_active == True).all()
        
        gatherer = IntelligenceGatherer()
        
        # Quick check if domain is registered
        if not gatherer.is_domain_registered(domain):
            return {'status': 'not_registered', 'domain': domain}
        
        # Analyze against each CSE domain to find best match
        best_match = None
        highest_similarity = 0
        
        for cse_domain in cse_domains:
            detector = PhishingDetector()
            result = detector.analyze_domain(cse_domain.domain, domain)
            
            if result.get('visual_similarity_score', 0) > highest_similarity:
                highest_similarity = result['visual_similarity_score']
                best_match = cse_domain
        
        if best_match and highest_similarity > 30:
            # Analyze and store
            result = analyze_and_store_phishing(db, best_match, domain, 'manual_check')
            
            if result:
                return {'status': 'phishing_detected', 'domain': domain}
            else:
                return {'status': 'low_risk', 'domain': domain}
        else:
            return {'status': 'no_match', 'domain': domain}
            
    except Exception as e:
        print(f"[ERROR] Manual check failed: {e}")
        return {'status': 'error', 'domain': domain, 'error': str(e)}
    finally:
        db.close()


@celery_app.task(name='backend.worker.update_blacklist_feeds')
def update_blacklist_feeds():
    """Update local blacklist feeds from public sources"""
    import requests
    
    try:
        print("[UPDATE] Updating blacklist feeds...")
        
        # Download PhishTank database
        # Note: In production, you'd download the full database
        # https://data.phishtank.com/data/online-valid.json
        
        # Download OpenPhish feed
        try:
            response = requests.get('https://openphish.com/feed.txt', timeout=30)
            if response.status_code == 200:
                # Save to file for later checking
                with open('/tmp/openphish_feed.txt', 'w') as f:
                    f.write(response.text)
                print("[UPDATE] OpenPhish feed updated")
        except Exception as e:
            print(f"[ERROR] Failed to update OpenPhish: {e}")
        
        return {'status': 'completed'}
        
    except Exception as e:
        print(f"[ERROR] Failed to update blacklists: {e}")
        return {'status': 'failed', 'error': str(e)}


@celery_app.task(name='backend.worker.long_term_monitoring_cycle')
def long_term_monitoring_cycle():
    """Long-term monitoring cycle - monitors suspected domains for configurable duration"""
    monitor = LongTermMonitor()
    start_time = time.time()
    
    try:
        log_info("Starting long-term monitoring cycle")
        
        # Get domains that need monitoring
        schedules = monitor.get_domains_for_monitoring()
        
        if not schedules:
            log_info("No domains due for long-term monitoring")
            return {'status': 'completed', 'domains_checked': 0}
        
        domains_checked = 0
        changes_detected = 0
        
        for schedule in schedules:
            try:
                result = monitor.monitor_domain(schedule)
                domains_checked += 1
                
                if result.get('status') == 'success' and result.get('changes_detected', 0) > 0:
                    changes_detected += result['changes_detected']
                    log_warning(f"Changes detected in {schedule.domain}: {result['changes']}")
                
            except Exception as e:
                log_error("monitor_domain", e, schedule.domain)
        
        duration = time.time() - start_time
        log_performance(f"Long-term monitoring cycle completed: {domains_checked} domains, {changes_detected} changes in {duration:.2f}s")
        
        return {
            'status': 'completed',
            'domains_checked': domains_checked,
            'changes_detected': changes_detected,
            'duration': duration
        }
        
    except Exception as e:
        log_error("long_term_monitoring_cycle", e)
        return {'status': 'failed', 'error': str(e)}


@celery_app.task(name='backend.worker.cleanup_expired_monitoring')
def cleanup_expired_monitoring():
    """Clean up expired monitoring schedules"""
    monitor = LongTermMonitor()
    
    try:
        log_info("Starting cleanup of expired monitoring schedules")
        monitor.cleanup_expired_monitoring()
        return {'status': 'completed'}
        
    except Exception as e:
        log_error("cleanup_expired_monitoring", e)
        return {'status': 'failed', 'error': str(e)}


@celery_app.task(name='backend.worker.create_monitoring_schedule')
def create_monitoring_schedule(domain: str, cse_domain_id: int, duration_days: int = None, risk_level: str = "MEDIUM"):
    """Create a new monitoring schedule for a domain"""
    monitor = LongTermMonitor()
    db = SessionLocal()
    
    try:
        # Check if domain is already being monitored
        existing = db.query(MonitoringSchedule).filter(
            and_(
                MonitoringSchedule.domain == domain,
                MonitoringSchedule.is_active == True
            )
        ).first()
        
        if existing:
            return {'status': 'already_monitored', 'domain': domain}
        
        # Create new monitoring schedule
        schedule = monitor.create_monitoring_schedule(domain, cse_domain_id, duration_days, risk_level)
        db.add(schedule)
        db.commit()
        
        log_info(f"Created monitoring schedule for {domain} (duration: {duration_days or 90} days, risk: {risk_level})")
        
        return {
            'status': 'created',
            'domain': domain,
            'schedule_id': schedule.id,
            'duration_days': schedule.monitoring_duration_days,
            'risk_level': schedule.risk_level
        }
        
    except Exception as e:
        log_error("create_monitoring_schedule", e, domain)
        return {'status': 'failed', 'error': str(e)}
    finally:
        db.close()


@celery_app.task(name='backend.worker.get_monitoring_statistics')
def get_monitoring_statistics():
    """Get monitoring statistics"""
    monitor = LongTermMonitor()
    
    try:
        stats = monitor.get_monitoring_statistics()
        return {'status': 'success', 'statistics': stats}
        
    except Exception as e:
        log_error("get_monitoring_statistics", e)
        return {'status': 'failed', 'error': str(e)}


if __name__ == '__main__':
    celery_app.start()

