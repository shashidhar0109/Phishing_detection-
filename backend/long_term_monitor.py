"""
Long-term Monitoring System for Phishing Detection
Monitors suspected domains for configurable duration (e.g., 3 months)
Detects content changes, binary hosting, and lookalike content
"""

import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from backend.database import SessionLocal
from backend.models import (
    MonitoringSchedule, ContentChangeLog, PhishingDetection, 
    CSEDomain, ScanHistory
)
from backend.detector import PhishingDetector
from backend.intelligence import IntelligenceGatherer
from backend.risk_scorer import RiskScorer
from backend.config import settings
from backend.logging_config import log_info, log_warning, log_error, log_performance


class LongTermMonitor:
    """Long-term monitoring system for suspected domains"""
    
    def __init__(self):
        self.detector = PhishingDetector()
        self.intelligence = IntelligenceGatherer()
        self.risk_scorer = RiskScorer()
    
    def create_monitoring_schedule(
        self, 
        domain: str, 
        cse_domain_id: int, 
        duration_days: int = None,
        risk_level: str = "MEDIUM"
    ) -> MonitoringSchedule:
        """Create a new monitoring schedule for a domain"""
        if duration_days is None:
            duration_days = settings.DEFAULT_MONITORING_DURATION_DAYS
        
        # Validate duration
        duration_days = min(duration_days, settings.MAX_MONITORING_DURATION_DAYS)
        
        # Calculate monitoring interval based on risk level
        interval_hours = self._get_monitoring_interval(risk_level)
        
        # Calculate end date
        end_date = datetime.utcnow() + timedelta(days=duration_days)
        
        # Calculate next check time
        next_check = datetime.utcnow() + timedelta(hours=interval_hours)
        
        schedule = MonitoringSchedule(
            domain=domain,
            cse_domain_id=cse_domain_id,
            monitoring_duration_days=duration_days,
            end_date=end_date,
            monitoring_interval_hours=interval_hours,
            next_check=next_check,
            risk_level=risk_level
        )
        
        return schedule
    
    def _get_monitoring_interval(self, risk_level: str) -> int:
        """Get monitoring interval based on risk level"""
        intervals = {
            "HIGH": settings.HIGH_RISK_MONITORING_INTERVAL,
            "MEDIUM": settings.MEDIUM_RISK_MONITORING_INTERVAL,
            "LOW": settings.LOW_RISK_MONITORING_INTERVAL
        }
        return intervals.get(risk_level.upper(), settings.MEDIUM_RISK_MONITORING_INTERVAL)
    
    def get_domains_for_monitoring(self) -> List[MonitoringSchedule]:
        """Get domains that need monitoring based on schedule"""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            
            # Get active schedules that are due for checking
            schedules = db.query(MonitoringSchedule).filter(
                and_(
                    MonitoringSchedule.is_active == True,
                    MonitoringSchedule.next_check <= now,
                    MonitoringSchedule.end_date > now  # Not expired
                )
            ).all()
            
            log_info(f"Found {len(schedules)} domains due for monitoring")
            return schedules
            
        finally:
            db.close()
    
    def monitor_domain(self, schedule: MonitoringSchedule) -> Dict:
        """Monitor a single domain for changes"""
        db = SessionLocal()
        start_time = time.time()
        
        try:
            log_info(f"Starting monitoring for {schedule.domain}")
            
            # Get CSE domain info
            cse_domain = db.query(CSEDomain).filter(
                CSEDomain.id == schedule.cse_domain_id
            ).first()
            
            if not cse_domain:
                log_error("monitor_domain", "CSE domain not found", schedule.domain)
                return {"status": "error", "message": "CSE domain not found"}
            
            # Get previous detection record
            previous_detection = db.query(PhishingDetection).filter(
                PhishingDetection.phishing_domain == schedule.domain
            ).first()
            
            # Check if domain is still accessible
            if not self.detector.quick_check_accessibility(schedule.domain):
                log_warning(f"Domain {schedule.domain} is no longer accessible")
                schedule.is_active = False
                schedule.updated_at = datetime.utcnow()
                db.commit()
                return {"status": "inaccessible", "domain": schedule.domain}
            
            # Capture current screenshot
            current_screenshot = self._capture_screenshot(schedule.domain)
            
            # Analyze current content
            current_analysis = self._analyze_domain_content(schedule.domain)
            
            changes_detected = []
            
            # Check for content changes
            if previous_detection and settings.ENABLE_CONTENT_CHANGE_DETECTION:
                content_changes = self._detect_content_changes(
                    db, schedule, previous_detection, current_analysis, current_screenshot
                )
                changes_detected.extend(content_changes)
            
            # Check for binary hosting
            if settings.ENABLE_BINARY_HOSTING_MONITORING:
                binary_changes = self._detect_binary_hosting_changes(
                    db, schedule, previous_detection, current_analysis
                )
                changes_detected.extend(binary_changes)
            
            # Check for lookalike content changes
            if settings.ENABLE_LOOKALIKE_CONTENT_MONITORING:
                lookalike_changes = self._detect_lookalike_content_changes(
                    db, schedule, cse_domain, current_analysis, current_screenshot
                )
                changes_detected.extend(lookalike_changes)
            
            # Update monitoring schedule
            schedule.last_checked = datetime.utcnow()
            schedule.next_check = datetime.utcnow() + timedelta(hours=schedule.monitoring_interval_hours)
            schedule.updated_at = datetime.utcnow()
            
            # Update or create detection record
            if changes_detected:
                self._update_detection_record(db, schedule, previous_detection, current_analysis)
                log_warning(f"Changes detected in {schedule.domain}: {len(changes_detected)} changes")
            else:
                log_info(f"No significant changes detected in {schedule.domain}")
            
            db.commit()
            
            # Log performance
            duration = time.time() - start_time
            log_performance(f"Monitoring {schedule.domain} completed in {duration:.2f}s")
            
            return {
                "status": "success",
                "domain": schedule.domain,
                "changes_detected": len(changes_detected),
                "changes": changes_detected,
                "duration": duration
            }
            
        except Exception as e:
            log_error("monitor_domain", e, schedule.domain)
            return {"status": "error", "domain": schedule.domain, "error": str(e)}
        finally:
            db.close()
    
    def _capture_screenshot(self, domain: str) -> Optional[str]:
        """Capture screenshot of domain"""
        try:
            # Use the detector's screenshot capture method
            return self.detector._capture_screenshot(domain)
        except Exception as e:
            log_error("_capture_screenshot", e, domain)
            return None
    
    def _analyze_domain_content(self, domain: str) -> Dict:
        """Analyze domain content for changes"""
        try:
            # Use the detector's content analysis
            return self.detector._analyze_content(domain)
        except Exception as e:
            log_error("_analyze_domain_content", e, domain)
            return {}
    
    def _detect_content_changes(
        self, 
        db: Session, 
        schedule: MonitoringSchedule, 
        previous_detection: PhishingDetection,
        current_analysis: Dict,
        current_screenshot: str
    ) -> List[Dict]:
        """Detect content changes in monitored domain"""
        changes = []
        
        try:
            # Calculate content hash
            current_content_hash = self._calculate_content_hash(current_analysis)
            previous_content_hash = previous_detection.detection_metadata.get('content_hash') if previous_detection.detection_metadata else None
            
            if previous_content_hash and current_content_hash != previous_content_hash:
                # Calculate change percentage
                change_percentage = self._calculate_change_percentage(previous_content_hash, current_content_hash)
                
                if change_percentage >= settings.CONTENT_CHANGE_THRESHOLD:
                    # Log content change
                    change_log = ContentChangeLog(
                        domain=schedule.domain,
                        detection_id=previous_detection.id,
                        change_type="content_change",
                        previous_content_hash=previous_content_hash,
                        current_content_hash=current_content_hash,
                        change_percentage=change_percentage,
                        change_details={
                            "previous_analysis": previous_detection.detection_metadata,
                            "current_analysis": current_analysis
                        },
                        screenshot_before=previous_detection.screenshot_path,
                        screenshot_after=current_screenshot
                    )
                    db.add(change_log)
                    
                    changes.append({
                        "type": "content_change",
                        "percentage": change_percentage,
                        "details": "Significant content changes detected"
                    })
                    
                    log_warning(f"Content change detected in {schedule.domain}: {change_percentage:.1%}")
            
        except Exception as e:
            log_error("_detect_content_changes", e, schedule.domain)
        
        return changes
    
    def _detect_binary_hosting_changes(
        self, 
        db: Session, 
        schedule: MonitoringSchedule, 
        previous_detection: PhishingDetection,
        current_analysis: Dict
    ) -> List[Dict]:
        """Detect binary hosting changes"""
        changes = []
        
        try:
            previous_binary = previous_detection.detection_metadata.get('has_binary_hosting', False) if previous_detection.detection_metadata else False
            current_binary = current_analysis.get('has_binary_hosting', False)
            
            if current_binary and not previous_binary:
                # New binary hosting detected
                change_log = ContentChangeLog(
                    domain=schedule.domain,
                    detection_id=previous_detection.id,
                    change_type="binary_hosting",
                    change_details={
                        "previous": previous_binary,
                        "current": current_binary,
                        "binary_indicators": current_analysis.get('suspicious_keywords', [])
                    }
                )
                db.add(change_log)
                
                changes.append({
                    "type": "binary_hosting",
                    "details": "Binary hosting detected"
                })
                
                log_warning(f"Binary hosting detected in {schedule.domain}")
            
        except Exception as e:
            log_error("_detect_binary_hosting_changes", e, schedule.domain)
        
        return changes
    
    def _detect_lookalike_content_changes(
        self, 
        db: Session, 
        schedule: MonitoringSchedule, 
        cse_domain: CSEDomain,
        current_analysis: Dict,
        current_screenshot: str
    ) -> List[Dict]:
        """Detect lookalike content changes"""
        changes = []
        
        try:
            # Compare with legitimate CSE domain
            if current_screenshot:
                # Capture CSE domain screenshot for comparison
                cse_screenshot = self._capture_screenshot(cse_domain.domain)
                
                if cse_screenshot:
                    # Calculate visual similarity
                    visual_similarity = self.detector._calculate_visual_similarity(
                        cse_screenshot, current_screenshot
                    )
                    
                    # Check if similarity increased significantly
                    if visual_similarity > 80:  # High similarity threshold
                        change_log = ContentChangeLog(
                            domain=schedule.domain,
                            detection_id=None,  # New detection
                            change_type="lookalike_content",
                            change_details={
                                "visual_similarity": visual_similarity,
                                "cse_domain": cse_domain.domain,
                                "content_analysis": current_analysis
                            },
                            screenshot_after=current_screenshot
                        )
                        db.add(change_log)
                        
                        changes.append({
                            "type": "lookalike_content",
                            "similarity": visual_similarity,
                            "details": f"High visual similarity with {cse_domain.domain}"
                        })
                        
                        log_warning(f"Lookalike content detected in {schedule.domain} (similarity: {visual_similarity:.1f}%)")
            
        except Exception as e:
            log_error("_detect_lookalike_content_changes", e, schedule.domain)
        
        return changes
    
    def _calculate_content_hash(self, analysis: Dict) -> str:
        """Calculate hash of content analysis"""
        content_str = str(sorted(analysis.items()))
        return hashlib.md5(content_str.encode()).hexdigest()
    
    def _calculate_change_percentage(self, old_hash: str, new_hash: str) -> float:
        """Calculate percentage of change between hashes"""
        if old_hash == new_hash:
            return 0.0
        
        # Simple hash comparison - in practice, you'd use more sophisticated content comparison
        return 0.5  # Placeholder - implement actual content comparison
    
    def _update_detection_record(
        self, 
        db: Session, 
        schedule: MonitoringSchedule, 
        previous_detection: PhishingDetection,
        current_analysis: Dict
    ):
        """Update or create detection record with current analysis"""
        try:
            if previous_detection:
                # Update existing detection
                previous_detection.last_checked = datetime.utcnow()
                previous_detection.detection_metadata = current_analysis
                previous_detection.updated_at = datetime.utcnow()
            else:
                # Create new detection record
                new_detection = PhishingDetection(
                    cse_domain_id=schedule.cse_domain_id,
                    phishing_domain=schedule.domain,
                    variation_type="monitored_domain",
                    detected_at=datetime.utcnow(),
                    is_active=True,
                    last_checked=datetime.utcnow(),
                    detection_metadata=current_analysis,
                    source_of_detection="long_term_monitoring"
                )
                db.add(new_detection)
                
        except Exception as e:
            log_error("_update_detection_record", e, schedule.domain)
    
    def cleanup_expired_monitoring(self):
        """Clean up expired monitoring schedules"""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            
            # Deactivate expired schedules
            expired_schedules = db.query(MonitoringSchedule).filter(
                and_(
                    MonitoringSchedule.is_active == True,
                    MonitoringSchedule.end_date <= now
                )
            ).all()
            
            for schedule in expired_schedules:
                schedule.is_active = False
                schedule.updated_at = now
                log_info(f"Deactivated expired monitoring for {schedule.domain}")
            
            db.commit()
            log_info(f"Cleaned up {len(expired_schedules)} expired monitoring schedules")
            
        except Exception as e:
            log_error("cleanup_expired_monitoring", e)
        finally:
            db.close()
    
    def get_monitoring_statistics(self) -> Dict:
        """Get monitoring statistics"""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            
            total_schedules = db.query(MonitoringSchedule).count()
            active_schedules = db.query(MonitoringSchedule).filter(
                MonitoringSchedule.is_active == True
            ).count()
            
            due_for_checking = db.query(MonitoringSchedule).filter(
                and_(
                    MonitoringSchedule.is_active == True,
                    MonitoringSchedule.next_check <= now
                )
            ).count()
            
            recent_changes = db.query(ContentChangeLog).filter(
                ContentChangeLog.detected_at >= now - timedelta(days=7)
            ).count()
            
            return {
                "total_schedules": total_schedules,
                "active_schedules": active_schedules,
                "due_for_checking": due_for_checking,
                "recent_changes": recent_changes
            }
            
        finally:
            db.close()
