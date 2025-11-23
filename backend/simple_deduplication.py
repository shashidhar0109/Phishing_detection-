"""
Simple and Robust Deduplication System
"""

import numpy as np
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
import logging
from difflib import SequenceMatcher

from .models import PhishingDetection

logger = logging.getLogger(__name__)

class SimpleDeduplicator:
    """
    Simple but robust deduplication system
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.similarity_threshold = 0.85
        
    def deduplicate_all_detections(self) -> Dict[str, Any]:
        """
        Perform simple but effective deduplication
        """
        logger.info("Starting simple deduplication process...")
        
        # Get all active detections
        all_detections = self.db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True
        ).all()
        
        logger.info(f"Found {len(all_detections)} active detections")
        
        if len(all_detections) < 2:
            return {
                'total_detections': len(all_detections),
                'duplicates_found': 0,
                'duplicates_removed': 0,
                'unique_detections': len(all_detections),
                'clusters_created': 0
            }
        
        # Group by exact domain matches first
        domain_groups = {}
        for detection in all_detections:
            domain = detection.phishing_domain.lower().strip()
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(detection)
        
        # Process each group
        removed_count = 0
        kept_count = 0
        
        for domain, detections in domain_groups.items():
            if len(detections) > 1:
                # Keep the best detection, mark others as inactive
                best_detection = self._select_best_detection(detections)
                duplicates = [d for d in detections if d.id != best_detection.id]
                
                # Mark duplicates as inactive
                for duplicate in duplicates:
                    duplicate.is_active = False
                    duplicate.detection_metadata = {
                        **duplicate.detection_metadata,
                        'deduplication_reason': 'exact_domain_duplicate',
                        'duplicate_of_id': best_detection.id,
                        'deduplicated_at': datetime.now().isoformat()
                    }
                    removed_count += len(duplicates)
                
                kept_count += 1
            else:
                kept_count += 1
        
        # Commit changes
        self.db.commit()
        
        logger.info(f"Deduplication complete: {removed_count} removed, {kept_count} kept")
        
        return {
            'total_detections': len(all_detections),
            'duplicates_found': len([g for g in domain_groups.values() if len(g) > 1]),
            'duplicates_removed': removed_count,
            'unique_detections': kept_count,
            'clusters_created': len([g for g in domain_groups.values() if len(g) > 1])
        }
    
    def _select_best_detection(self, detections: List[PhishingDetection]) -> PhishingDetection:
        """Select the best detection from a group of duplicates"""
        if len(detections) == 1:
            return detections[0]
        
        # Scoring criteria
        scores = []
        
        for detection in detections:
            score = 0
            
            # Higher risk score is better
            score += detection.risk_score or 0
            
            # More recent detection is better
            if detection.detected_at:
                days_old = (datetime.now() - detection.detected_at).days
                score += max(0, 30 - days_old) / 30  # Recent detections get higher score
            
            # Has screenshot is better
            if detection.screenshot_path:
                score += 0.1
            
            # Has evidence PDF is better
            if detection.evidence_pdf_path:
                score += 0.1
            
            # More complete data is better
            completeness = 0
            if detection.registrar:
                completeness += 0.1
            if detection.registrant:
                completeness += 0.1
            if detection.ip_address:
                completeness += 0.1
            if detection.ssl_issuer:
                completeness += 0.1
            
            score += completeness
            
            scores.append((score, detection))
        
        # Return detection with highest score
        scores.sort(key=lambda x: x[0], reverse=True)
        return scores[0][1]
    
    def get_deduplication_stats(self) -> Dict[str, Any]:
        """Get statistics about deduplication"""
        total_detections = self.db.query(PhishingDetection).count()
        active_detections = self.db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True
        ).count()
        inactive_detections = total_detections - active_detections
        
        # Get unique domains
        unique_domains = self.db.query(PhishingDetection.phishing_domain).filter(
            PhishingDetection.is_active == True
        ).distinct().count()
        
        # Get duplicate rate
        duplicate_rate = (total_detections - unique_domains) / total_detections if total_detections > 0 else 0
        
        return {
            'total_detections': total_detections,
            'active_detections': active_detections,
            'inactive_detections': inactive_detections,
            'unique_domains': unique_domains,
            'duplicate_rate': duplicate_rate,
            'data_quality_score': 1.0 - duplicate_rate
        }
