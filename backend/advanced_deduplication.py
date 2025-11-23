"""
Advanced Deduplication System for Phishing Detections
Uses ML-based similarity matching and intelligent merging
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from datetime import datetime, timedelta
import logging
from difflib import SequenceMatcher
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
import hashlib
import re

from .models import PhishingDetection, CSEDomain
from .ml_detector import MLPhishingDetector

logger = logging.getLogger(__name__)

class AdvancedDeduplicator:
    """
    Advanced deduplication system using ML and similarity matching
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.ml_detector = MLPhishingDetector()
        self.similarity_threshold = 0.85
        self.time_window_hours = 24
        
    def deduplicate_all_detections(self) -> Dict[str, Any]:
        """
        Perform comprehensive deduplication of all detections
        """
        logger.info("Starting advanced deduplication process...")
        
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
        
        # Step 1: Exact domain matching
        exact_duplicates = self._find_exact_duplicates(all_detections)
        logger.info(f"Found {len(exact_duplicates)} exact duplicates")
        
        # Step 2: Similar domain clustering
        similar_clusters = self._find_similar_domains(all_detections)
        logger.info(f"Found {len(similar_clusters)} similar domain clusters")
        
        # Step 3: ML-based similarity matching
        ml_duplicates = self._find_ml_similar_domains(all_detections)
        logger.info(f"Found {len(ml_duplicates)} ML-similar domains")
        
        # Step 4: Merge all duplicate groups
        all_duplicate_groups = exact_duplicates + similar_clusters + ml_duplicates
        merged_groups = self._merge_duplicate_groups(all_duplicate_groups)
        
        # Step 5: Process each group and keep the best detection
        removed_count = 0
        kept_count = 0
        
        for group in merged_groups:
            if len(group) > 1:
                best_detection = self._select_best_detection(group)
                duplicates = [d for d in group if d.id != best_detection.id]
                
                # Mark duplicates as inactive
                for duplicate in duplicates:
                    duplicate.is_active = False
                    duplicate.detection_metadata = {
                        **duplicate.detection_metadata,
                        'deduplication_reason': 'duplicate_of',
                        'duplicate_of_id': best_detection.id,
                        'deduplicated_at': datetime.now().isoformat()
                    }
                    removed_count += 1
                
                kept_count += 1
        
        # Commit changes
        self.db.commit()
        
        logger.info(f"Deduplication complete: {removed_count} removed, {kept_count} kept")
        
        return {
            'total_detections': len(all_detections),
            'duplicates_found': len(merged_groups),
            'duplicates_removed': removed_count,
            'unique_detections': kept_count,
            'clusters_created': len(merged_groups)
        }
    
    def _find_exact_duplicates(self, detections: List[PhishingDetection]) -> List[List[PhishingDetection]]:
        """Find exact domain name duplicates"""
        domain_groups = {}
        
        for detection in detections:
            domain = detection.phishing_domain.lower().strip()
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(detection)
        
        # Return groups with more than one detection
        return [group for group in domain_groups.values() if len(group) > 1]
    
    def _find_similar_domains(self, detections: List[PhishingDetection]) -> List[List[PhishingDetection]]:
        """Find similar domains using string similarity"""
        if len(detections) < 2:
            return []
        
        # Create domain pairs and calculate similarity
        similar_pairs = []
        
        for i, det1 in enumerate(detections):
            for j, det2 in enumerate(detections[i+1:], i+1):
                similarity = self._calculate_domain_similarity(
                    det1.phishing_domain, det2.phishing_domain
                )
                
                if similarity > self.similarity_threshold:
                    similar_pairs.append((det1, det2, similarity))
        
        # Group similar domains
        return self._group_similar_pairs(similar_pairs)
    
    def _find_ml_similar_domains(self, detections: List[PhishingDetection]) -> List[List[PhishingDetection]]:
        """Find similar domains using ML-based features"""
        if len(detections) < 2:
            return []
        
        # Extract features for all domains
        domain_features = []
        domain_to_detection = {}
        
        for detection in detections:
            try:
                features = self.ml_detector.extract_domain_features(
                    detection.phishing_domain,
                    detection.cse_domain.domain if detection.cse_domain else None
                )
                
                # Convert to vector
                feature_vector = np.array(list(features.values()))
                domain_features.append(feature_vector)
                domain_to_detection[len(domain_features) - 1] = detection
                
            except Exception as e:
                logger.warning(f"Error extracting features for {detection.phishing_domain}: {e}")
                continue
        
        if len(domain_features) < 2:
            return []
        
        # Use DBSCAN clustering
        domain_features = np.array(domain_features)
        
        # Normalize features
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        normalized_features = scaler.fit_transform(domain_features)
        
        # Cluster similar domains
        try:
            clustering = DBSCAN(eps=0.5, min_samples=2, metric='cosine')
            cluster_labels = clustering.fit_predict(normalized_features)
        except Exception as e:
            logger.warning(f"DBSCAN clustering failed: {e}, using fallback")
            # Fallback: use simple distance-based clustering
            from sklearn.cluster import AgglomerativeClustering
            clustering = AgglomerativeClustering(n_clusters=None, distance_threshold=0.5)
            cluster_labels = clustering.fit_predict(normalized_features)
        
        # Group detections by cluster
        clusters = {}
        for idx, label in enumerate(cluster_labels):
            if label != -1:  # -1 means noise/outlier
                if label not in clusters:
                    clusters[label] = []
                clusters[label].append(domain_to_detection[idx])
        
        return list(clusters.values())
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains"""
        # Normalize domains
        d1 = domain1.lower().strip()
        d2 = domain2.lower().strip()
        
        # Exact match
        if d1 == d2:
            return 1.0
        
        # Sequence similarity
        seq_similarity = SequenceMatcher(None, d1, d2).ratio()
        
        # Character-based similarity
        char_similarity = self._calculate_character_similarity(d1, d2)
        
        # Subdomain similarity
        subdomain_similarity = self._calculate_subdomain_similarity(d1, d2)
        
        # Weighted combination
        similarity = (
            seq_similarity * 0.5 +
            char_similarity * 0.3 +
            subdomain_similarity * 0.2
        )
        
        return similarity
    
    def _calculate_character_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate character-based similarity"""
        # Character frequency comparison
        chars1 = set(domain1)
        chars2 = set(domain2)
        
        intersection = len(chars1.intersection(chars2))
        union = len(chars1.union(chars2))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def _calculate_subdomain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate subdomain similarity"""
        parts1 = domain1.split('.')
        parts2 = domain2.split('.')
        
        # Compare main domain parts
        main1 = parts1[-2] if len(parts1) >= 2 else parts1[0]
        main2 = parts2[-2] if len(parts2) >= 2 else parts2[0]
        
        if main1 == main2:
            return 1.0
        
        # Calculate similarity of main parts
        return SequenceMatcher(None, main1, main2).ratio()
    
    def _group_similar_pairs(self, similar_pairs: List[Tuple]) -> List[List[PhishingDetection]]:
        """Group similar pairs into clusters"""
        if not similar_pairs:
            return []
        
        # Create graph of similar domains
        domain_groups = {}
        domain_to_group = {}
        next_group_id = 0
        
        for det1, det2, similarity in similar_pairs:
            id1, id2 = det1.id, det2.id
            
            if id1 in domain_to_group and id2 in domain_to_group:
                # Both already in groups, merge if different
                group1 = domain_to_group[id1]
                group2 = domain_to_group[id2]
                if group1 != group2 and group2 in domain_groups:
                    # Merge groups
                    domain_groups[group1].extend(domain_groups[group2])
                    for det_id in domain_groups[group2]:
                        domain_to_group[det_id] = group1
                    del domain_groups[group2]
            elif id1 in domain_to_group:
                # Add det2 to det1's group
                group = domain_to_group[id1]
                if group in domain_groups:
                    domain_groups[group].append(det2)
                    domain_to_group[id2] = group
            elif id2 in domain_to_group:
                # Add det1 to det2's group
                group = domain_to_group[id2]
                if group in domain_groups:
                    domain_groups[group].append(det1)
                    domain_to_group[id1] = group
            else:
                # Create new group
                group_id = next_group_id
                next_group_id += 1
                domain_groups[group_id] = [det1, det2]
                domain_to_group[id1] = group_id
                domain_to_group[id2] = group_id
        
        return list(domain_groups.values())
    
    def _merge_duplicate_groups(self, groups: List[List[PhishingDetection]]) -> List[List[PhishingDetection]]:
        """Merge overlapping duplicate groups"""
        if not groups:
            return []
        
        # Create a mapping of detection ID to groups
        detection_to_groups = {}
        for i, group in enumerate(groups):
            for detection in group:
                if detection.id not in detection_to_groups:
                    detection_to_groups[detection.id] = []
                detection_to_groups[detection.id].append(i)
        
        # Find connected components
        merged_groups = []
        processed_groups = set()
        
        for i, group in enumerate(groups):
            if i in processed_groups:
                continue
            
            # Find all groups connected to this one
            connected_groups = set([i])
            to_process = [i]
            
            while to_process:
                current_group = to_process.pop()
                for detection in groups[current_group]:
                    for connected_group in detection_to_groups[detection.id]:
                        if connected_group not in connected_groups:
                            connected_groups.add(connected_group)
                            to_process.append(connected_group)
            
            # Merge all connected groups
            merged_group = []
            for group_idx in connected_groups:
                merged_group.extend(groups[group_idx])
                processed_groups.add(group_idx)
            
            # Remove duplicates within merged group
            unique_detections = []
            seen_ids = set()
            for detection in merged_group:
                if detection.id not in seen_ids:
                    unique_detections.append(detection)
                    seen_ids.add(detection.id)
            
            merged_groups.append(unique_detections)
        
        return merged_groups
    
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
