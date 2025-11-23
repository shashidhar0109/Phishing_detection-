from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from datetime import datetime, timedelta
import os
import time

from backend.database import get_db, init_db, engine
from backend.models import CSEDomain, PhishingDetection, ScanHistory, Base, MonitoringSchedule, ContentChangeLog
from backend.schemas import (
    CSEDomainCreate, CSEDomainResponse, PhishingDetectionResponse,
    PhishingDetectionDetail, DashboardStats, ManualCheckRequest, BulkCSEImport,
    BulkCSEImportResult
)
from backend.config import settings
from backend.monitoring_control import monitoring_controller
from backend.ps02_export import PS02Exporter
from backend.logging_config import log_system_startup, log_info

# Initialize database with error handling
try:
    from backend.database import init_db, test_connection
    init_db()
    
    # Test database connection
    if not test_connection():
        print("⚠️ Database connection test failed - some features may not work")
    
    # Log system startup
    log_system_startup()
except Exception as e:
    print(f"❌ Database initialization failed: {e}")
    print("⚠️ Starting with limited functionality - database features disabled")

# Create FastAPI app
app = FastAPI(
    title="Phishing Detection System",
    description="Critical Sector Entity Phishing Detection and Monitoring",
    version="1.0.0"
)

# List of allowed origins
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002"
]

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600
)

# CORS middleware to handle preflight and add CORS headers
@app.middleware("http")
async def add_cors_header(request: Request, call_next):
    # Get the origin from the request
    origin = request.headers.get("origin")
    
    # Handle preflight requests
    if request.method == "OPTIONS":
        response = Response(status_code=200)
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Max-Age"] = "600"
        return response
    
    # Process the request
    response = await call_next(request)
    
    # Add CORS headers to all responses if origin is allowed
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

# Socket.IO for real-time updates
# WebSocket support is handled by FastAPI directly

# Real-time features removed for stability


# ==================== Threat Intelligence Endpoints ====================
@app.get("/api/threat-intel/feeds")
async def get_threat_intel_feeds():
    """Get threat intelligence feed statistics"""
    try:
        from backend.threat_intelligence import ThreatIntelligenceGatherer
        ti_gatherer = ThreatIntelligenceGatherer()
        stats = ti_gatherer.get_feed_statistics()
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat intel feeds: {str(e)}")

@app.post("/api/threat-intel/check-domain")
async def check_domain_threat_intel(request: dict, db: Session = Depends(get_db)):
    """Check a specific domain against threat intelligence feeds"""
    try:
        domain = request.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        from backend.threat_intelligence import ThreatIntelligenceGatherer
        ti_gatherer = ThreatIntelligenceGatherer()
        ti_data = ti_gatherer.check_domain_in_feeds(domain)
        
        return {
            "success": True,
            "domain": domain,
            "threat_intel": {
                "in_phishtank": ti_data.in_phishtank,
                "in_openphish": ti_data.in_openphish,
                "in_urlhaus": ti_data.in_urlhaus,
                "blacklist_hits": ti_data.blacklist_hits,
                "enrichment_data": ti_data.enrichment_data
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check domain: {str(e)}")

@app.post("/api/threat-intel/process-detections")
async def process_detections_threat_intel(request: dict, db: Session = Depends(get_db)):
    """Process new detections with threat intelligence"""
    try:
        limit = request.get("limit", 100)
        
        from backend.threat_intelligence import ThreatIntelProcessor
        processor = ThreatIntelProcessor(db)
        updated_count = processor.process_new_detections(limit)
        
        return {
            "success": True,
            "updated_detections": updated_count,
            "message": f"Processed {updated_count} detections with threat intelligence"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process detections: {str(e)}")

# ==================== Queue Processing Endpoints ====================
@app.post("/api/queue/add-domain")
async def add_domain_to_queue(request: dict, db: Session = Depends(get_db)):
    """Add a domain to the processing queue"""
    try:
        domain = request.get("domain")
        cse_domain = request.get("cse_domain", "")
        priority = request.get("priority", 1)
        
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        job_id = processor.add_domain_job(domain, cse_domain, priority)
        
        return {
            "success": True,
            "job_id": job_id,
            "message": f"Domain {domain} added to processing queue"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add domain to queue: {str(e)}")

@app.post("/api/queue/add-batch")
async def add_batch_to_queue(request: dict, db: Session = Depends(get_db)):
    """Add multiple domains to the processing queue"""
    try:
        domains = request.get("domains", [])
        priority = request.get("priority", 1)
        
        if not domains:
            raise HTTPException(status_code=400, detail="Domains list is required")
        
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        job_ids = processor.add_batch_jobs(domains, priority)
        
        return {
            "success": True,
            "job_ids": job_ids,
            "message": f"Added {len(job_ids)} domains to processing queue"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add batch to queue: {str(e)}")

@app.get("/api/queue/status")
async def get_queue_status(db: Session = Depends(get_db)):
    """Get queue processing status"""
    try:
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        status = processor.get_queue_status()
        return {"success": True, "data": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get queue status: {str(e)}")

@app.get("/api/queue/job/{job_id}")
async def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Get status of a specific job"""
    try:
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        job_status = processor.get_job_status(job_id)
        
        if not job_status:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return {"success": True, "data": job_status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")

@app.get("/api/queue/recent-jobs")
async def get_recent_jobs(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    """Get recent processing jobs"""
    try:
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        jobs = processor.get_recent_jobs(limit)
        return {"success": True, "data": jobs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get recent jobs: {str(e)}")

@app.get("/api/queue/metrics")
async def get_processing_metrics(db: Session = Depends(get_db)):
    """Get processing performance metrics"""
    try:
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        metrics = processor.get_processing_metrics()
        return {"success": True, "data": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get processing metrics: {str(e)}")

@app.post("/api/queue/start")
async def start_queue_processing(db: Session = Depends(get_db)):
    """Start queue processing"""
    try:
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        processor.start_processing()
        return {"success": True, "message": "Queue processing started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start queue processing: {str(e)}")

@app.post("/api/queue/stop")
async def stop_queue_processing(db: Session = Depends(get_db)):
    """Stop queue processing"""
    try:
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        processor.stop_processing()
        return {"success": True, "message": "Queue processing stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop queue processing: {str(e)}")

@app.post("/api/queue/cleanup")
async def cleanup_old_jobs(request: dict, db: Session = Depends(get_db)):
    """Clean up old completed jobs"""
    try:
        older_than_hours = request.get("older_than_hours", 24)
        
        from backend.queue_processor import QueueProcessor
        processor = QueueProcessor(db)
        removed_count = processor.clear_completed_jobs(older_than_hours)
        
        return {
            "success": True,
            "removed_jobs": removed_count,
            "message": f"Cleaned up {removed_count} old jobs"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup old jobs: {str(e)}")

# ==================== Root Endpoint ====================
@app.get("/")
async def root():
    return {
        "message": "Phishing Detection System API",
        "version": "1.0.0",
        "docs": "/docs"
    }


# ==================== CSE Domain Endpoints ====================
@app.get("/api/cse-domains", response_model=List[CSEDomainResponse])
async def get_cse_domains(
    skip: int = 0,
    limit: int = 50,  # Reduced default limit
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """Get list of CSE domains with pagination"""
    query = db.query(CSEDomain)
    if active_only:
        query = query.filter(CSEDomain.is_active == True)
    
    # Add ordering for consistent pagination
    query = query.order_by(CSEDomain.added_at.desc())
    
    domains = query.offset(skip).limit(limit).all()
    return domains


@app.post("/api/cse-domains", response_model=CSEDomainResponse)
async def add_cse_domain(
    domain_data: CSEDomainCreate,
    db: Session = Depends(get_db)
):
    """Add a new CSE domain for monitoring"""
    from backend.intelligence import IntelligenceGatherer
    
    # Get all existing CSE domains to check for typosquatting
    all_existing_domains = db.query(CSEDomain).filter(CSEDomain.is_active == True).all()
    existing_domain_list = [d.domain for d in all_existing_domains]
    
    # CHECK FOR MALICIOUS/TYPOSQUATTING FIRST (before checking if exists)
    # This ensures we show the RIGHT error message
    gatherer = IntelligenceGatherer()
    malicious_check = gatherer.is_domain_malicious(
        domain_data.domain, 
        existing_cse_domains=existing_domain_list
    )
    
    if malicious_check['is_malicious']:
        # Format the error message nicely
        reason = malicious_check['reason']
        
        # Make typosquatting messages clearer
        if 'TYPOSQUATTING' in reason or 'typosquatting' in reason.lower():
            # Extract the brand name if possible
            if malicious_check.get('typosquatting_target'):
                target = malicious_check['typosquatting_target']
                detail_msg = f"⚠️ TYPOSQUATTING DETECTED\n\n" \
                           f"The domain '{domain_data.domain}' appears to be a typosquatting variant of '{target}'.\n\n" \
                           f"This domain cannot be added because it mimics an existing legitimate domain.\n\n" \
                           f"If you believe this is an error, please verify the correct domain spelling."
            else:
                detail_msg = reason
        else:
            detail_msg = reason
        
        raise HTTPException(status_code=400, detail=detail_msg)
    
    # THEN check if domain already exists AND is active (only if it passed validation)
    existing_active = db.query(CSEDomain).filter(
        CSEDomain.domain == domain_data.domain,
        CSEDomain.is_active == True
    ).first()
    
    if existing_active:
        raise HTTPException(status_code=400, detail="This domain is already being monitored")
    
    # Check if domain exists but is inactive
    # If it exists as inactive, it means it was deleted/deactivated for a reason
    # So we should NOT allow re-adding it (especially if it's malicious)
    existing_inactive = db.query(CSEDomain).filter(
        CSEDomain.domain == domain_data.domain,
        CSEDomain.is_active == False
    ).first()
    
    if existing_inactive:
        # Domain was previously deactivated - don't allow re-adding
        raise HTTPException(
            status_code=400, 
            detail="This domain was previously removed from monitoring and cannot be re-added. If this is a legitimate domain, please contact the administrator."
        )
    
    # Create new domain
    new_domain = CSEDomain(**domain_data.dict())
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)
    
    # Real-time notification removed for stability
    
    return new_domain


@app.post("/api/cse-domains/bulk", response_model=BulkCSEImportResult)
async def bulk_add_cse_domains(
    bulk_data: BulkCSEImport,
    db: Session = Depends(get_db)
):
    """Bulk add CSE domains - ULTRA FAST VERSION (No scanning during upload)"""
    
    added_domain_objs = []
    skipped_existing = []
    
    try:
        for domain_data in bulk_data.domains:
            # Check if exists
            existing = db.query(CSEDomain).filter(
                CSEDomain.domain == domain_data.domain
            ).first()
            
            if existing:
                skipped_existing.append(domain_data.domain)
                continue
            
            # Add the domain directly (no scanning, no malicious checks)
            new_domain = CSEDomain(
                domain=domain_data.domain,
                organization_name=domain_data.organization_name,
                sector=domain_data.sector,
                added_at=datetime.utcnow(),
                is_active=True
            )
            db.add(new_domain)
            added_domain_objs.append(new_domain)
        
        db.commit()
        
        # Refresh all added domains to populate IDs
        for domain_obj in added_domain_objs:
            db.refresh(domain_obj)
        
        # Convert to response format using from_attributes
        added_responses = [CSEDomainResponse.model_validate(obj) for obj in added_domain_objs]
        
        return BulkCSEImportResult(
            added=added_responses,
            skipped_existing=skipped_existing,
            skipped_malicious=[],  # No malicious checking during upload
            total_added=len(added_domain_objs),
            total_skipped=len(skipped_existing),
            message=f"Successfully added {len(added_domain_objs)} domains (scanning will happen when monitoring starts)"
        )
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.post("/api/domains/bulk-with-screening")
async def bulk_add_with_screening(
    bulk_data: BulkCSEImport,
    db: Session = Depends(get_db)
):
    """
    NEW: Bulk add with pre-screening
    Classifies each domain as MALICIOUS or CSE before processing
    """
    from backend.input_classifier import InputDomainClassifier
    
    classifier = InputDomainClassifier()
    
    results = {
        'total': len(bulk_data.domains),
        'malicious_count': 0,
        'cse_count': 0,
        'skipped_existing': 0,
        'threats': [],
        'cse_domains': []
    }
    
    try:
        for domain_data in bulk_data.domains:
            domain = domain_data.domain
            
            # STEP 1: Classify domain
            classification, confidence, reason = classifier.classify(domain)
            
            if classification == 'MALICIOUS':
                # Add directly to phishing_detections (threats)
                detection = PhishingDetection(
                    phishing_domain=domain,
                    cse_domain_id=None,
                    risk_level='HIGH',
                    risk_score=int(confidence * 100),
                    detection_method='INPUT_SCREENING',
                    visual_similarity_score=0,
                    content_similarity_score=0,
                    detected_at=datetime.utcnow(),
                    is_active=True
                )
                db.add(detection)
                
                results['threats'].append({
                    'domain': domain,
                    'confidence': round(confidence * 100, 1),
                    'reason': reason
                })
                results['malicious_count'] += 1
                
            else:  # CSE
                # Check if already exists
                existing = db.query(CSEDomain).filter(CSEDomain.domain == domain).first()
                if existing:
                    results['skipped_existing'] += 1
                    continue
                
                # Add to cse_domains (legitimate to protect)
                cse = CSEDomain(
                    domain=domain,
                    organization_name=domain_data.organization_name or 'Auto-detected',
                    sector=domain_data.sector or 'Unknown',
                    added_at=datetime.utcnow(),
                    is_active=True
                )
                db.add(cse)
                
                results['cse_domains'].append({
                    'domain': domain,
                    'confidence': round(confidence * 100, 1),
                    'reason': reason
                })
                results['cse_count'] += 1
        
        db.commit()
        
        results['message'] = (
            f"Screening complete: {results['malicious_count']} threats detected, "
            f"{results['cse_count']} CSE domains added, "
            f"{results['skipped_existing']} duplicates skipped"
        )
        
        return results
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.delete("/api/cse-domains/{domain_id}")
async def delete_cse_domain(
    domain_id: int,
    db: Session = Depends(get_db)
):
    """Delete (deactivate) a CSE domain"""
    domain = db.query(CSEDomain).filter(CSEDomain.id == domain_id).first()
    
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    domain.is_active = False
    db.commit()
    
    return {"message": "Domain deactivated successfully"}


# ==================== Phishing Detection Endpoints ====================
@app.get("/api/phishing-detections", response_model=List[PhishingDetectionResponse])
async def get_phishing_detections(
    skip: int = 0,
    limit: int = 1000,  # Reasonable limit for dashboard performance
    risk_level: Optional[str] = None,
    cse_domain_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get list of detected phishing sites"""
    query = db.query(PhishingDetection).filter(PhishingDetection.is_active == True)
    
    if risk_level:
        query = query.filter(PhishingDetection.risk_level == risk_level.upper())
    
    if cse_domain_id:
        query = query.filter(PhishingDetection.cse_domain_id == cse_domain_id)
    
    # Order by detection date (newest first)
    query = query.order_by(PhishingDetection.detected_at.desc())
    
    detections = query.offset(skip).limit(limit).all()
    
    # Enrich with CSE domain info
    result = []
    for detection in detections:
        detection_dict = detection.__dict__
        if detection.cse_domain:
            detection_dict['legitimate_domain'] = detection.cse_domain.domain
            detection_dict['organization_name'] = detection.cse_domain.organization_name
        result.append(PhishingDetectionResponse(**detection_dict))
    
    return result


@app.get("/api/phishing-detections/all-for-trend")
async def get_all_detections_for_trend(db: Session = Depends(get_db)):
    """Get all detections for trend analysis (optimized for chart)"""
    try:
        detections = db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True
        ).order_by(PhishingDetection.detected_at.desc()).all()
        
        # Return minimal data for trend analysis - ensure it's always an array
        result = []
        for detection in detections:
            result.append({
                "id": detection.id,
                "detected_at": detection.detected_at.isoformat() if detection.detected_at else None,
                "risk_level": detection.risk_level,
                "phishing_domain": detection.phishing_domain
            })
        
        # Ensure we always return an array, even if empty
        return result if result else []
    except Exception as e:
        # Return empty array on error to prevent frontend crashes
        return []


@app.get("/api/phishing-detections/{detection_id}", response_model=PhishingDetectionDetail)
async def get_phishing_detection(
    detection_id: int,
    db: Session = Depends(get_db)
):
    """Get detailed information about a phishing detection"""
    detection = db.query(PhishingDetection).filter(
        PhishingDetection.id == detection_id
    ).first()
    
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    detection_dict = detection.__dict__
    if detection.cse_domain:
        detection_dict['legitimate_domain'] = detection.cse_domain.domain
        detection_dict['organization_name'] = detection.cse_domain.organization_name
    
    return PhishingDetectionDetail(**detection_dict)


@app.delete("/api/phishing-detections/{detection_id}")
async def delete_phishing_detection(
    detection_id: int,
    db: Session = Depends(get_db)
):
    """Delete a phishing detection"""
    detection = db.query(PhishingDetection).filter(
        PhishingDetection.id == detection_id
    ).first()
    
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    # Soft delete by setting is_active to False
    detection.is_active = False
    db.commit()
    
    return {"message": "Detection deleted successfully"}


@app.get("/api/reports/{detection_id}/download")
async def download_report(
    detection_id: int,
    db: Session = Depends(get_db)
):
    """Download PDF report for a detection"""
    detection = db.query(PhishingDetection).filter(
        PhishingDetection.id == detection_id
    ).first()
    
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    if not detection.report_path or not os.path.exists(detection.report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        detection.report_path,
        media_type='application/pdf',
        filename=f"phishing_report_{detection_id}.pdf"
    )


@app.get("/api/screenshots/{detection_id}")
async def get_screenshot(
    detection_id: int,
    db: Session = Depends(get_db)
):
    """Get screenshot for a detection"""
    detection = db.query(PhishingDetection).filter(
        PhishingDetection.id == detection_id
    ).first()
    
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    if not detection.screenshot_path:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    # Handle relative paths
    screenshot_path = detection.screenshot_path
    if screenshot_path.startswith('./'):
        screenshot_path = os.path.join(os.getcwd(), screenshot_path[2:])
    
    if not os.path.exists(screenshot_path):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    return FileResponse(screenshot_path)


# ==================== Statistics Endpoints ====================
# Simple in-memory cache for stats
_stats_cache = {}
_cache_timestamp = 0
CACHE_DURATION = 300  # 5 minutes

@app.get("/api/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics with caching"""
    global _stats_cache, _cache_timestamp
    
    current_time = time.time()
    
    # Return cached data if it's still fresh (disabled for real-time data)
    # if current_time - _cache_timestamp < CACHE_DURATION and _stats_cache:
    #     return DashboardStats(**_stats_cache)
    
    try:
        # Optimized single query approach
        today = datetime.now().date()
        week_ago = datetime.now() - timedelta(days=7)
        
        # Get all stats in fewer queries
        total_cse = db.query(CSEDomain).filter(CSEDomain.is_active == True).count()
        
        # Get phishing stats with simpler queries to avoid case statement issues
        total_phishing = db.query(PhishingDetection).filter(PhishingDetection.is_active == True).count()
        high_risk = db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True,
            PhishingDetection.risk_level == 'HIGH'
        ).count()
        medium_risk = db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True,
            PhishingDetection.risk_level == 'MEDIUM'
        ).count()
        low_risk = db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True,
            PhishingDetection.risk_level == 'LOW'
        ).count()
        today_detections = db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True,
            PhishingDetection.detected_at >= today
        ).count()
        week_detections = db.query(PhishingDetection).filter(
            PhishingDetection.is_active == True,
            PhishingDetection.detected_at >= week_ago
        ).count()
        
        stats_data = {
            'total_cse_domains': total_cse,
            'total_phishing_detected': total_phishing,
            'high_risk_count': high_risk,
            'medium_risk_count': medium_risk,
            'low_risk_count': low_risk,
            'detections_today': today_detections,
            'detections_this_week': week_detections,
            'active_monitoring': monitoring_controller.get_status()["monitoring_active"]
        }
        
        # Cache the results
        _stats_cache = stats_data
        _cache_timestamp = current_time
        
        return DashboardStats(**stats_data)
        
    except Exception as e:
        print(f"Error in stats calculation: {e}")
        # Return cached data or minimal stats on error
        if _stats_cache:
            return DashboardStats(**_stats_cache)
    return DashboardStats(
            total_cse_domains=0,
            total_phishing_detected=0,
            high_risk_count=0,
            medium_risk_count=0,
            low_risk_count=0,
            detections_today=0,
            detections_this_week=0,
            active_monitoring=monitoring_controller.get_status()["monitoring_active"]
        )


# ==================== Domain Update Endpoint ====================
@app.post("/api/cse-domains/update-sectors")
async def update_domain_sectors(db: Session = Depends(get_db)):
    """Update sectors for domains that have 'Unknown' sector"""
    try:
        # Get all domains with Unknown sector
        unknown_domains = db.query(CSEDomain).filter(CSEDomain.sector == "Unknown").all()
        
        updated_count = 0
        for domain in unknown_domains:
            # Categorize the domain
            domain_lower = domain.domain.lower()
            
            # Banking and Financial Services
            if ('bank' in domain_lower or 'sbi' in domain_lower or 'hdfc' in domain_lower or 
                'icici' in domain_lower or 'pnb' in domain_lower or 'bob' in domain_lower or
                'axis' in domain_lower or 'kotak' in domain_lower or 'yes' in domain_lower or
                'union' in domain_lower or 'canara' in domain_lower or 'indian' in domain_lower or
                'paytm' in domain_lower or 'phonepe' in domain_lower or 'gpay' in domain_lower or
                'paypal' in domain_lower or 'razorpay' in domain_lower or 'cashfree' in domain_lower):
                domain.sector = 'BFSI'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Banking/Financial Services'
                updated_count += 1
            # Government
            elif ('.gov' in domain_lower or 'nic' in domain_lower or 'india' in domain_lower or
                  'ministry' in domain_lower or 'department' in domain_lower or 'portal' in domain_lower):
                domain.sector = 'Government'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Government of India'
                updated_count += 1
            # E-commerce
            elif ('shop' in domain_lower or 'store' in domain_lower or 'market' in domain_lower or
                  'amazon' in domain_lower or 'flipkart' in domain_lower or 'myntra' in domain_lower or
                  'snapdeal' in domain_lower or 'nykaa' in domain_lower or 'zomato' in domain_lower or
                  'swiggy' in domain_lower or 'uber' in domain_lower or 'ola' in domain_lower):
                domain.sector = 'E-commerce'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'E-commerce Platform'
                updated_count += 1
            # Telecom
            elif ('airtel' in domain_lower or 'jio' in domain_lower or 'vi' in domain_lower or
                  'bsnl' in domain_lower or 'vodafone' in domain_lower or 'idea' in domain_lower):
                domain.sector = 'Telecom'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Telecom Service Provider'
                updated_count += 1
            # Healthcare
            elif ('health' in domain_lower or 'medical' in domain_lower or 'hospital' in domain_lower or
                  'pharma' in domain_lower or 'medicine' in domain_lower or 'doctor' in domain_lower):
                domain.sector = 'Healthcare'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Healthcare Provider'
                updated_count += 1
            # Education
            elif ('edu' in domain_lower or 'university' in domain_lower or 'college' in domain_lower or
                  'school' in domain_lower or 'institute' in domain_lower or 'academy' in domain_lower):
                domain.sector = 'Education'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Educational Institution'
                updated_count += 1
            # Technology
            elif ('tech' in domain_lower or 'software' in domain_lower or 'it' in domain_lower or
                  'digital' in domain_lower or 'app' in domain_lower or 'cloud' in domain_lower):
                domain.sector = 'Technology'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Technology Company'
                updated_count += 1
            # Default categorization based on TLD
            elif domain_lower.endswith('.gov.in') or domain_lower.endswith('.nic.in'):
                domain.sector = 'Government'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Government of India'
                updated_count += 1
            elif domain_lower.endswith('.edu') or domain_lower.endswith('.ac.in'):
                domain.sector = 'Education'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Educational Institution'
                updated_count += 1
            elif domain_lower.endswith('.org') or domain_lower.endswith('.org.in'):
                domain.sector = 'Non-Profit'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Non-Profit Organization'
                updated_count += 1
            else:
                domain.sector = 'Other'
                if domain.organization_name == 'Unknown':
                    domain.organization_name = 'Other Organization'
                updated_count += 1
        
        db.commit()
        return {"message": f"Updated {updated_count} domains with proper sectors", "updated_count": updated_count}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update domains: {str(e)}")


# ==================== Manual Check Endpoint ====================
@app.post("/api/manual-check")
async def manual_check_domain(
    request: ManualCheckRequest,
    db: Session = Depends(get_db)
):
    """Manually check if a domain is a phishing site"""
    from backend.worker import check_single_domain
    
    # Trigger async check
    result = check_single_domain.delay(request.domain)
    
    return {
        "message": "Domain check initiated",
        "domain": request.domain,
        "task_id": result.id
    }


# WebSocket endpoint removed for stability


# ==================== Monitoring Control Endpoints ====================
@app.post("/api/monitoring/start")
async def start_monitoring():
    """Start background monitoring (workers)"""
    try:
        result = monitoring_controller.start_monitoring()
        
        # Real-time notification removed for stability
        
        return result
    except Exception as e:
        # Real-time error notification removed for stability
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {str(e)}")


@app.post("/api/monitoring/stop")
async def stop_monitoring():
    """Stop background monitoring (workers)"""
    try:
        result = monitoring_controller.stop_monitoring()
        
        # Real-time notification removed for stability
        
        return result
    except Exception as e:
        # Real-time error notification removed for stability
        raise HTTPException(status_code=500, detail=f"Failed to stop monitoring: {str(e)}")


@app.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get monitoring status"""
    return monitoring_controller.get_status()


# ==================== PS-02 Export Endpoints ====================
@app.post("/api/export/ps02-submission")
async def export_ps02_submission(
    request: dict,
    db: Session = Depends(get_db)
):
    """Generate PS-02 submission package"""
    try:
        application_id = request.get("application_id", "AIGR-108366")
        participant_id = request.get("participant_id", "AIGR-S82274")
        
        # Import here to avoid circular imports
        from backend.ps02_export_final import PS02ExporterFinal
        
        # Create exporter and generate package
        exporter = PS02ExporterFinal(db)
        zip_path = exporter.generate_submission_package(application_id, participant_id)
        
        # Return the file path for download
        return {
            "success": True,
            "message": "PS-02 submission package generated successfully",
            "application_id": application_id,
            "participant_id": participant_id,
            "file_path": zip_path,
            "download_url": f"/api/download/{os.path.basename(zip_path)}"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate submission package: {str(e)}")


@app.get("/api/download/{filename}")
async def download_file(filename: str):
    """Download generated files"""
    try:
        # Security check - only allow specific file types
        if not filename.endswith(('.zip', '.xlsx', '.pdf')):
            raise HTTPException(status_code=400, detail="Invalid file type")
        
        # Look for the file in ps02_submissions directory
        from pathlib import Path
        file_path = Path("./ps02_submissions") / filename
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileResponse(
            path=str(file_path),
            filename=filename,
            media_type='application/zip' if filename.endswith('.zip') else 'application/octet-stream'
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download file: {str(e)}")


# ==================== Long-term Monitoring Endpoints ====================

@app.post("/api/monitoring/schedule")
async def create_monitoring_schedule(
    domain: str,
    cse_domain_id: int,
    duration_days: Optional[int] = None,
    risk_level: str = "MEDIUM",
    db: Session = Depends(get_db)
):
    """Create a new long-term monitoring schedule for a domain"""
    try:
        from backend.worker import create_monitoring_schedule
        
        # Validate CSE domain exists
        cse_domain = db.query(CSEDomain).filter(CSEDomain.id == cse_domain_id).first()
        if not cse_domain:
            raise HTTPException(status_code=404, detail="CSE domain not found")
        
        # Create monitoring schedule
        result = create_monitoring_schedule.delay(domain, cse_domain_id, duration_days, risk_level)
        task_result = result.get(timeout=30)
        
        if task_result['status'] == 'already_monitored':
            raise HTTPException(status_code=400, detail=f"Domain {domain} is already being monitored")
        elif task_result['status'] == 'failed':
            raise HTTPException(status_code=500, detail=task_result['error'])
        
        return task_result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create monitoring schedule: {str(e)}")


@app.get("/api/monitoring/schedules")
async def get_monitoring_schedules(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    active_only: bool = Query(True),
    db: Session = Depends(get_db)
):
    """Get monitoring schedules"""
    try:
        query = db.query(MonitoringSchedule)
        
        if active_only:
            query = query.filter(MonitoringSchedule.is_active == True)
        
        schedules = query.offset(skip).limit(limit).all()
        
        return {
            "schedules": [
                {
                    "id": s.id,
                    "domain": s.domain,
                    "cse_domain_id": s.cse_domain_id,
                    "monitoring_duration_days": s.monitoring_duration_days,
                    "start_date": s.start_date,
                    "end_date": s.end_date,
                    "is_active": s.is_active,
                    "monitoring_interval_hours": s.monitoring_interval_hours,
                    "last_checked": s.last_checked,
                    "next_check": s.next_check,
                    "risk_level": s.risk_level,
                    "created_at": s.created_at
                }
                for s in schedules
            ],
            "total": query.count()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get monitoring schedules: {str(e)}")


@app.delete("/api/monitoring/schedules/{schedule_id}")
async def deactivate_monitoring_schedule(
    schedule_id: int,
    db: Session = Depends(get_db)
):
    """Deactivate a monitoring schedule"""
    try:
        schedule = db.query(MonitoringSchedule).filter(MonitoringSchedule.id == schedule_id).first()
        if not schedule:
            raise HTTPException(status_code=404, detail="Monitoring schedule not found")
        
        schedule.is_active = False
        schedule.updated_at = datetime.utcnow()
        db.commit()
        
        return {"status": "deactivated", "schedule_id": schedule_id}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to deactivate monitoring schedule: {str(e)}")


@app.get("/api/monitoring/content-changes")
async def get_content_changes(
    domain: Optional[str] = None,
    change_type: Optional[str] = None,
    days: int = Query(30, ge=1, le=365),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get content change logs"""
    try:
        query = db.query(ContentChangeLog)
        
        # Filter by domain
        if domain:
            query = query.filter(ContentChangeLog.domain == domain)
        
        # Filter by change type
        if change_type:
            query = query.filter(ContentChangeLog.change_type == change_type)
        
        # Filter by date range
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(ContentChangeLog.detected_at >= start_date)
        
        changes = query.order_by(ContentChangeLog.detected_at.desc()).offset(skip).limit(limit).all()
        
        return {
            "changes": [
                {
                    "id": c.id,
                    "domain": c.domain,
                    "detection_id": c.detection_id,
                    "change_type": c.change_type,
                    "change_percentage": c.change_percentage,
                    "change_details": c.change_details,
                    "detected_at": c.detected_at,
                    "screenshot_before": c.screenshot_before,
                    "screenshot_after": c.screenshot_after
                }
                for c in changes
            ],
            "total": query.count()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get content changes: {str(e)}")


@app.get("/api/monitoring/statistics")
async def get_monitoring_statistics():
    """Get monitoring statistics"""
    try:
        from backend.worker import get_monitoring_statistics
        
        result = get_monitoring_statistics.delay()
        task_result = result.get(timeout=30)
        
        if task_result['status'] == 'failed':
            raise HTTPException(status_code=500, detail=task_result['error'])
        
        return task_result['statistics']
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get monitoring statistics: {str(e)}")


@app.post("/api/monitoring/trigger-check")
async def trigger_manual_monitoring_check(
    domain: str,
    db: Session = Depends(get_db)
):
    """Manually trigger a monitoring check for a domain"""
    try:
        from backend.long_term_monitor import LongTermMonitor
        
        # Find the monitoring schedule
        schedule = db.query(MonitoringSchedule).filter(
            MonitoringSchedule.domain == domain,
            MonitoringSchedule.is_active == True
        ).first()
        
        if not schedule:
            raise HTTPException(status_code=404, detail=f"No active monitoring schedule found for {domain}")
        
        # Trigger monitoring
        monitor = LongTermMonitor()
        result = monitor.monitor_domain(schedule)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to trigger monitoring check: {str(e)}")


# ==================== Utility function ====================
async def notify_new_detection(detection_data: dict):
    """Real-time notification removed for stability"""
    pass


# Export the socket app for uvicorn
# WebSocket is handled by FastAPI directly at /ws endpoint

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

