from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime


# CSE Domain Schemas
class CSEDomainBase(BaseModel):
    sector: str
    organization_name: str
    domain: str


class CSEDomainCreate(CSEDomainBase):
    pass


class CSEDomainResponse(CSEDomainBase):
    id: int
    added_at: datetime
    is_active: bool
    
    class Config:
        from_attributes = True


# Phishing Detection Schemas
class PhishingDetectionResponse(BaseModel):
    id: int
    cse_domain_id: int
    phishing_domain: str
    variation_type: Optional[str]
    detected_at: datetime
    is_active: bool
    
    # Domain info
    domain_created_at: Optional[datetime]
    registrar: Optional[str]
    
    # Network info
    ip_address: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    hosting_isp: Optional[str]
    hosting_country: Optional[str]
    
    # SSL info
    ssl_issuer: Optional[str]
    ssl_valid_from: Optional[datetime]
    ssl_valid_to: Optional[datetime]
    
    # Analysis
    visual_similarity_score: float
    content_similarity_score: float
    has_login_form: bool
    has_payment_form: bool
    
    # Risk
    risk_score: float
    risk_level: Optional[str]
    
    # Files
    screenshot_path: Optional[str]
    report_path: Optional[str]
    
    # Relations
    legitimate_domain: Optional[str] = None
    organization_name: Optional[str] = None
    
    class Config:
        from_attributes = True


class PhishingDetectionDetail(PhishingDetectionResponse):
    """Extended response with all details"""
    subnet: Optional[str]
    registrant: Optional[str]
    mx_records: Optional[List]
    ns_records: Optional[List]
    ssl_issuer: Optional[str]
    ssl_valid_from: Optional[datetime]
    ssl_valid_to: Optional[datetime]
    cert_transparency_logs: Optional[List[Dict]]
    content_similarity_score: float
    in_phishtank: bool
    in_openphish: bool
    in_urlhaus: bool
    detection_metadata: Optional[Dict]
    last_checked: datetime


# Statistics
class DashboardStats(BaseModel):
    total_cse_domains: int
    total_phishing_detected: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    detections_today: int
    detections_this_week: int
    active_monitoring: bool


# Manual Check Request
class ManualCheckRequest(BaseModel):
    domain: str
    
    @validator('domain')
    def validate_domain(cls, v):
        v = v.strip().lower()
        # Remove protocol if present
        v = v.replace('https://', '').replace('http://', '')
        return v


# Bulk CSE Domain Import
class BulkCSEImport(BaseModel):
    domains: List[CSEDomainCreate]


class BulkCSEImportResult(BaseModel):
    added: List[CSEDomainResponse]
    skipped_existing: List[str]
    skipped_malicious: List[Dict[str, str]]
    total_added: int
    total_skipped: int
    message: str

