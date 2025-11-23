from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base


class CSEDomain(Base):
    """Critical Sector Entity legitimate domains"""
    __tablename__ = "cse_domains"
    
    id = Column(Integer, primary_key=True, index=True)
    sector = Column(String, nullable=False)
    organization_name = Column(String, nullable=False)
    domain = Column(String, unique=True, nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationship
    phishing_detections = relationship("PhishingDetection", back_populates="cse_domain")


class PhishingDetection(Base):
    """Detected phishing sites"""
    __tablename__ = "phishing_detections"
    
    id = Column(Integer, primary_key=True, index=True)
    cse_domain_id = Column(Integer, ForeignKey("cse_domains.id"))
    
    # Domain Information
    phishing_domain = Column(String, nullable=False, index=True)
    variation_type = Column(String)  # typosquatting, combosquatting, etc.
    
    # Detection Information
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    last_checked = Column(DateTime, default=datetime.utcnow)
    
    # Domain Intelligence (WHOIS)
    domain_created_at = Column(DateTime, nullable=True)  # PS-02: Domain Registration Date
    registrar = Column(String, nullable=True)  # PS-02: Registrar Name
    registrant = Column(Text, nullable=True)  # PS-02: Registrant Name
    registrant_organization = Column(String, nullable=True)  # PS-02: Registrant Organisation
    registrant_country = Column(String, nullable=True)  # PS-02: Registrant Country
    
    # Network Information
    ip_address = Column(String, nullable=True)  # PS-02: Hosting IP
    subnet = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    country = Column(String, nullable=True)  # Detection country (geolocation)
    hosting_isp = Column(String, nullable=True)  # PS-02: Hosting ISP
    hosting_country = Column(String, nullable=True)  # PS-02: Hosting Country
    
    # DNS Records
    mx_records = Column(JSON, nullable=True)
    ns_records = Column(JSON, nullable=True)  # PS-02: Name Servers
    name_servers = Column(Text, nullable=True)  # PS-02: Name Servers (text format)
    dns_records = Column(JSON, nullable=True)  # PS-02: All DNS Records
    dns_records_text = Column(Text, nullable=True)  # PS-02: DNS Records as text
    
    # SSL/Certificate
    ssl_issuer = Column(String, nullable=True)
    ssl_valid_from = Column(DateTime, nullable=True)
    ssl_valid_to = Column(DateTime, nullable=True)
    cert_transparency_logs = Column(JSON, nullable=True)
    
    # Analysis Results
    visual_similarity_score = Column(Float, default=0.0)
    content_similarity_score = Column(Float, default=0.0)
    has_login_form = Column(Boolean, default=False)
    has_payment_form = Column(Boolean, default=False)
    
    # External Verification
    in_phishtank = Column(Boolean, default=False)
    in_openphish = Column(Boolean, default=False)
    in_urlhaus = Column(Boolean, default=False)
    
    # Risk Assessment
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String)  # HIGH, MEDIUM, LOW
    
    # Files
    screenshot_path = Column(String, nullable=True)
    report_path = Column(String, nullable=True)
    evidence_pdf_path = Column(String, nullable=True)  # PS-02: Evidence PDF file path
    
    # Detection Source & Method (PS-02)
    source_of_detection = Column(String, nullable=True)  # typosquatting, social_media, subdomain, etc.
    detection_method = Column(String, nullable=True)  # How it was detected
    social_media_post_date = Column(DateTime, nullable=True)  # PS-02: If from social media
    social_media_platform = Column(String, nullable=True)  # twitter, facebook, etc.
    social_media_post_url = Column(String, nullable=True)  # Link to original post
    
    # Metadata
    detection_metadata = Column(JSON, nullable=True)
    
    # Relationship
    cse_domain = relationship("CSEDomain", back_populates="phishing_detections")


class DomainVariation(Base):
    """Generated domain variations for monitoring"""
    __tablename__ = "domain_variations"
    
    id = Column(Integer, primary_key=True, index=True)
    cse_domain_id = Column(Integer, ForeignKey("cse_domains.id"))
    variation = Column(String, unique=True, nullable=False, index=True)
    variation_type = Column(String)
    is_registered = Column(Boolean, default=False)
    last_checked = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanHistory(Base):
    """Audit trail of scans"""
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String)  # full_scan, quick_check, manual_check
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    domains_checked = Column(Integer, default=0)
    phishing_found = Column(Integer, default=0)
    status = Column(String)  # running, completed, failed
    error_message = Column(Text, nullable=True)


class Report(Base):
    """Generated PDF reports metadata"""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    phishing_detection_id = Column(Integer, ForeignKey("phishing_detections.id"))
    report_path = Column(String, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    file_size = Column(Integer)


class MonitoringSchedule(Base):
    """Long-term monitoring schedule for suspected domains"""
    __tablename__ = "monitoring_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    cse_domain_id = Column(Integer, ForeignKey("cse_domains.id"))
    monitoring_duration_days = Column(Integer, default=90)
    start_date = Column(DateTime, default=datetime.utcnow)
    end_date = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    monitoring_interval_hours = Column(Integer, default=24)
    last_checked = Column(DateTime, nullable=True)
    next_check = Column(DateTime, nullable=True)
    risk_level = Column(String, default="MEDIUM")  # HIGH, MEDIUM, LOW
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ContentChangeLog(Base):
    """Log of content changes in monitored domains"""
    __tablename__ = "content_change_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    detection_id = Column(Integer, ForeignKey("phishing_detections.id"))
    change_type = Column(String, nullable=False)  # content_change, binary_hosting, lookalike_content
    previous_content_hash = Column(String, nullable=True)
    current_content_hash = Column(String, nullable=True)
    change_percentage = Column(Float, nullable=True)
    change_details = Column(JSON, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)
    screenshot_before = Column(String, nullable=True)
    screenshot_after = Column(String, nullable=True)

