"""
Comprehensive logging configuration for Phishing Detection System
Logs all monitoring activities, scans, detections, and errors
"""

import logging
import os
from datetime import datetime
from pathlib import Path

# Create logs directory if it doesn't exist
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Define log file paths
MONITORING_LOG = LOGS_DIR / "monitoring.log"
SCAN_LOG = LOGS_DIR / "scan_activity.log"
DETECTION_LOG = LOGS_DIR / "detections.log"
ERROR_LOG = LOGS_DIR / "errors.log"
PERFORMANCE_LOG = LOGS_DIR / "performance.log"

# Custom formatter with timestamp
class DetailedFormatter(logging.Formatter):
    """Custom formatter with detailed information"""
    
    def format(self, record):
        # Add timestamp
        record.timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Format based on log level
        if record.levelno == logging.INFO:
            prefix = "ℹ️ "
        elif record.levelno == logging.WARNING:
            prefix = "⚠️ "
        elif record.levelno == logging.ERROR:
            prefix = "❌"
        elif record.levelno == logging.CRITICAL:
            prefix = "🚨"
        else:
            prefix = "✅"
        
        record.prefix = prefix
        return super().format(record)


def setup_logger(name, log_file, level=logging.INFO):
    """Setup a logger with file and console handlers"""
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers = []
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_formatter = DetailedFormatter(
        '%(timestamp)s | %(prefix)s %(levelname)-8s | %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = DetailedFormatter(
        '%(prefix)s [%(name)s] %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger


# Create specialized loggers
monitoring_logger = setup_logger('monitoring', MONITORING_LOG)
scan_logger = setup_logger('scan', SCAN_LOG)
detection_logger = setup_logger('detection', DETECTION_LOG)
error_logger = setup_logger('error', ERROR_LOG, level=logging.ERROR)
performance_logger = setup_logger('performance', PERFORMANCE_LOG)


def log_monitoring_cycle_start(scan_id, cse_domains_count):
    """Log the start of a monitoring cycle"""
    monitoring_logger.info("=" * 80)
    monitoring_logger.info(f"🔄 MONITORING CYCLE STARTED - Scan ID: {scan_id}")
    monitoring_logger.info(f"📋 Active CSE Domains to Monitor: {cse_domains_count}")
    monitoring_logger.info("=" * 80)


def log_monitoring_cycle_end(scan_id, domains_checked, detections_found, duration):
    """Log the end of a monitoring cycle"""
    monitoring_logger.info("=" * 80)
    monitoring_logger.info(f"✅ MONITORING CYCLE COMPLETED - Scan ID: {scan_id}")
    monitoring_logger.info(f"📊 Summary:")
    monitoring_logger.info(f"   - Domains Checked: {domains_checked}")
    monitoring_logger.info(f"   - Phishing Detections: {detections_found}")
    monitoring_logger.info(f"   - Duration: {duration:.2f} seconds")
    monitoring_logger.info("=" * 80)
    monitoring_logger.info("")  # Empty line for readability


def log_cse_domain_scan_start(domain, organization):
    """Log when starting to scan a CSE domain"""
    scan_logger.info(f"🔍 Scanning CSE Domain: {domain} ({organization})")


def log_cse_domain_scan_end(domain, variations_checked, new_detections):
    """Log when finished scanning a CSE domain"""
    scan_logger.info(f"✓ Completed: {domain} - Checked {variations_checked} variations, Found {new_detections} new threats")


def log_variation_check(variation_domain, variation_type, is_registered):
    """Log when checking a domain variation"""
    status = "🔴 REGISTERED" if is_registered else "⚪ Not Registered"
    scan_logger.debug(f"   Checking {variation_type}: {variation_domain} - {status}")


def log_new_detection(phishing_domain, legitimate_domain, risk_level, risk_score, variation_type):
    """Log a new phishing detection"""
    detection_logger.warning("=" * 80)
    detection_logger.warning(f"🚨 NEW PHISHING THREAT DETECTED!")
    detection_logger.warning(f"   Phishing Domain: {phishing_domain}")
    detection_logger.warning(f"   Legitimate Target: {legitimate_domain}")
    detection_logger.warning(f"   Variation Type: {variation_type}")
    detection_logger.warning(f"   Risk Level: {risk_level}")
    detection_logger.warning(f"   Risk Score: {risk_score}/100")
    detection_logger.warning("=" * 80)


def log_intelligence_gathering(domain, intel_data):
    """Log intelligence gathering results"""
    scan_logger.info(f"   📡 Intelligence Gathered for {domain}:")
    if intel_data.get('ip'):
        scan_logger.info(f"      - IP: {intel_data['ip']}")
    if intel_data.get('country'):
        scan_logger.info(f"      - Country: {intel_data['country']}")
    if intel_data.get('registrar'):
        scan_logger.info(f"      - Registrar: {intel_data['registrar']}")


def log_social_media_scan(domain, platform, found):
    """Log social media scanning results"""
    status = "✓ Found" if found else "✗ Not found"
    scan_logger.info(f"   🔎 Social Media Check ({platform}): {domain} - {status}")


def log_error(context, error, domain=None):
    """Log an error with context"""
    error_logger.error(f"Error in {context}" + (f" for {domain}" if domain else ""))
    error_logger.error(f"   Type: {type(error).__name__}")
    error_logger.error(f"   Message: {str(error)}")


def log_performance(operation, duration, details=None):
    """Log performance metrics"""
    performance_logger.info(f"⏱️  {operation}: {duration:.2f}s" + (f" - {details}" if details else ""))


def log_warning(message):
    """Log a warning"""
    monitoring_logger.warning(message)


def log_info(message):
    """Log general information"""
    monitoring_logger.info(message)


# Create a summary log entry on startup
def log_system_startup():
    """Log system startup"""
    monitoring_logger.info("=" * 80)
    monitoring_logger.info("🚀 PHISHING DETECTION SYSTEM STARTED")
    monitoring_logger.info(f"   Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    monitoring_logger.info(f"   Log Directory: {LOGS_DIR}")
    monitoring_logger.info("=" * 80)
    monitoring_logger.info("")

