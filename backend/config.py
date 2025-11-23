from pydantic_settings import BaseSettings
from functools import lru_cache
import os


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://phishing_user:phishing_pass@localhost:5432/phishing_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Application
    DEBUG: bool = True
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:3001,http://localhost:3002,http://localhost:5173"
    
    # Monitoring
    SCAN_INTERVAL_MINUTES: int = 15
    MAX_WORKERS: int = 5
    SCREENSHOT_TIMEOUT: int = 30
    
    # Long-term Monitoring Configuration
    DEFAULT_MONITORING_DURATION_DAYS: int = 90  # 3 months default
    MAX_MONITORING_DURATION_DAYS: int = 365     # 1 year maximum
    MONITORING_RETENTION_DAYS: int = 730        # 2 years data retention
    
    # Monitoring Intervals (in hours)
    HIGH_RISK_MONITORING_INTERVAL: int = 6      # High risk domains every 6 hours
    MEDIUM_RISK_MONITORING_INTERVAL: int = 24   # Medium risk domains every 24 hours
    LOW_RISK_MONITORING_INTERVAL: int = 168     # Low risk domains every 7 days
    
    # Content Change Detection
    ENABLE_CONTENT_CHANGE_DETECTION: bool = True
    CONTENT_CHANGE_THRESHOLD: float = 0.15      # 15% content change threshold
    ENABLE_BINARY_HOSTING_MONITORING: bool = True
    ENABLE_LOOKALIKE_CONTENT_MONITORING: bool = True
    
    # Risk Thresholds
    RISK_THRESHOLD_HIGH: int = 75
    RISK_THRESHOLD_MEDIUM: int = 50
    
    # File Storage
    REPORTS_DIR: str = "./reports"
    SCREENSHOTS_DIR: str = "./screenshots"
    
    # Social Media APIs (Optional)
    TWITTER_API_KEY: str = ""
    TWITTER_API_SECRET: str = ""
    TWITTER_BEARER_TOKEN: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    
    # Frontend API URL (for reference only)
    VITE_API_URL: str = "http://localhost:8000"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()

