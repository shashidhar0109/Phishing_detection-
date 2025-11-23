#!/usr/bin/env python3
"""
Clear all data from the database to ensure clean start
This script removes all CSE domains and phishing detections
"""

import sys
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

from database import SessionLocal, init_db
from models import CSEDomain, PhishingDetection

def clear_all_data():
    """Clear all data from the database"""
    print("🧹 Clearing all data from database...")
    
    db = SessionLocal()
    
    try:
        # Initialize database (create tables if they don't exist)
        init_db()
        
        # Clear phishing detections
        phishing_count = db.query(PhishingDetection).count()
        if phishing_count > 0:
            db.query(PhishingDetection).delete()
            print(f"✅ Removed {phishing_count} phishing detections")
        else:
            print("✅ No phishing detections to remove")
        
        # Clear CSE domains
        cse_count = db.query(CSEDomain).count()
        if cse_count > 0:
            db.query(CSEDomain).delete()
            print(f"✅ Removed {cse_count} CSE domains")
        else:
            print("✅ No CSE domains to remove")
        
        # Commit changes
        db.commit()
        print("✅ Database cleared successfully!")
        
        # Verify empty database
        final_phishing = db.query(PhishingDetection).count()
        final_cse = db.query(CSEDomain).count()
        
        print(f"📊 Final counts: {final_phishing} phishing detections, {final_cse} CSE domains")
        
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
        db.rollback()
        return False
    finally:
        db.close()
    
    return True

if __name__ == "__main__":
    print("🚀 Database Cleanup Script")
    print("=" * 30)
    
    if clear_all_data():
        print("\n🎉 Database is now clean and ready for fresh data!")
        print("📋 Next steps:")
        print("1. Start the system: docker compose up -d")
        print("2. Add your CSE domains via the web interface")
        print("3. Test phishing detection with suspicious domains")
    else:
        print("\n❌ Failed to clear database")
        sys.exit(1)
