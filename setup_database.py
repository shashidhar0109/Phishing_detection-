#!/usr/bin/env python3
"""
Database setup script for Phishing Detection System
Creates database, user, and tables
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr}")
        return False

def check_postgresql():
    """Check if PostgreSQL is installed and running"""
    print("🔍 Checking PostgreSQL installation...")
    
    # Check if psql is available
    if not run_command("which psql", "Checking psql command"):
        print("❌ PostgreSQL client (psql) not found. Please install PostgreSQL.")
        return False
    
    # Check if PostgreSQL service is running
    if not run_command("pg_isready", "Checking PostgreSQL service"):
        print("❌ PostgreSQL service is not running. Please start PostgreSQL.")
        return False
    
    print("✅ PostgreSQL is installed and running")
    return True

def create_database():
    """Create database and user"""
    print("🗄️ Setting up database...")
    
    # Database configuration
    db_name = "phishing_db"
    db_user = "phishing_user"
    db_password = "phishing_pass"
    
    # Create user
    create_user_cmd = f"""
    sudo -u postgres psql -c "CREATE USER {db_user} WITH PASSWORD '{db_password}';" 2>/dev/null || echo "User already exists"
    """
    
    if not run_command(create_user_cmd, "Creating database user"):
        print("⚠️ User creation failed, but continuing...")
    
    # Create database
    create_db_cmd = f"""
    sudo -u postgres psql -c "CREATE DATABASE {db_name} OWNER {db_user};" 2>/dev/null || echo "Database already exists"
    """
    
    if not run_command(create_db_cmd, "Creating database"):
        print("⚠️ Database creation failed, but continuing...")
    
    # Grant privileges
    grant_cmd = f"""
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};"
    """
    
    run_command(grant_cmd, "Granting privileges")
    
    print("✅ Database setup completed")
    return True

def test_connection():
    """Test database connection"""
    print("🧪 Testing database connection...")
    
    try:
        # Add the project directory to Python path
        project_dir = Path(__file__).parent
        sys.path.insert(0, str(project_dir))
        
        # Import and test database connection
        from backend.database import test_connection
        
        if test_connection():
            print("✅ Database connection test successful")
            return True
        else:
            print("❌ Database connection test failed")
            return False
            
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 Phishing Detection System - Database Setup")
    print("=" * 50)
    
    # Check PostgreSQL
    if not check_postgresql():
        print("\n❌ Setup failed: PostgreSQL requirements not met")
        print("\nTo install PostgreSQL on Ubuntu/Debian:")
        print("sudo apt update")
        print("sudo apt install postgresql postgresql-contrib")
        print("sudo systemctl start postgresql")
        print("sudo systemctl enable postgresql")
        sys.exit(1)
    
    # Create database
    if not create_database():
        print("\n❌ Setup failed: Database creation failed")
        sys.exit(1)
    
    # Test connection
    if not test_connection():
        print("\n❌ Setup failed: Database connection test failed")
        sys.exit(1)
    
    print("\n🎉 Database setup completed successfully!")
    print("\nNext steps:")
    print("1. Run: ./setup.sh")
    print("2. Edit .env file if needed")
    print("3. Start the application: ./start-backend.sh")

if __name__ == "__main__":
    main()
