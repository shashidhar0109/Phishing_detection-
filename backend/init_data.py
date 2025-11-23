"""Initialize database with CSE domains from CSV"""
import csv
from backend.database import SessionLocal, init_db
from backend.models import CSEDomain


def load_cse_domains_from_csv(csv_path: str = "Phishing Detection CSE.csv"):
    """Load CSE domains from CSV file"""
    db = SessionLocal()
    
    try:
        # Initialize database
        init_db()
        
        with open(csv_path, 'r') as file:
            csv_reader = csv.DictReader(file)
            
            current_sector = None
            current_org = None
            
            for row in csv_reader:
                sector = row.get('Sector', '').strip()
                org_name = row.get('Organisation Name', '').strip()
                domain = row.get('Whitelisted Domains', '').strip()
                
                # Update current sector and org if provided
                if sector:
                    current_sector = sector
                if org_name:
                    current_org = org_name
                
                # Skip if no domain
                if not domain or domain == '':
                    continue
                
                # Clean domain (remove quotes, whitespace)
                domain = domain.replace('"', '').strip()
                
                if not domain:
                    continue
                
                # Use current sector and org if not in this row
                final_sector = sector if sector else current_sector
                final_org = org_name if org_name else current_org
                
                # Check if domain already exists
                existing = db.query(CSEDomain).filter(
                    CSEDomain.domain == domain
                ).first()
                
                if not existing:
                    cse_domain = CSEDomain(
                        sector=final_sector or 'Unknown',
                        organization_name=final_org or 'Unknown',
                        domain=domain
                    )
                    db.add(cse_domain)
                    print(f"Added: {domain} ({final_org})")
                else:
                    print(f"Skipped (exists): {domain}")
        
        db.commit()
        print("\n✅ CSE domains loaded successfully!")
        
        # Print summary
        total = db.query(CSEDomain).count()
        print(f"Total CSE domains in database: {total}")
        
    except Exception as e:
        print(f"❌ Error loading CSE domains: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    load_cse_domains_from_csv()

