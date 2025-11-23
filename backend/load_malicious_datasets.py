"""
Load and process malicious domain datasets for training
Handles large datasets with 5 lakh+ domains each
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, List, Any, Tuple
from pathlib import Path
import json
import gzip
import csv
from datetime import datetime
import os

from backend.database import SessionLocal
from backend.models import PhishingDetection, CSEDomain
from backend.ensemble_detector import EnsemblePhishingDetector
from backend.train_ensemble import EnsembleTrainer

logger = logging.getLogger(__name__)

class MaliciousDatasetLoader:
    """Load and process large malicious domain datasets"""
    
    def __init__(self):
        self.ensemble_detector = EnsemblePhishingDetector()
        self.processed_domains = []
        self.feature_names = []
        
    def load_dataset_file(self, file_path: str, dataset_type: str = "malicious") -> List[Dict[str, Any]]:
        """Load dataset from various file formats"""
        domains = []
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                return []
            
            logger.info(f"Loading {dataset_type} dataset from {file_path}")
            
            # Handle compressed files
            if file_path.suffix == '.gz':
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    if file_path.stem.endswith('.csv'):
                        df = pd.read_csv(f)
                    elif file_path.stem.endswith('.json'):
                        data = json.load(f)
                        df = pd.DataFrame(data)
                    else:
                        # Assume text file with one domain per line
                        domains = [{'domain': line.strip(), 'label': 1 if dataset_type == 'malicious' else 0} 
                                 for line in f if line.strip()]
                        return domains
            else:
                if file_path.suffix == '.csv':
                    df = pd.read_csv(file_path)
                elif file_path.suffix == '.json':
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    df = pd.DataFrame(data)
                elif file_path.suffix == '.xlsx':
                    df = pd.read_excel(file_path)
                elif file_path.suffix == '.txt':
                    with open(file_path, 'r') as f:
                        domains = [{'domain': line.strip(), 'label': 1 if dataset_type == 'malicious' else 0} 
                                 for line in f if line.strip()]
                    return domains
                else:
                    logger.error(f"Unsupported file format: {file_path.suffix}")
                    return []
            
            # Process DataFrame
            domains = self._process_dataframe(df, dataset_type)
            
            logger.info(f"Loaded {len(domains)} {dataset_type} domains")
            return domains
            
        except Exception as e:
            logger.error(f"Error loading dataset {file_path}: {e}")
            return []
    
    def _process_dataframe(self, df: pd.DataFrame, dataset_type: str) -> List[Dict[str, Any]]:
        """Process DataFrame to extract domain information"""
        domains = []
        
        # Common column mappings
        domain_columns = ['domain', 'url', 'hostname', 'site', 'website']
        label_columns = ['label', 'class', 'type', 'is_phishing', 'is_malicious', 'phishing']
        
        # Find domain column
        domain_col = None
        for col in df.columns:
            if any(keyword in col.lower() for keyword in domain_columns):
                domain_col = col
                break
        
        if domain_col is None:
            # Use first column as domain
            domain_col = df.columns[0]
        
        # Find label column
        label_col = None
        for col in df.columns:
            if any(keyword in col.lower() for keyword in label_columns):
                label_col = col
                break
        
        # Process each row
        for idx, row in df.iterrows():
            try:
                domain = str(row[domain_col]).strip()
                
                # Skip invalid domains
                if not domain or domain == 'nan' or len(domain) < 3:
                    continue
                
                # Clean domain
                domain = self._clean_domain(domain)
                
                # Determine label
                if label_col:
                    label_value = str(row[label_col]).lower()
                    if dataset_type == 'malicious':
                        label = 1 if any(keyword in label_value for keyword in ['phishing', 'malicious', '1', 'true', 'yes']) else 1
                    else:
                        label = 0 if any(keyword in label_value for keyword in ['legitimate', 'clean', '0', 'false', 'no']) else 0
                else:
                    label = 1 if dataset_type == 'malicious' else 0
                
                domains.append({
                    'domain': domain,
                    'content': '',
                    'legitimate_domain': '',
                    'label': label,
                    'source': f'dataset_{dataset_type}',
                    'original_data': row.to_dict()
                })
                
            except Exception as e:
                logger.warning(f"Error processing row {idx}: {e}")
                continue
        
        return domains
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain"""
        # Remove protocol
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove www
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove path and query parameters
        domain = domain.split('/')[0].split('?')[0].split('#')[0]
        
        # Remove port
        if ':' in domain and not domain.count(':') > 1:  # Not IPv6
            domain = domain.split(':')[0]
        
        return domain.lower().strip()
    
    def generate_legitimate_domains(self, malicious_domains: List[Dict]) -> List[Dict[str, Any]]:
        """Generate legitimate domains for training"""
        legitimate_domains = []
        
        # Get CSE domains from database
        try:
            db = SessionLocal()
            cse_domains = db.query(CSEDomain).filter(CSEDomain.is_active == True).all()
            db.close()
            
            for cse in cse_domains:
                legitimate_domains.append({
                    'domain': cse.domain,
                    'content': '',
                    'legitimate_domain': cse.domain,
                    'label': 0,
                    'source': 'cse_database'
                })
        except Exception as e:
            logger.warning(f"Could not load CSE domains: {e}")
        
        # Add common legitimate domains
        common_legitimate = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'youtube.com', 'netflix.com',
            'spotify.com', 'dropbox.com', 'adobe.com', 'salesforce.com'
        ]
        
        for domain in common_legitimate:
            legitimate_domains.append({
                'domain': domain,
                'content': '',
                'legitimate_domain': domain,
                'label': 0,
                'source': 'common_legitimate'
            })
        
        logger.info(f"Generated {len(legitimate_domains)} legitimate domains")
        return legitimate_domains
    
    def process_large_dataset(self, malicious_file: str, legitimate_file: str = None, 
                            sample_size: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
        """Process large dataset with sampling for memory efficiency"""
        
        logger.info(f"Processing large dataset with sample size: {sample_size}")
        
        # Load malicious domains
        malicious_domains = self.load_dataset_file(malicious_file, "malicious")
        
        # Sample malicious domains if too many
        if len(malicious_domains) > sample_size:
            logger.info(f"Sampling {sample_size} from {len(malicious_domains)} malicious domains")
            malicious_domains = np.random.choice(malicious_domains, sample_size, replace=False).tolist()
        
        # Load or generate legitimate domains
        if legitimate_file and Path(legitimate_file).exists():
            legitimate_domains = self.load_dataset_file(legitimate_file, "legitimate")
        else:
            legitimate_domains = self.generate_legitimate_domains(malicious_domains)
        
        # Sample legitimate domains
        if len(legitimate_domains) > sample_size:
            logger.info(f"Sampling {sample_size} from {len(legitimate_domains)} legitimate domains")
            legitimate_domains = np.random.choice(legitimate_domains, sample_size, replace=False).tolist()
        
        # Combine datasets
        all_domains = malicious_domains + legitimate_domains
        
        logger.info(f"Combined dataset: {len(malicious_domains)} malicious + {len(legitimate_domains)} legitimate = {len(all_domains)} total")
        
        # Generate features
        X, y = self._generate_features(all_domains)
        
        return X, y
    
    def _generate_features(self, domains: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Generate features for all domains"""
        X = []
        y = []
        
        logger.info("Generating features for domains...")
        
        for i, domain_data in enumerate(domains):
            if i % 1000 == 0:
                logger.info(f"Processing domain {i}/{len(domains)}")
            
            try:
                # Extract features
                features = self.ensemble_detector._extract_advanced_features(
                    domain_data['domain'],
                    domain_data['content'],
                    domain_data['legitimate_domain']
                )
                
                if not self.feature_names:
                    self.feature_names = list(features.keys())
                
                feature_vector = [features.get(name, 0.0) for name in self.feature_names]
                X.append(feature_vector)
                y.append(domain_data['label'])
                
            except Exception as e:
                logger.warning(f"Error processing domain {domain_data['domain']}: {e}")
                continue
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"Generated features: {X.shape[0]} samples, {X.shape[1]} features")
        return X, y
    
    def train_with_datasets(self, malicious_file: str, legitimate_file: str = None, 
                          sample_size: int = 10000) -> Dict[str, Any]:
        """Train ensemble models with large datasets"""
        
        try:
            # Process datasets
            X, y = self.process_large_dataset(malicious_file, legitimate_file, sample_size)
            
            if X.shape[0] < 100:
                return {'success': False, 'error': 'Insufficient training data'}
            
            # Train ensemble
            trainer = EnsembleTrainer()
            result = trainer.train_models(X, y)
            
            if result['success']:
                logger.info("✅ Training completed successfully!")
                
                # Save training info
                training_info = {
                    'malicious_file': malicious_file,
                    'legitimate_file': legitimate_file,
                    'sample_size': sample_size,
                    'total_samples': X.shape[0],
                    'features_count': X.shape[1],
                    'class_distribution': np.bincount(y).tolist(),
                    'training_result': result,
                    'timestamp': datetime.now().isoformat()
                }
                
                self._save_training_info(training_info)
                
            return result
            
        except Exception as e:
            logger.error(f"Training with datasets failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _save_training_info(self, info: Dict[str, Any]):
        """Save training information"""
        try:
            info_file = Path("./logs/training_info.json")
            info_file.parent.mkdir(exist_ok=True)
            
            with open(info_file, 'w') as f:
                json.dump(info, f, indent=2, default=str)
            
            logger.info(f"Training info saved to {info_file}")
            
        except Exception as e:
            logger.warning(f"Could not save training info: {e}")

def main():
    """Main function for dataset loading and training"""
    logging.basicConfig(level=logging.INFO)
    
    loader = MaliciousDatasetLoader()
    
    print("🚀 Malicious Dataset Loader")
    print("=" * 50)
    
    # Example usage
    print("📁 To use this loader:")
    print("1. Place your malicious domain files in the datasets/ folder")
    print("2. Supported formats: .csv, .json, .txt, .gz")
    print("3. Run: python load_malicious_datasets.py <malicious_file> [legitimate_file]")
    print()
    print("📊 Example files:")
    print("  - malicious_domains_part1.csv")
    print("  - malicious_domains_part2.csv") 
    print("  - legitimate_domains.csv")
    print()
    print("💡 The loader will automatically:")
    print("  - Sample large datasets for memory efficiency")
    print("  - Generate features using ensemble detector")
    print("  - Train ensemble models")
    print("  - Save performance metrics")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        main()
    else:
        malicious_file = sys.argv[1]
        legitimate_file = sys.argv[2] if len(sys.argv) > 2 else None
        
        loader = MaliciousDatasetLoader()
        result = loader.train_with_datasets(malicious_file, legitimate_file)
        
        if result['success']:
            print("✅ Training completed successfully!")
        else:
            print(f"❌ Training failed: {result['error']}")
