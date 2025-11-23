"""
Training script for ensemble phishing detection models
Uses malicious domain datasets for training
"""

import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Any, Tuple
from pathlib import Path
import json
from datetime import datetime

from backend.database import SessionLocal
from backend.models import PhishingDetection
from backend.ensemble_detector import EnsemblePhishingDetector

logger = logging.getLogger(__name__)

class EnsembleTrainer:
    """Train ensemble models using malicious domain datasets"""
    
    def __init__(self):
        self.ensemble_detector = EnsemblePhishingDetector()
        self.training_data = []
        self.feature_names = []
        
    def load_malicious_domains(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load malicious domains from dataset file"""
        malicious_domains = []
        
        try:
            if dataset_path.endswith('.csv'):
                df = pd.read_csv(dataset_path)
                
                # Common column names for malicious domain datasets
                domain_col = None
                label_col = None
                
                for col in df.columns:
                    col_lower = col.lower()
                    if 'domain' in col_lower or 'url' in col_lower:
                        domain_col = col
                    elif 'label' in col_lower or 'class' in col_lower or 'type' in col_lower:
                        label_col = col
                
                if domain_col is None:
                    logger.error("No domain column found in dataset")
                    return []
                
                for _, row in df.iterrows():
                    domain = str(row[domain_col])
                    label = 1 if label_col and str(row[label_col]).lower() in ['phishing', 'malicious', '1', 'true'] else 1
                    
                    malicious_domains.append({
                        'domain': domain,
                        'content': '',  # Will be filled during analysis
                        'legitimate_domain': '',  # Will be generated
                        'label': label,
                        'source': 'dataset'
                    })
                    
            elif dataset_path.endswith('.json'):
                with open(dataset_path, 'r') as f:
                    data = json.load(f)
                
                for item in data:
                    malicious_domains.append({
                        'domain': item.get('domain', ''),
                        'content': item.get('content', ''),
                        'legitimate_domain': item.get('legitimate_domain', ''),
                        'label': 1 if item.get('is_phishing', True) else 0,
                        'source': 'dataset'
                    })
            
            logger.info(f"Loaded {len(malicious_domains)} malicious domains from {dataset_path}")
            return malicious_domains
            
        except Exception as e:
            logger.error(f"Error loading malicious domains: {e}")
            return []
    
    def load_legitimate_domains(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load legitimate domains from dataset file"""
        legitimate_domains = []
        
        try:
            if dataset_path.endswith('.csv'):
                df = pd.read_csv(dataset_path)
                
                for _, row in df.iterrows():
                    domain = str(row.iloc[0])  # Assume first column is domain
                    
                    legitimate_domains.append({
                        'domain': domain,
                        'content': '',
                        'legitimate_domain': domain,
                        'label': 0,
                        'source': 'dataset'
                    })
                    
            logger.info(f"Loaded {len(legitimate_domains)} legitimate domains from {dataset_path}")
            return legitimate_domains
            
        except Exception as e:
            logger.error(f"Error loading legitimate domains: {e}")
            return []
    
    def generate_training_data(self, malicious_domains: List[Dict], legitimate_domains: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Generate training data with features"""
        X = []
        y = []
        
        logger.info("Generating training features...")
        
        # Process malicious domains
        for i, domain_data in enumerate(malicious_domains):
            if i % 100 == 0:
                logger.info(f"Processing malicious domain {i}/{len(malicious_domains)}")
            
            try:
                # Extract features using ensemble detector
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
        
        # Process legitimate domains
        for i, domain_data in enumerate(legitimate_domains):
            if i % 100 == 0:
                logger.info(f"Processing legitimate domain {i}/{len(legitimate_domains)}")
            
            try:
                features = self.ensemble_detector._extract_advanced_features(
                    domain_data['domain'],
                    domain_data['content'],
                    domain_data['legitimate_domain']
                )
                
                feature_vector = [features.get(name, 0.0) for name in self.feature_names]
                X.append(feature_vector)
                y.append(domain_data['label'])
                
            except Exception as e:
                logger.warning(f"Error processing domain {domain_data['domain']}: {e}")
                continue
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"Generated training data: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"Class distribution: {np.bincount(y)}")
        
        return X, y
    
    def train_models(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, Any]:
        """Train ensemble models"""
        try:
            from sklearn.model_selection import train_test_split
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            logger.info(f"Training set: {X_train.shape[0]} samples")
            logger.info(f"Test set: {X_test.shape[0]} samples")
            
            # Train ensemble
            training_result = self.ensemble_detector.train_ensemble(
                X_train, y_train, X_test, y_test
            )
            
            if training_result['success']:
                logger.info("✅ Ensemble training completed successfully!")
                logger.info(f"Individual model scores: {training_result['individual_scores']}")
                logger.info(f"Ensemble score: {training_result['ensemble_score']:.4f}")
                
                # Save model performance
                self.save_model_performance(training_result)
                # Persist models
                try:
                    self.ensemble_detector.save_models()
                except Exception as e:
                    logger.warning(f"Could not persist models: {e}")
                
                return training_result
            else:
                logger.error(f"Training failed: {training_result['error']}")
                return training_result
                
        except Exception as e:
            logger.error(f"Training error: {e}")
            return {'success': False, 'error': str(e)}
    
    def save_model_performance(self, performance: Dict[str, Any]):
        """Save model performance metrics"""
        try:
            performance_file = Path("./logs/ensemble_performance.json")
            performance_file.parent.mkdir(exist_ok=True)
            
            with open(performance_file, 'w') as f:
                json.dump(performance, f, indent=2, default=str)
            
            logger.info(f"Model performance saved to {performance_file}")
            
        except Exception as e:
            logger.warning(f"Could not save performance metrics: {e}")
    
    def train_from_database(self) -> Dict[str, Any]:
        """Train using existing database detections"""
        try:
            db = SessionLocal()
            
            # Get phishing detections
            phishing_detections = db.query(PhishingDetection).filter(
                PhishingDetection.is_active == True
            ).limit(1000).all()
            
            if len(phishing_detections) < 100:
                logger.warning("Not enough detections in database for training")
                return {'success': False, 'error': 'Insufficient training data'}
            
            # Prepare training data
            X = []
            y = []
            
            for detection in phishing_detections:
                try:
                    features = self.ensemble_detector._extract_advanced_features(
                        detection.phishing_domain,
                        getattr(detection, 'content', ''),
                        getattr(detection, 'cse_domain', {}).get('domain', '') if hasattr(detection, 'cse_domain') else ''
                    )
                    
                    if not self.feature_names:
                        self.feature_names = list(features.keys())
                    
                    feature_vector = [features.get(name, 0.0) for name in self.feature_names]
                    X.append(feature_vector)
                    y.append(1)  # All are phishing
                    
                except Exception as e:
                    logger.warning(f"Error processing detection {detection.id}: {e}")
                    continue
            
            # Add some legitimate domains (simulated)
            legitimate_domains = [
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                'facebook.com', 'twitter.com', 'linkedin.com', 'github.com'
            ]
            
            for domain in legitimate_domains:
                try:
                    features = self.ensemble_detector._extract_advanced_features(
                        domain, '', domain
                    )
                    
                    feature_vector = [features.get(name, 0.0) for name in self.feature_names]
                    X.append(feature_vector)
                    y.append(0)  # Legitimate
                    
                except Exception as e:
                    logger.warning(f"Error processing legitimate domain {domain}: {e}")
                    continue
            
            X = np.array(X)
            y = np.array(y)
            
            logger.info(f"Database training data: {X.shape[0]} samples, {X.shape[1]} features")
            
            # Train models
            result = self.train_models(X, y)
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Database training error: {e}")
            return {'success': False, 'error': str(e)}

def main():
    """Main training function"""
    logging.basicConfig(level=logging.INFO)
    
    trainer = EnsembleTrainer()
    
    print("🚀 Starting Ensemble Model Training...")
    
    # Try to train from database first
    print("📊 Training from database detections...")
    result = trainer.train_from_database()
    
    if result['success']:
        print("✅ Training completed successfully!")
        print(f"Individual model scores: {result['individual_scores']}")
        print(f"Ensemble score: {result['ensemble_score']:.4f}")
    else:
        print(f"❌ Training failed: {result['error']}")
        print("💡 To train with external datasets, provide malicious and legitimate domain files")

if __name__ == "__main__":
    main()
