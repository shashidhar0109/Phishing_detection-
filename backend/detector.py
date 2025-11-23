import cv2
import numpy as np
from PIL import Image
import imagehash
from skimage.metrics import structural_similarity as ssim
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import requests
from typing import Dict, Any, Optional, Tuple
import os
from datetime import datetime
from backend.config import settings
from .ml_detector import MLPhishingDetector
from .nlp_analyzer import NLPContentAnalyzer
from .ensemble_detector import EnsemblePhishingDetector


class PhishingDetector:
    """Detect phishing sites using visual and content analysis"""
    
    def __init__(self):
        self.screenshots_dir = settings.SCREENSHOTS_DIR
        os.makedirs(self.screenshots_dir, exist_ok=True)
        
        # Initialize ML components
        self.ml_detector = MLPhishingDetector()
        self.nlp_analyzer = NLPContentAnalyzer()
        self.ensemble_detector = EnsemblePhishingDetector()
    
    def analyze_domain(self, legitimate_domain: str, suspicious_domain: str) -> Dict[str, Any]:
        """
        Analyze a suspicious domain against the legitimate one
        Returns detection results with scores
        """
        result = {
            'suspicious_domain': suspicious_domain,
            'legitimate_domain': legitimate_domain,
            'visual_similarity_score': 0.0,
            'content_similarity_score': 0.0,
            'has_login_form': False,
            'has_payment_form': False,
            'has_binary_hosting': False,
            'has_download_page': False,
            'suspicious_keywords': [],
            'idn_homograph_detected': False,
            'screenshot_path': None,
            'legitimate_screenshot_path': None,
            'is_accessible': False,
            'error': None
        }
        
        try:
            # Capture screenshots
            susp_screenshot = self._capture_screenshot(suspicious_domain)
            legit_screenshot = self._capture_screenshot(legitimate_domain)
            
            if susp_screenshot and legit_screenshot:
                result['screenshot_path'] = susp_screenshot
                result['legitimate_screenshot_path'] = legit_screenshot
                result['is_accessible'] = True
                
                # Calculate visual similarity
                visual_score = self._calculate_visual_similarity(legit_screenshot, susp_screenshot)
                result['visual_similarity_score'] = visual_score
                
                # Analyze content
                content_analysis = self._analyze_content(suspicious_domain)
                result['content_similarity_score'] = content_analysis.get('similarity_score', 0.0)
                result['has_login_form'] = content_analysis.get('has_login_form', False)
                result['has_payment_form'] = content_analysis.get('has_payment_form', False)
                result['has_binary_hosting'] = content_analysis.get('has_binary_hosting', False)
                result['has_download_page'] = content_analysis.get('has_download_page', False)
                result['suspicious_keywords'] = content_analysis.get('suspicious_keywords', [])
                
                # Check for IDN homograph attacks
                result['idn_homograph_detected'] = self._detect_idn_homographs(suspicious_domain)
                
                # Perform ML-based analysis
                content = content_analysis.get('content', '')
                ml_analysis = self._perform_ml_analysis(suspicious_domain, content, legitimate_domain)
                result['ml_analysis'] = ml_analysis
                
                # Update final score with ensemble integration
                result['final_score'] = (
                    result['visual_similarity_score'] * 0.20 +
                    result['content_similarity_score'] * 0.15 +
                    ml_analysis['combined_score'] * 0.35 +
                    ml_analysis['ensemble_score'] * 0.20 +
                    (1.0 if result['has_login_form'] else 0.0) * 0.05 +
                    (1.0 if result['has_payment_form'] else 0.0) * 0.05
                )
            else:
                result['error'] = 'Could not capture screenshots'
                result['ml_analysis'] = self._perform_ml_analysis(suspicious_domain, '', legitimate_domain)
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _perform_ml_analysis(self, suspicious_domain: str, content: str, legitimate_domain: str) -> Dict[str, Any]:
        """Perform ML-based analysis on the domain and content"""
        try:
            # Get ML prediction
            ml_prediction = self.ml_detector.predict_phishing_probability(
                suspicious_domain, content, legitimate_domain
            )
            
            # Get NLP analysis
            nlp_analysis = self.nlp_analyzer.analyze_content(content, suspicious_domain)
            
            # Get ensemble prediction
            ensemble_prediction = self.ensemble_detector.predict_phishing_probability(
                suspicious_domain, content, legitimate_domain
            )
            
            # Combine all predictions with weights
            ml_weight = 0.3
            nlp_weight = 0.3
            ensemble_weight = 0.4
            
            combined_score = (
                ml_prediction['phishing_probability'] * ml_weight +
                nlp_analysis['risk_score'] / 100.0 * nlp_weight +
                ensemble_prediction['phishing_probability'] * ensemble_weight
            )
            
            # Calculate overall confidence
            confidences = [
                ml_prediction['confidence'],
                nlp_analysis['confidence'],
                ensemble_prediction['confidence']
            ]
            overall_confidence = sum(confidences) / len(confidences)
            
            return {
                'ml_score': ml_prediction['phishing_probability'],
                'ml_confidence': ml_prediction['confidence'],
                'nlp_risk_score': nlp_analysis['risk_score'],
                'nlp_confidence': nlp_analysis['confidence'],
                'ensemble_score': ensemble_prediction['phishing_probability'],
                'ensemble_confidence': ensemble_prediction['confidence'],
                'combined_score': combined_score,
                'overall_confidence': overall_confidence,
                'ml_features': ml_prediction.get('feature_importance', {}),
                'nlp_features': {
                    'phishing_patterns': nlp_analysis['phishing_patterns']['overall_score'],
                    'suspicious_keywords': nlp_analysis['suspicious_keywords']['overall_risk'],
                    'grammatical_errors': nlp_analysis['grammatical_errors']['overall_score'],
                    'brand_impersonation': nlp_analysis['brand_impersonation']['overall_score']
                },
                'ensemble_features': ensemble_prediction.get('feature_importance', {}),
                'individual_predictions': ensemble_prediction.get('individual_predictions', {}),
                'model_weights': ensemble_prediction.get('model_weights', {})
            }
        except Exception as e:
            print(f"ML analysis failed: {e}")
            return {
                'ml_score': 0.5,
                'ml_confidence': 0.0,
                'nlp_risk_score': 0.5,
                'nlp_confidence': 0.0,
                'ensemble_score': 0.5,
                'ensemble_confidence': 0.0,
                'combined_score': 0.5,
                'overall_confidence': 0.0,
                'ml_features': {},
                'nlp_features': {},
                'ensemble_features': {},
                'individual_predictions': {},
                'model_weights': {}
            }
    
    def _capture_screenshot(self, domain: str, timeout: int = 30000) -> Optional[str]:
        """Capture screenshot of a domain using Playwright with fallback"""
        try:
            # Ensure domain has protocol
            if not domain.startswith('http'):
                url = f'https://{domain}'
            else:
                url = domain
            
            # Generate filename
            safe_domain = domain.replace('https://', '').replace('http://', '').replace('/', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{safe_domain}_{timestamp}.png"
            filepath = os.path.join(self.screenshots_dir, filename)
            
            # Try Playwright first
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    context = browser.new_context(
                        viewport={'width': 1920, 'height': 1080},
                        ignore_https_errors=True
                    )
                    page = context.new_page()
                    
                    # Set timeout
                    page.set_default_timeout(timeout)
                    
                    try:
                        page.goto(url, wait_until='networkidle', timeout=timeout)
                        page.screenshot(path=filepath, full_page=True)
                        return filepath
                    except Exception as e:
                        # Try http if https fails
                        if url.startswith('https://'):
                            url = url.replace('https://', 'http://')
                            page.goto(url, wait_until='networkidle', timeout=timeout)
                            page.screenshot(path=filepath, full_page=True)
                            return filepath
                        raise e
                    finally:
                        browser.close()
            except Exception as playwright_error:
                print(f"Playwright failed for {domain}: {playwright_error}")
                # Fallback: Create a placeholder screenshot
                return self._create_placeholder_screenshot(domain, filepath)
                    
        except Exception as e:
            print(f"Screenshot capture failed for {domain}: {e}")
            return self._create_placeholder_screenshot(domain, filepath)
    
    def _create_placeholder_screenshot(self, domain: str, filepath: str) -> str:
        """Create a placeholder screenshot when Playwright fails"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            
            # Create a simple placeholder image
            img = Image.new('RGB', (1920, 1080), color='white')
            draw = ImageDraw.Draw(img)
            
            # Add text
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
            except:
                font = ImageFont.load_default()
            
            text = f"Screenshot Unavailable\nDomain: {domain}\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Get text size and center it
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (1920 - text_width) // 2
            y = (1080 - text_height) // 2
            
            draw.text((x, y), text, fill='black', font=font)
            
            # Save image
            img.save(filepath)
            print(f"Created placeholder screenshot for {domain}: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"Failed to create placeholder screenshot: {e}")
            return None
    
    def _calculate_visual_similarity(self, image1_path: str, image2_path: str) -> float:
        """
        Calculate visual similarity between two screenshots
        Returns score 0-100 (higher = more similar)
        """
        try:
            # Read images
            img1 = cv2.imread(image1_path)
            img2 = cv2.imread(image2_path)
            
            if img1 is None or img2 is None:
                return 0.0
            
            # Resize images to same size
            height = min(img1.shape[0], img2.shape[0], 1080)
            width = min(img1.shape[1], img2.shape[1], 1920)
            
            img1_resized = cv2.resize(img1, (width, height))
            img2_resized = cv2.resize(img2, (width, height))
            
            # Convert to grayscale
            gray1 = cv2.cvtColor(img1_resized, cv2.COLOR_BGR2GRAY)
            gray2 = cv2.cvtColor(img2_resized, cv2.COLOR_BGR2GRAY)
            
            # Calculate SSIM (Structural Similarity Index)
            ssim_score = ssim(gray1, gray2)
            
            # Calculate perceptual hash similarity
            hash1 = imagehash.phash(Image.open(image1_path))
            hash2 = imagehash.phash(Image.open(image2_path))
            hash_diff = hash1 - hash2
            hash_similarity = 1 - (hash_diff / 64.0)  # Normalize to 0-1
            
            # Calculate histogram similarity
            hist1 = cv2.calcHist([img1_resized], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            hist2 = cv2.calcHist([img2_resized], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            hist1 = cv2.normalize(hist1, hist1).flatten()
            hist2 = cv2.normalize(hist2, hist2).flatten()
            hist_similarity = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
            
            # Calculate template matching
            template_match = cv2.matchTemplate(gray1, gray2, cv2.TM_CCOEFF_NORMED)
            template_similarity = np.max(template_match)
            
            # Calculate edge similarity
            edges1 = cv2.Canny(gray1, 50, 150)
            edges2 = cv2.Canny(gray2, 50, 150)
            edge_match = cv2.matchTemplate(edges1, edges2, cv2.TM_CCOEFF_NORMED)
            edge_similarity = np.max(edge_match)
            
            # Calculate color similarity
            color1 = np.mean(img1_resized, axis=(0, 1))
            color2 = np.mean(img2_resized, axis=(0, 1))
            color_diff = np.linalg.norm(color1 - color2)
            color_similarity = max(0, 1 - (color_diff / 441.67))  # Normalize by max possible distance
            
            # Weighted average of all methods (enhanced)
            final_score = (
                ssim_score * 0.35 +
                hash_similarity * 0.25 +
                hist_similarity * 0.15 +
                template_similarity * 0.15 +
                edge_similarity * 0.05 +
                color_similarity * 0.05
            ) * 100
            
            # Convert to Python float (not numpy float64)
            return float(round(final_score, 2))
            
        except Exception as e:
            print(f"Visual similarity calculation failed: {e}")
            return 0.0
    
    def _analyze_content(self, domain: str) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators"""
        result = {
            'similarity_score': 0.0,
            'has_login_form': False,
            'has_payment_form': False,
            'has_binary_hosting': False,
            'has_download_page': False,
            'suspicious_keywords': [],
            'form_count': 0,
            'input_fields': [],
        }
        
        try:
            # Ensure domain has protocol
            if not domain.startswith('http'):
                url = f'https://{domain}'
            else:
                url = domain
            
            # Fetch page content
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            try:
                response = requests.get(url, headers=headers, timeout=10, verify=False)
            except:
                # Try http if https fails
                url = url.replace('https://', 'http://')
                response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code != 200:
                return result
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            result['form_count'] = len(forms)
            
            # Analyze forms for login/payment indicators
            login_keywords = ['login', 'signin', 'password', 'username', 'email', 'user']
            payment_keywords = ['card', 'credit', 'cvv', 'payment', 'billing', 'checkout']
            
            for form in forms:
                # Get all input fields in the form
                inputs = form.find_all('input')
                
                for input_field in inputs:
                    field_name = input_field.get('name', '').lower()
                    field_type = input_field.get('type', '').lower()
                    field_id = input_field.get('id', '').lower()
                    field_placeholder = input_field.get('placeholder', '').lower()
                    
                    # Check for login form
                    if any(kw in field_name + field_type + field_id + field_placeholder 
                           for kw in login_keywords):
                        result['has_login_form'] = True
                    
                    # Check for payment form
                    if any(kw in field_name + field_type + field_id + field_placeholder 
                           for kw in payment_keywords):
                        result['has_payment_form'] = True
                    
                    result['input_fields'].append({
                        'type': field_type,
                        'name': field_name,
                    })
            
            # Detect binary hosting and download pages
            binary_analysis = self._detect_binary_hosting(response.text, url)
            result.update(binary_analysis)
            
            # Detect suspicious keywords
            result['suspicious_keywords'] = self._detect_suspicious_keywords(response.text)
            
            # Calculate basic content similarity (could be enhanced)
            # For now, presence of forms increases similarity if it's a banking site
            if result['has_login_form']:
                result['similarity_score'] = 50.0
            
        except Exception as e:
            print(f"Content analysis failed for {domain}: {e}")
        
        return result
    
    def quick_check_accessibility(self, domain: str) -> bool:
        """Quick check if domain is accessible"""
        try:
            if not domain.startswith('http'):
                url = f'https://{domain}'
            else:
                url = domain
            
            response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
            return response.status_code < 400
        except:
            try:
                # Try http
                url = url.replace('https://', 'http://')
                response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
                return response.status_code < 400
            except:
                return False
    
    def _detect_idn_homographs(self, domain: str) -> bool:
        """Detect IDN homograph attacks in domain names"""
        try:
            # Check for non-ASCII characters that could be homographs
            if not domain.isascii():
                return True
            
            # Check for mixed scripts (Latin + non-Latin)
            has_latin = any(ord(char) < 128 for char in domain)
            has_non_latin = any(ord(char) >= 128 for char in domain)
            
            if has_latin and has_non_latin:
                return True
            
            # Check for confusable characters
            confusable_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у', 'і', 'ј', 'к', 'м', 'п', 'т']
            if any(char in domain for char in confusable_chars):
                return True
                
            return False
        except:
            return False
    
    def _detect_binary_hosting(self, content: str, url: str) -> Dict[str, bool]:
        """Detect binary hosting and download pages"""
        result = {
            'has_binary_hosting': False,
            'has_download_page': False
        }
        
        try:
            content_lower = content.lower()
            url_lower = url.lower()
            
            # Binary file extensions
            binary_extensions = ['.exe', '.zip', '.rar', '.7z', '.tar', '.gz', '.msi', '.dmg', '.pkg', '.deb', '.rpm']
            if any(ext in url_lower for ext in binary_extensions):
                result['has_binary_hosting'] = True
            
            # Download-related keywords
            download_keywords = [
                'download', 'install', 'setup', 'update', 'upgrade', 'patch',
                'installer', 'executable', 'binary', 'software', 'program',
                'click to download', 'download now', 'free download'
            ]
            
            if any(keyword in content_lower for keyword in download_keywords):
                result['has_download_page'] = True
                
            # Form elements that might indicate downloads
            if 'download' in content_lower and ('button' in content_lower or 'link' in content_lower):
                result['has_download_page'] = True
                
        except:
            pass
            
        return result
    
    def _detect_suspicious_keywords(self, content: str) -> list:
        """Detect suspicious keywords that indicate phishing"""
        suspicious_keywords = [
            'urgent', 'verify', 'suspended', 'expired', 'locked', 'blocked',
            'security alert', 'account compromised', 'immediate action required',
            'click here', 'verify now', 'update immediately', 'confirm identity',
            'suspicious activity', 'unauthorized access', 'password expired',
            'account will be closed', 'limited time offer', 'act now',
            'your account', 'dear customer', 'dear user', 'valued customer'
        ]
        
        found_keywords = []
        content_lower = content.lower()
        
        for keyword in suspicious_keywords:
            if keyword in content_lower:
                found_keywords.append(keyword)
                
        return found_keywords


# Helper function
def detect_phishing(legitimate_domain: str, suspicious_domain: str) -> Dict[str, Any]:
    """Detect if suspicious domain is phishing the legitimate one"""
    detector = PhishingDetector()
    return detector.analyze_domain(legitimate_domain, suspicious_domain)

