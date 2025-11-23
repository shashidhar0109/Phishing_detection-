"""
Screenshot Capture System for Phishing Domains
Captures screenshots of phishing pages using Playwright
Generates evidence PDFs for PS-02 submission
"""

import os
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from PIL import Image
import io

class ScreenshotCapturer:
    """Capture screenshots of phishing domains"""
    
    def __init__(self, screenshots_dir="./screenshots", evidences_dir="./evidences"):
        self.screenshots_dir = Path(screenshots_dir)
        self.evidences_dir = Path(evidences_dir)
        
        # Create directories if they don't exist
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.evidences_dir.mkdir(parents=True, exist_ok=True)
    
    async def capture_screenshot(self, domain: str, url: str = None) -> Optional[str]:
        """
        Capture screenshot of a domain with robust error handling
        
        Args:
            domain: Domain name
            url: Full URL (if None, will use http://domain)
        
        Returns:
            Path to screenshot file or None if failed
        """
        if url is None:
            url = f"http://{domain}"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_filename = f"{domain.replace('/', '_').replace(':', '_')}_{timestamp}.png"
        screenshot_path = self.screenshots_dir / screenshot_filename
        
        try:
            async with async_playwright() as p:
                # Launch browser with additional stability options
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor',
                        '--disable-extensions',
                        '--disable-plugins',
                        '--disable-images'  # Faster loading
                    ]
                )
                
                # Create page with timeout settings
                page = await browser.new_page(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                )
                
                # Set timeouts
                page.set_default_timeout(30000)
                page.set_default_navigation_timeout(30000)
                
                # Navigate to URL with retry logic
                success = False
                for attempt in range(3):
                    try:
                        await page.goto(url, wait_until='domcontentloaded', timeout=20000)
                        success = True
                        break
                    except PlaywrightTimeout:
                        if attempt < 2:  # Not the last attempt
                            # Try with http:// if https:// failed
                            if url.startswith('https://'):
                                url = url.replace('https://', 'http://')
                                print(f"🔄 Retrying with HTTP for {domain} (attempt {attempt + 1})")
                                continue
                        else:
                            print(f"⚠️ Timeout after 3 attempts for {domain}")
                            break
                    except Exception as e:
                        print(f"⚠️ Navigation error for {domain}: {e}")
                        if attempt < 2:
                            continue
                        else:
                            break
                
                if not success:
                    await browser.close()
                    return self._create_placeholder_screenshot(domain, str(screenshot_path))
                
                # Wait for content to load
                try:
                    await page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    # Continue even if networkidle times out
                    pass
                
                # Take screenshot
                await page.screenshot(path=str(screenshot_path), full_page=True)
                
                # Close browser
                await browser.close()
                
                # Verify screenshot was created
                if screenshot_path.exists() and screenshot_path.stat().st_size > 0:
                    print(f"✅ Screenshot captured: {screenshot_filename}")
                    return str(screenshot_path)
                else:
                    print(f"⚠️ Screenshot file is empty for {domain}")
                    return self._create_placeholder_screenshot(domain, str(screenshot_path))
                
        except Exception as e:
            print(f"❌ Failed to capture screenshot for {domain}: {e}")
            return self._create_placeholder_screenshot(domain, str(screenshot_path))
    
    def _create_placeholder_screenshot(self, domain: str, filepath: str) -> str:
        """Create a placeholder screenshot when capture fails"""
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
            print(f"📷 Created placeholder screenshot for {domain}")
            return filepath
            
        except Exception as e:
            print(f"❌ Failed to create placeholder screenshot: {e}")
            return None
    
    def generate_evidence_pdf(
        self,
        screenshot_path: str,
        organization: str,
        domain: str,
        serial_number: int
    ) -> Optional[str]:
        """
        Generate evidence PDF from screenshot for PS-02 submission
        
        Args:
            screenshot_path: Path to screenshot image
            organization: Organization short name (e.g., "SBI", "PNB")
            domain: Domain name for naming
            serial_number: Serial number for evidence file
        
        Returns:
            Path to generated PDF or None if failed
        
        Naming Convention:
            <Organization>_<up_to_2_level_subdomain>_<serial>.pdf
            Example: SBI_sbi123.co.in_1.pdf
        """
        try:
            # Extract up to 2-level subdomain
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                # Get last 2 parts (domain.tld) or subdomain.domain.tld
                subdomain = '.'.join(domain_parts[-3:]) if len(domain_parts) >= 3 else '.'.join(domain_parts[-2:])
            else:
                subdomain = domain
            
            # Clean subdomain for filename (remove http://, https://, etc.)
            subdomain = subdomain.replace('http://', '').replace('https://', '').replace('/', '_')
            
            # Create PDF filename
            pdf_filename = f"{organization}_{subdomain}_{serial_number}.pdf"
            pdf_path = self.evidences_dir / pdf_filename
            
            # Create PDF
            c = canvas.Canvas(str(pdf_path), pagesize=A4)
            page_width, page_height = A4
            
            # Add title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, page_height - 50, f"Phishing Evidence: {domain}")
            
            c.setFont("Helvetica", 10)
            c.drawString(50, page_height - 70, f"Organization: {organization}")
            c.drawString(50, page_height - 85, f"Detection Date: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}")
            c.drawString(50, page_height - 100, f"Evidence ID: {pdf_filename}")
            
            # Add screenshot
            if os.path.exists(screenshot_path):
                # Open and resize image if needed
                img = Image.open(screenshot_path)
                img_width, img_height = img.size
                
                # Calculate scaling to fit on page
                max_width = page_width - 100  # 50px margin on each side
                max_height = page_height - 150  # Space for title and footer
                
                scale = min(max_width / img_width, max_height / img_height)
                new_width = img_width * scale
                new_height = img_height * scale
                
                # Draw image
                c.drawImage(
                    screenshot_path,
                    50,  # x position
                    page_height - 130 - new_height,  # y position
                    width=new_width,
                    height=new_height,
                    preserveAspectRatio=True
                )
            
            # Save PDF
            c.save()
            
            print(f"✅ Evidence PDF generated: {pdf_filename}")
            return str(pdf_path)
            
        except Exception as e:
            print(f"❌ Failed to generate evidence PDF: {e}")
            return None
    
    async def capture_and_generate_evidence(
        self,
        domain: str,
        organization: str,
        serial_number: int,
        url: str = None
    ) -> Dict[str, Optional[str]]:
        """
        Capture screenshot and generate evidence PDF in one call
        
        Returns:
            Dict with 'screenshot_path' and 'evidence_pdf_path'
        """
        result = {
            'screenshot_path': None,
            'evidence_pdf_path': None
        }
        
        # Capture screenshot
        screenshot_path = await self.capture_screenshot(domain, url)
        result['screenshot_path'] = screenshot_path
        
        # Generate evidence PDF
        if screenshot_path:
            pdf_path = self.generate_evidence_pdf(
                screenshot_path,
                organization,
                domain,
                serial_number
            )
            result['evidence_pdf_path'] = pdf_path
        
        return result


# Helper function for synchronous usage
def capture_evidence(domain: str, organization: str, serial_number: int, url: str = None):
    """Synchronous wrapper for screenshot capture"""
    capturer = ScreenshotCapturer()
    return asyncio.run(capturer.capture_and_generate_evidence(domain, organization, serial_number, url))


# Example usage
if __name__ == "__main__":
    # Test
    result = capture_evidence(
        domain="example-phishing.com",
        organization="SBI",
        serial_number=1,
        url="http://example.com"
    )
    
    print(f"Screenshot: {result['screenshot_path']}")
    print(f"Evidence PDF: {result['evidence_pdf_path']}")

