from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
from typing import Dict, Any
import os
from backend.config import settings


class PhishingReportGenerator:
    """Generate PDF reports for detected phishing sites"""
    
    def __init__(self):
        self.reports_dir = settings.REPORTS_DIR
        os.makedirs(self.reports_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.red,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.orange,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.green,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
    
    def generate_report(
        self,
        phishing_data: Dict[str, Any],
        output_filename: str = None
    ) -> str:
        """
        Generate a comprehensive PDF report
        Returns the path to the generated PDF
        """
        if not output_filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            domain = phishing_data.get('phishing_domain', 'unknown').replace('.', '_')
            org = phishing_data.get('organization_name', 'Unknown').replace(' ', '_')
            risk_level = phishing_data.get('risk_level', 'Unknown').lower()
            output_filename = f"Phishing_Report_{org}_{domain}_{risk_level}_{timestamp}.pdf"
        
        filepath = os.path.join(self.reports_dir, output_filename)
        
        # Create PDF document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Add content
        elements.extend(self._create_header(phishing_data))
        elements.extend(self._create_executive_summary(phishing_data))
        elements.extend(self._create_risk_assessment(phishing_data))
        elements.extend(self._create_domain_intelligence(phishing_data))
        elements.extend(self._create_network_information(phishing_data))
        elements.extend(self._create_screenshots_section(phishing_data))
        elements.extend(self._create_recommendations())
        
        # Build PDF
        doc.build(elements)
        
        return filepath
    
    def _create_header(self, data: Dict[str, Any]) -> list:
        """Create report header"""
        elements = []
        
        # Title
        title = Paragraph(
            "PHISHING DETECTION REPORT",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Report metadata
        metadata_data = [
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Detection Date:', data.get('detected_at', 'N/A')],
            ['Report ID:', str(data.get('id', 'N/A'))],
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        
        elements.append(metadata_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_executive_summary(self, data: Dict[str, Any]) -> list:
        """Create executive summary"""
        elements = []
        
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        summary_data = [
            ['Legitimate Domain:', data.get('legitimate_domain', 'N/A')],
            ['Phishing Domain:', data.get('phishing_domain', 'N/A')],
            ['Variation Type:', data.get('variation_type', 'N/A')],
            ['Risk Score:', f"{data.get('risk_score', 0)}/100"],
            ['Risk Level:', data.get('risk_level', 'N/A')],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_risk_assessment(self, data: Dict[str, Any]) -> list:
        """Create risk assessment section"""
        elements = []
        
        elements.append(Paragraph("RISK ASSESSMENT", self.styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Risk level with color
        risk_level = data.get('risk_level', 'UNKNOWN')
        risk_score = data.get('risk_score', 0)
        
        if risk_level == 'HIGH':
            risk_style = 'RiskHigh'
        elif risk_level == 'MEDIUM':
            risk_style = 'RiskMedium'
        else:
            risk_style = 'RiskLow'
        
        risk_text = Paragraph(
            f"RISK LEVEL: {risk_level} ({risk_score}/100)",
            self.styles[risk_style]
        )
        elements.append(risk_text)
        elements.append(Spacer(1, 0.2*inch))
        
        # Risk factors
        risk_factors_data = [
            ['Risk Factor', 'Score', 'Assessment'],
            ['Visual Similarity', 
             f"{data.get('visual_similarity_score', 0)}/100",
             self._assess_visual_similarity(data.get('visual_similarity_score', 0))],
            ['Domain Age', 
             'See details',
             'Newer domains are higher risk'],
            ['Login Form Present', 
             'Yes' if data.get('has_login_form') else 'No',
             'Credential harvesting risk' if data.get('has_login_form') else 'Low risk'],
            ['Payment Form Present', 
             'Yes' if data.get('has_payment_form') else 'No',
             'Financial fraud risk' if data.get('has_payment_form') else 'Low risk'],
        ]
        
        risk_table = Table(risk_factors_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
        risk_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a4a4a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_domain_intelligence(self, data: Dict[str, Any]) -> list:
        """Create domain intelligence section"""
        elements = []
        
        elements.append(Paragraph("DOMAIN INTELLIGENCE", self.styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        intel_data = [
            ['Field', 'Value'],
            ['Domain Created', data.get('domain_created_at', 'Unknown')],
            ['Registrar', data.get('registrar', 'Unknown')],
            ['Country', data.get('country', 'Unknown')],
            ['ASN', data.get('asn', 'Unknown')],
        ]
        
        intel_table = Table(intel_data, colWidths=[2*inch, 4*inch])
        intel_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a4a4a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(intel_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_network_information(self, data: Dict[str, Any]) -> list:
        """Create network information section"""
        elements = []
        
        elements.append(Paragraph("NETWORK INFORMATION", self.styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        network_data = [
            ['Field', 'Value'],
            ['IP Address', data.get('ip_address', 'Unknown')],
            ['Subnet', data.get('subnet', 'Unknown')],
            ['SSL Issuer', data.get('ssl_issuer', 'None')],
        ]
        
        # Add MX records if available
        mx_records = data.get('mx_records', [])
        if mx_records:
            mx_str = ', '.join([f"{mx.get('host', 'N/A')}" for mx in mx_records[:3]])
            network_data.append(['MX Records', mx_str])
        
        network_table = Table(network_data, colWidths=[2*inch, 4*inch])
        network_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a4a4a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(network_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_screenshots_section(self, data: Dict[str, Any]) -> list:
        """Create screenshots comparison section"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("VISUAL COMPARISON", self.styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Add screenshots if available
        screenshot_path = data.get('screenshot_path')
        
        if screenshot_path and os.path.exists(screenshot_path):
            elements.append(Paragraph("Phishing Site Screenshot:", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            try:
                img = Image(screenshot_path, width=6*inch, height=4*inch, kind='proportional')
                elements.append(img)
            except:
                elements.append(Paragraph("Screenshot not available", self.styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_recommendations(self) -> list:
        """Create recommendations section"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("RECOMMENDED ACTIONS", self.styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        recommendations = [
            "1. Block access to the phishing domain across your organization's network",
            "2. Report the domain to domain registrar for takedown",
            "3. Report to PhishTank and other threat intelligence platforms",
            "4. Alert users about this phishing attempt",
            "5. Monitor for additional variations of this attack",
            "6. Consider legal action if brand impersonation is severe",
            "7. Update security awareness training with this example"
        ]
        
        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _assess_visual_similarity(self, score: float) -> str:
        """Assess visual similarity score"""
        if score >= 80:
            return "Very High - Likely phishing"
        elif score >= 60:
            return "High - Suspicious"
        elif score >= 40:
            return "Medium - Monitor"
        else:
            return "Low - Less concern"


# Helper function
def generate_phishing_report(phishing_data: Dict[str, Any], filename: str = None) -> str:
    """Generate a PDF report for phishing detection"""
    generator = PhishingReportGenerator()
    return generator.generate_report(phishing_data, filename)


def generate_phishing_report_by_id(detection_id: int, filename: str = None) -> str:
    """Generate a PDF report for phishing detection by ID"""
    from backend.database import SessionLocal
    from backend.models import PhishingDetection, CSEDomain
    
    db = SessionLocal()
    try:
        # Get detection with CSE domain info
        detection = db.query(PhishingDetection).filter(PhishingDetection.id == detection_id).first()
        if not detection:
            raise ValueError(f"Detection with ID {detection_id} not found")
        
        cse_domain = db.query(CSEDomain).filter(CSEDomain.id == detection.cse_domain_id).first()
        
        # Convert to dictionary format
        phishing_data = {
            'phishing_domain': detection.phishing_domain,
            'cse_domain': cse_domain.domain if cse_domain else 'Unknown',
            'cse_organization': cse_domain.organization_name if cse_domain else 'Unknown',
            'cse_sector': cse_domain.sector if cse_domain else 'Unknown',
            'variation_type': detection.variation_type,
            'detected_at': detection.detected_at,
            'domain_created_at': detection.domain_created_at,
            'registrar': detection.registrar,
            'registrant': detection.registrant,
            'registrant_organization': detection.registrant_organization,
            'registrant_country': detection.registrant_country,
            'ip_address': detection.ip_address,
            'subnet': detection.subnet,
            'asn': detection.asn,
            'country': detection.country,
            'hosting_isp': detection.hosting_isp,
            'hosting_country': detection.hosting_country,
            'mx_records': detection.mx_records,
            'ns_records': detection.ns_records,
            'name_servers': detection.name_servers,
            'dns_records': detection.dns_records,
            'ssl_issuer': detection.ssl_issuer,
            'ssl_valid_from': detection.ssl_valid_from,
            'ssl_valid_to': detection.ssl_valid_to,
            'cert_transparency_logs': detection.cert_transparency_logs,
            'visual_similarity_score': detection.visual_similarity_score,
            'content_similarity_score': detection.content_similarity_score,
            'has_login_form': detection.has_login_form,
            'has_payment_form': detection.has_payment_form,
            'in_phishtank': detection.in_phishtank,
            'in_openphish': detection.in_openphish,
            'in_urlhaus': detection.in_urlhaus,
            'risk_score': detection.risk_score,
            'risk_level': detection.risk_level,
            'screenshot_path': detection.screenshot_path,
            'source_of_detection': detection.source_of_detection,
            'detection_method': detection.detection_method,
            'social_media_platform': detection.social_media_platform,
            'social_media_post_url': detection.social_media_post_url,
            'detection_metadata': detection.detection_metadata
        }
        
        generator = PhishingReportGenerator()
        return generator.generate_report(phishing_data, filename)
        
    finally:
        db.close()

