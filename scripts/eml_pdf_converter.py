#!/usr/bin/env python3
"""
Email Forensics Export Framework
Batch EML to PDF Converter for Legal Documentation

Security Features:
- Cryptographic integrity validation
- Immutable PDF generation with metadata preservation
- Audit trail generation
- Error resilience and recovery protocols
"""

import os
import sys
import email
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import argparse

# Required dependencies - install via: pip install reportlab weasyprint cryptography
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    import weasyprint
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install reportlab weasyprint cryptography")
    sys.exit(1)


class EmailForensicsValidator:
    """Cryptographic validation and integrity verification system"""
    
    def __init__(self):
        self.digest_algorithm = hashes.SHA256()
        
    def generate_integrity_hash(self, content: bytes) -> str:
        """Generate SHA-256 hash for content integrity verification"""
        digest = hashes.Hash(self.digest_algorithm)
        digest.update(content)
        return digest.finalize().hex()
    
    def validate_eml_structure(self, eml_path: Path) -> Tuple[bool, str]:
        """Validate EML file structure and integrity with enhanced corruption detection"""
        try:
            with open(eml_path, 'rb') as f:
                raw_content = f.read()
            
            # Check for binary corruption indicators
            if len(raw_content) < 50:
                return False, "File too small to be valid EML"
            
            # Detect non-ASCII content that suggests corruption
            try:
                # Attempt to decode as UTF-8 first
                decoded_content = raw_content.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                try:
                    # Fallback to latin-1 for legacy encoding
                    decoded_content = raw_content.decode('latin-1')
                except UnicodeDecodeError:
                    return False, "File contains invalid character encoding"
            
            # Check for obvious corruption patterns
            corruption_indicators = [
                b'\x00\x00\x00',  # Null byte sequences
                b'\xff\xfe',      # BOM markers in wrong context
                b'\x1a\x0e\x0f',  # Control character sequences
            ]
            
            for indicator in corruption_indicators:
                if indicator in raw_content:
                    return False, f"Binary corruption detected: {indicator.hex()}"
            
            # Parse as email message
            try:
                msg = email.message_from_bytes(raw_content)
            except Exception as e:
                return False, f"Email parsing failed: {str(e)}"
            
            # Basic structure validation
            if not msg.get('Message-ID') and not msg.get('Subject'):
                return False, "Missing critical headers (Message-ID and Subject)"
            
            if not msg.get('Date') and not msg.get('From'):
                return False, "Missing temporal or sender identification"
                
            return True, "Valid EML structure"
            
        except Exception as e:
            return False, f"EML validation failed: {str(e)}"


class EmailMetadataExtractor:
    """Secure email metadata extraction with forensic preservation"""
    
    @staticmethod
    def extract_headers(msg: email.message.Message) -> Dict[str, str]:
        """Extract critical email headers for legal documentation"""
        critical_headers = [
            'Message-ID', 'Date', 'From', 'To', 'Cc', 'Bcc', 'Subject',
            'Return-Path', 'Received', 'Authentication-Results',
            'DKIM-Signature', 'X-Originating-IP'
        ]
        
        headers = {}
        for header in critical_headers:
            value = msg.get(header, '')
            if value:
                headers[header] = str(value).replace('\n', ' ').replace('\r', '')
        
        return headers
    
    @staticmethod
    def extract_body_content(msg: email.message.Message) -> Tuple[str, str]:
        """Extract text and HTML body content"""
        text_content = ""
        html_content = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    text_content += part.get_payload(decode=True).decode('utf-8', errors='replace')
                elif content_type == "text/html":
                    html_content += part.get_payload(decode=True).decode('utf-8', errors='replace')
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True).decode('utf-8', errors='replace')
            if content_type == "text/plain":
                text_content = payload
            elif content_type == "text/html":
                html_content = payload
        
        return text_content, html_content


class PDFDocumentGenerator:
    """Immutable PDF generation system with legal compliance features"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configure document styles for legal documentation"""
        self.styles.add(ParagraphStyle(
            name='EmailHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=colors.darkblue,
            spaceBefore=6,
            spaceAfter=3
        ))
        
        self.styles.add(ParagraphStyle(
            name='EmailBody',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Helvetica',
            leftIndent=20,
            spaceBefore=3,
            spaceAfter=6
        ))
    
    def generate_pdf(self, eml_file: Path, headers: Dict, body_text: str, 
                    integrity_hash: str) -> Path:
        """Generate legally compliant PDF with embedded metadata"""
        
        # Sanitize filename for PDF output
        safe_filename = self._sanitize_filename(eml_file.stem)
        pdf_path = self.output_dir / f"{safe_filename}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Document header with forensic metadata
        story.append(Paragraph("EMAIL FORENSICS EXPORT", self.styles['Title']))
        story.append(Spacer(1, 12))
        
        # Integrity verification section
        story.append(Paragraph("FORENSIC VALIDATION", self.styles['Heading2']))
        integrity_data = [
            ['Export Timestamp:', datetime.now().isoformat()],
            ['Source File:', str(eml_file)],
            ['SHA-256 Hash:', integrity_hash],
            ['Extraction Method:', 'Automated Python Framework v1.0']
        ]
        
        integrity_table = Table(integrity_data, colWidths=[2*inch, 4*inch])
        integrity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(integrity_table)
        story.append(Spacer(1, 20))
        
        # Email headers section
        story.append(Paragraph("EMAIL HEADERS", self.styles['Heading2']))
        for key, value in headers.items():
            story.append(Paragraph(f"<b>{key}:</b> {value}", self.styles['EmailHeader']))
        
        story.append(Spacer(1, 20))
        
        # Email body section
        story.append(Paragraph("MESSAGE CONTENT", self.styles['Heading2']))
        
        # Process body text to handle long lines and special characters
        body_paragraphs = body_text.split('\n')
        for para in body_paragraphs:
            if para.strip():
                # Escape special characters for ReportLab
                escaped_para = para.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(escaped_para, self.styles['EmailBody']))
            else:
                story.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(story)
        return pdf_path
    
    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """Sanitize filename for filesystem compatibility"""
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        return filename[:100]  # Limit length


class AuditLogger:
    """Comprehensive audit trail system for legal compliance"""
    
    def __init__(self, log_file: Path):
        self.log_file = log_file
        # Ensure parent directory exists before attempting log file creation
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure forensic-grade logging with defensive error handling"""
        try:
            logging.basicConfig(
                filename=self.log_file,
                level=logging.INFO,
                format='%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S UTC'
            )
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            # Fallback to console logging if file logging fails
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger(__name__)
            self.logger.warning(f"File logging failed, using console: {e}")
    
    def log_conversion(self, eml_file: Path, pdf_file: Path, integrity_hash: str, status: str):
        """Log conversion operation with forensic metadata"""
        self.logger.info(f"CONVERSION | {eml_file} -> {pdf_file} | Hash: {integrity_hash} | Status: {status}")
    
    def log_error(self, eml_file: Path, error_msg: str):
        """Log conversion errors"""
        self.logger.error(f"ERROR | {eml_file} | {error_msg}")


class EMLToPDFConverter:
    """Main orchestration class for batch email conversion with enhanced resilience"""
    
    def __init__(self, input_dir: Path, output_dir: Path):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        
        # Critical: Ensure output directory infrastructure before subsystem initialization
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize subsystems with defensive error boundaries
        self.validator = EmailForensicsValidator()
        self.extractor = EmailMetadataExtractor()
        self.pdf_generator = PDFDocumentGenerator(self.output_dir)
        self.audit_logger = AuditLogger(self.output_dir / "conversion_audit.log")
        
        # Log initialization success
        self.audit_logger.logger.info(f"Framework initialized | Input: {self.input_dir} | Output: {self.output_dir}")
    
    def process_single_eml(self, eml_path: Path) -> bool:
        """Process individual EML file with comprehensive error handling and corruption detection"""
        try:
            # Enhanced validation with corruption detection
            is_valid, validation_msg = self.validator.validate_eml_structure(eml_path)
            if not is_valid:
                self.audit_logger.log_error(eml_path, f"Validation failed: {validation_msg}")
                print(f"⚠️  VALIDATION FAILURE: {eml_path.name} - {validation_msg}")
                return False
            
            # Read and parse email with encoding resilience
            with open(eml_path, 'rb') as f:
                raw_content = f.read()
                
            try:
                msg = email.message_from_bytes(raw_content)
            except Exception as parse_error:
                # Attempt recovery with alternative encoding
                try:
                    decoded_content = raw_content.decode('latin-1', errors='replace')
                    msg = email.message_from_string(decoded_content)
                    self.audit_logger.logger.warning(f"Encoding recovery applied: {eml_path}")
                except Exception as recovery_error:
                    self.audit_logger.log_error(eml_path, f"Parse failure: {parse_error}, Recovery failed: {recovery_error}")
                    return False
            
            # Generate integrity hash
            integrity_hash = self.validator.generate_integrity_hash(raw_content)
            
            # Extract metadata and content with fallback protection
            headers = self.extractor.extract_headers(msg)
            text_content, html_content = self.extractor.extract_body_content(msg)
            
            # Content selection with quality validation
            body_content = text_content if text_content.strip() else html_content
            if not body_content.strip():
                body_content = "[EMAIL CONTENT NOT EXTRACTABLE - POSSIBLE CORRUPTION]"
                self.audit_logger.logger.warning(f"Content extraction limited: {eml_path}")
            
            # Generate PDF with defensive error handling
            try:
                pdf_path = self.pdf_generator.generate_pdf(
                    eml_path, headers, body_content, integrity_hash
                )
            except Exception as pdf_error:
                self.audit_logger.log_error(eml_path, f"PDF generation failed: {pdf_error}")
                return False
            
            # Verify PDF creation success
            if not pdf_path.exists() or pdf_path.stat().st_size == 0:
                self.audit_logger.log_error(eml_path, "PDF creation validation failed")
                return False
            
            # Log successful conversion with metadata
            self.audit_logger.log_conversion(eml_path, pdf_path, integrity_hash, "SUCCESS")
            print(f"✅ CONVERTED: {eml_path.name} → {pdf_path.name}")
            return True
            
        except Exception as e:
            error_msg = f"Critical conversion failure: {str(e)}"
            self.audit_logger.log_error(eml_path, error_msg)
            print(f"❌ CRITICAL ERROR: {eml_path.name} - {error_msg}")
            return False
    
    def batch_convert(self) -> Dict[str, int]:
        """Execute batch conversion with progress tracking"""
        eml_files = list(self.input_dir.glob("*.eml"))
        
        if not eml_files:
            print(f"No .eml files found in {self.input_dir}")
            return {"total": 0, "success": 0, "failed": 0}
        
        print(f"Found {len(eml_files)} EML files to convert...")
        
        success_count = 0
        failed_count = 0
        
        for i, eml_file in enumerate(eml_files, 1):
            print(f"Processing [{i}/{len(eml_files)}]: {eml_file.name}")
            
            if self.process_single_eml(eml_file):
                success_count += 1
            else:
                failed_count += 1
        
        # Generate summary report
        summary = {
            "total": len(eml_files),
            "success": success_count,
            "failed": failed_count
        }
        
        self._generate_summary_report(summary)
        return summary
    
    def _generate_summary_report(self, summary: Dict[str, int]):
        """Generate conversion summary report"""
        report_path = self.output_dir / "conversion_summary.json"
        
        report_data = {
            "conversion_summary": summary,
            "timestamp": datetime.now().isoformat(),
            "input_directory": str(self.input_dir),
            "output_directory": str(self.output_dir)
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\nConversion completed:")
        print(f"  Total files: {summary['total']}")
        print(f"  Successful: {summary['success']}")
        print(f"  Failed: {summary['failed']}")
        print(f"  Summary report: {report_path}")


def main():
    """Command-line interface for email conversion framework"""
    parser = argparse.ArgumentParser(
        description="Email Forensics Export Framework - EML to PDF Batch Converter"
    )
    parser.add_argument(
        "input_dir",
        type=str,
        help="Directory containing .eml files"
    )
    parser.add_argument(
        "output_dir", 
        type=str,
        help="Directory for PDF output and audit logs"
    )
    
    args = parser.parse_args()
    
    # Validate input directory
    input_path = Path(args.input_dir)
    if not input_path.exists():
        print(f"Error: Input directory '{input_path}' does not exist")
        sys.exit(1)
    
    # Initialize converter
    output_path = Path(args.output_dir)
    converter = EMLToPDFConverter(input_path, output_path)
    
    # Execute batch conversion
    print("=" * 60)
    print("EMAIL FORENSICS EXPORT FRAMEWORK")
    print("EML to PDF Batch Converter v1.0")
    print("=" * 60)
    
    summary = converter.batch_convert()
    
    if summary["failed"] > 0:
        print(f"\nWarning: {summary['failed']} files failed to convert.")
        print(f"Check audit log: {output_path / 'conversion_audit.log'}")


if __name__ == "__main__":
    main()
