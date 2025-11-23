"""
PS-02 Deduplication Script
Removes duplicate entries from Excel file and evidence folder
"""

import os
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any
import shutil


class PS02Deduplicator:
    def __init__(self, submission_path: str):
        self.submission_path = Path(submission_path)
        self.excel_path = self.submission_path / "PS-02_AIGR-123456_Submission_Set.xlsx"
        self.evidence_path = self.submission_path / "PS-02_AIGR-123456_Evidences"
        
    def deduplicate_submission(self) -> Dict[str, Any]:
        """Remove duplicates from Excel and evidence folder"""
        print("🔍 Analyzing duplicates...")
        
        # Read Excel file
        df = pd.read_excel(self.excel_path)
        original_count = len(df)
        
        print(f"📊 Original data: {original_count} rows")
        print(f"📊 Unique domains: {df['Identified Phishing/Suspected Domain Name'].nunique()}")
        
        # Find duplicates
        duplicates = df['Identified Phishing/Suspected Domain Name'].value_counts()
        duplicate_domains = duplicates[duplicates > 1].index.tolist()
        
        print(f"🔍 Found {len(duplicate_domains)} domains with duplicates")
        
        # Keep only the first occurrence of each domain (best quality)
        df_deduplicated = df.drop_duplicates(subset=['Identified Phishing/Suspected Domain Name'], keep='first')
        
        print(f"✅ After deduplication: {len(df_deduplicated)} rows")
        print(f"📉 Removed: {original_count - len(df_deduplicated)} duplicate entries")
        
        # Update serial numbers
        df_deduplicated = df_deduplicated.reset_index(drop=True)
        df_deduplicated.index = df_deduplicated.index + 1
        
        # Update evidence file names with new serial numbers
        df_deduplicated['Evidence file name'] = df_deduplicated.apply(
            lambda row: self._update_evidence_filename(row['Evidence file name'], row.name), 
            axis=1
        )
        
        # Save deduplicated Excel file
        df_deduplicated.to_excel(self.excel_path, index=False, engine='openpyxl')
        print(f"💾 Updated Excel file: {self.excel_path}")
        
        # Clean up evidence folder
        evidence_cleanup_result = self._cleanup_evidence_folder(df_deduplicated)
        
        return {
            'original_count': original_count,
            'deduplicated_count': len(df_deduplicated),
            'removed_count': original_count - len(df_deduplicated),
            'evidence_files_removed': evidence_cleanup_result['removed_count'],
            'evidence_files_kept': evidence_cleanup_result['kept_count']
        }
    
    def _update_evidence_filename(self, old_filename: str, new_serial: int) -> str:
        """Update evidence filename with new serial number"""
        # Extract CSE and domain parts
        parts = old_filename.split('_')
        if len(parts) >= 3:
            cse_part = parts[0]
            domain_part = '_'.join(parts[1:-1])  # Everything except first and last
            return f"{cse_part}_{domain_part}_{new_serial}.pdf"
        return old_filename
    
    def _cleanup_evidence_folder(self, df_deduplicated: pd.DataFrame) -> Dict[str, int]:
        """Remove duplicate evidence files and rename remaining ones"""
        if not self.evidence_path.exists():
            return {'removed_count': 0, 'kept_count': 0}
        
        print("🧹 Cleaning up evidence folder...")
        
        # Get list of evidence files that should be kept
        valid_evidence_files = set(df_deduplicated['Evidence file name'].tolist())
        
        # Create backup of evidence folder
        backup_path = self.evidence_path.parent / f"{self.evidence_path.name}_backup"
        if backup_path.exists():
            shutil.rmtree(backup_path)
        shutil.copytree(self.evidence_path, backup_path)
        print(f"📦 Created backup: {backup_path}")
        
        # Count files before cleanup
        all_files = list(self.evidence_path.glob("*.pdf"))
        original_file_count = len(all_files)
        
        # Remove files that are not in the valid list
        removed_count = 0
        kept_count = 0
        
        for file_path in all_files:
            filename = file_path.name
            if filename in valid_evidence_files:
                kept_count += 1
            else:
                file_path.unlink()  # Delete the file
                removed_count += 1
        
        print(f"📁 Evidence files - Original: {original_file_count}, Kept: {kept_count}, Removed: {removed_count}")
        
        return {
            'removed_count': removed_count,
            'kept_count': kept_count
        }
    
    def generate_clean_zip(self, output_path: str = None) -> str:
        """Generate a clean ZIP file with deduplicated data"""
        import zipfile
        
        if output_path is None:
            output_path = self.submission_path.parent / "PS02_AIGR-123456_Clean_Submission.zip"
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.submission_path):
                for file in files:
                    file_path = Path(root) / file
                    arc_path = file_path.relative_to(self.submission_path.parent)
                    zipf.write(file_path, arc_path)
        
        print(f"📦 Generated clean ZIP: {output_path}")
        return str(output_path)


def deduplicate_ps02_submission(submission_path: str = None) -> Dict[str, Any]:
    """Main function to deduplicate PS-02 submission"""
    if submission_path is None:
        submission_path = "/home/admincit/etherX/Phishing_detection/Frontend/Finaltry/ps02_submissions/PS-02_AIGR-123456_Submission"
    
    deduplicator = PS02Deduplicator(submission_path)
    result = deduplicator.deduplicate_submission()
    
    # Generate clean ZIP
    clean_zip_path = deduplicator.generate_clean_zip()
    result['clean_zip_path'] = clean_zip_path
    
    return result


if __name__ == "__main__":
    result = deduplicate_ps02_submission()
    print("\n🎉 Deduplication completed!")
    print(f"📊 Results: {result}")
