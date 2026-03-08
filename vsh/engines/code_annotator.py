"""
Code annotation engine for L1 scanner.

Injects vulnerability annotation comments directly into source code.
Supports Python (#) and JavaScript/TypeScript (//) comment styles.
"""

from pathlib import Path
from typing import Optional
from vsh.core.models import VulnRecord
from vsh.core.utils import read_text


def _get_comment_marker(file_path: str) -> str:
    """Get comment marker based on file extension."""
    lower_path = file_path.lower()
    if lower_path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
        return "//"
    # Default to Python/generic
    return "#"


def _build_annotation(vuln: VulnRecord, comment_marker: str) -> str:
    """Build annotation comment block with enhanced function-level risk information."""
    lines = [
        f"{comment_marker} ⚠️ [VSH-L1] {vuln.vuln_type} 탐지",
        f"{comment_marker} Severity: {vuln.severity}",
        f"{comment_marker} CWE: {vuln.cwe_id}",
    ]
    
    if vuln.reachability:
        lines.append(f"{comment_marker} Reachability: true")
    else:
        lines.append(f"{comment_marker} Reachability: false")
    
    if vuln.kisa_ref:
        lines.append(f"{comment_marker} KISA: {vuln.kisa_ref}")
    
    if vuln.owasp_ref:
        lines.append(f"{comment_marker} OWASP: {vuln.owasp_ref}")
    
    # Add function-level risk information if available
    if vuln.fix_suggestion:
        # Parse the enhanced fix suggestion for better formatting
        fix_lines = vuln.fix_suggestion.split('\n')
        if len(fix_lines) > 1:
            lines.append(f"{comment_marker} Function Risk: {fix_lines[0]}")
            if len(fix_lines) > 1:
                lines.append(f"{comment_marker} Safe Alternatives: {fix_lines[1]}")
            if len(fix_lines) > 2:
                lines.append(f"{comment_marker} Fix: {fix_lines[2]}")
        else:
            lines.append(f"{comment_marker} Fix: {vuln.fix_suggestion}")
    
    return "\n".join(lines)


def _check_existing_annotation(line_num: int, content: str) -> bool:
    """Check if line already has [VSH-L1] annotation."""
    lines = content.splitlines()
    
    # Check a few lines before the target line
    start = max(0, line_num - 10)
    end = min(len(lines), line_num)
    
    for i in range(start, end):
        if "[VSH-L1]" in lines[i]:
            return True
    
    return False


def annotate_files(
    vuln_records: list[VulnRecord],
    project_root: Path,
) -> dict[str, str]:
    """
    Annotate source code files with vulnerability information.
    
    Processes vulnerabilities from bottom to top (highest line first) to avoid
    line offset issues when inserting comments.
    
    Args:
        vuln_records: List of normalized vulnerability records
        project_root: Root directory of project
    
    Returns:
        Dict mapping file paths to annotated content
    """
    annotated: dict[str, str] = {}
    
    # Group vulnerabilities by file
    vulns_by_file: dict[str, list[VulnRecord]] = {}
    for vuln in vuln_records:
        if vuln.file_path.startswith("<"):  # Skip synthetic paths like "<dependency-scan>"
            continue
        
        file_path = vuln.file_path
        if file_path not in vulns_by_file:
            vulns_by_file[file_path] = []
        vulns_by_file[file_path].append(vuln)
    
    # Process each file
    for file_path, vulns in vulns_by_file.items():
        full_path = project_root / file_path
        
        if not full_path.exists():
            continue
        
        # Read original content
        try:
            content = read_text(full_path)
        except Exception:
            continue
        
        # Sort vulnerabilities by line number (descending) to process from bottom to top
        sorted_vulns = sorted(vulns, key=lambda x: x.line_number, reverse=True)
        
        # Build annotated content
        lines = content.splitlines(keepends=True)
        
        for vuln in sorted_vulns:
            # Validate line number
            if vuln.line_number > len(lines) or vuln.line_number < 1:
                continue
            
            # Check for existing annotation
            if _check_existing_annotation(vuln.line_number, content):
                continue
            
            # Build annotation
            comment_marker = _get_comment_marker(file_path)
            annotation = _build_annotation(vuln, comment_marker)
            
            # Insert annotation before the target line (1-indexed)
            insert_pos = vuln.line_number - 1  # Convert to 0-indexed
            if insert_pos < len(lines):
                # Get indentation from the target line
                target_line = lines[insert_pos]
                indent = len(target_line) - len(target_line.lstrip())
                indent_str = target_line[:indent] if indent > 0 else ""
                
                # Add indentation to annotation lines
                annotation_lines = annotation.split("\n")
                indented_annotation = "\n".join(
                    indent_str + line for line in annotation_lines
                ) + "\n"
                
                # Insert annotation
                lines.insert(insert_pos, indented_annotation)
        
        # Rebuild content
        annotated[file_path] = "".join(lines)
    
    return annotated


def write_annotated_files(
    annotated: dict[str, str],
    output_dir: Path,
    project_root: Optional[Path] = None,
) -> list[str]:
    """
    Write annotated files to output directory.
    
    Args:
        annotated: Dict of file paths to annotated content
        output_dir: Directory to write annotated files
        project_root: Original project root (to compute relative paths)
    
    Returns:
        List of written file paths
    """
    written = []
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for file_path, content in annotated.items():
        out_path = output_dir / file_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            out_path.write_text(content, encoding="utf-8")
            written.append(str(out_path))
        except Exception as e:
            print(f"Failed to write annotated file {file_path}: {e}")
    
    return written
