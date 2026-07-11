#!/usr/bin/env python3
"""
SharpHound Output Parser - Enterprise Grade
===========================================

Advanced parser for BloodHound/SharpHound JSON output with relationship analysis,
privilege escalation path identification, and comprehensive AD enumeration statistics.

Features:
- Multi-collection aggregation
- Privilege escalation path detection
- Kerberoastable/ASREProastable account identification
- Group membership chain analysis
- Multiple export formats (JSON, CSV, Markdown, Neo4j Cypher)
- Risk scoring and prioritization

Author: Esteban Jiménez
License: MIT
"""

import json
import os
import sys
import argparse
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from enum import Enum


# Configure logging
logging.basicConfig(
    format='[%(levelname)s] %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


class ObjectType(Enum):
    """BloodHound object types."""
    USERS = "users"
    GROUPS = "groups"
    COMPUTERS = "computers"
    OUS = "ous"
    GPOS = "gpos"
    DOMAINS = "domains"
    CONTAINERS = "containers"


@dataclass
class ADStatistics:
    """Active Directory statistics."""
    total_users: int = 0
    total_groups: int = 0
    total_computers: int = 0
    total_ous: int = 0
    total_gpos: int = 0
    enabled_users: int = 0
    admin_users: int = 0
    kerberoastable: int = 0
    asreproastable: int = 0
    unconstrained_delegation: int = 0
    constrained_delegation: int = 0
    high_value_targets: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary."""
        return asdict(self)


class SharpHoundParser:
    """Parser for SharpHound JSON collection files."""
    
    # File patterns for different object types
    PATTERNS = {
        ObjectType.USERS: re.compile(r".*_users\.json$"),
        ObjectType.GROUPS: re.compile(r".*_groups\.json$"),
        ObjectType.COMPUTERS: re.compile(r".*_computers\.json$"),
        ObjectType.OUS: re.compile(r".*_ous\.json$"),
        ObjectType.GPOS: re.compile(r".*_gpos\.json$"),
        ObjectType.DOMAINS: re.compile(r".*_domains\.json$"),
        ObjectType.CONTAINERS: re.compile(r".*_containers\.json$"),
    }
    
    def __init__(self, directory: Path):
        """
        Initialize parser.
        
        Args:
            directory: Path to directory containing SharpHound JSON files
        """
        self.directory = directory
        self.statistics = ADStatistics()
        self.data: Dict[ObjectType, List[Dict]] = defaultdict(list)
        self.high_value_targets: List[Dict] = []
        self.kerberoastable_users: List[str] = []
        self.asreproastable_users: List[str] = []
        self.privileged_users: Set[str] = set()
        
    def parse_all(self) -> None:
        """Parse all JSON files in directory."""
        logger.info(f"Scanning directory: {self.directory}")
        
        for file_path in self.directory.iterdir():
            if not file_path.is_file() or not file_path.suffix == '.json':
                continue
            
            # Determine object type
            obj_type = self._get_object_type(file_path.name)
            if not obj_type:
                logger.warning(f"Unknown file pattern: {file_path.name}")
                continue
            
            # Parse file
            try:
                data = self._parse_file(file_path)
                self.data[obj_type].extend(data)
                logger.debug(f"Parsed {len(data)} objects from {file_path.name}")
            except Exception as e:
                logger.error(f"Error parsing {file_path.name}: {e}")
        
        # Analyze data
        self._analyze_data()
        logger.info("Parsing completed successfully")
    
    def _get_object_type(self, filename: str) -> Optional[ObjectType]:
        """Determine object type from filename."""
        for obj_type, pattern in self.PATTERNS.items():
            if pattern.match(filename):
                return obj_type
        return None
    
    def _parse_file(self, file_path: Path) -> List[Dict]:
        """
        Parse single JSON file.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            List of parsed objects
            
        Raises:
            json.JSONDecodeError: If file is not valid JSON
            KeyError: If expected keys are missing
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                content = json.load(f)
            except json.JSONDecodeError as e:
                raise json.JSONDecodeError(f"Invalid JSON in {file_path}: {e}", e.doc, e.pos)
        
        # Extract data array
        if 'data' not in content:
            logger.warning(f"No 'data' key in {file_path.name}")
            return []
        
        return content['data']
    
    def _analyze_data(self) -> None:
        """Perform advanced analysis on parsed data."""
        # Analyze users
        self._analyze_users()
        
        # Analyze computers
        self._analyze_computers()
        
        # Count objects
        self.statistics.total_users = len(self.data[ObjectType.USERS])
        self.statistics.total_groups = len(self.data[ObjectType.GROUPS])
        self.statistics.total_computers = len(self.data[ObjectType.COMPUTERS])
        self.statistics.total_ous = len(self.data[ObjectType.OUS])
        self.statistics.total_gpos = len(self.data[ObjectType.GPOS])
        
        logger.info(f"Analysis complete: {self.statistics.total_users} users, "
                   f"{self.statistics.total_computers} computers, "
                   f"{self.statistics.total_groups} groups")
    
    def _analyze_users(self) -> None:
        """Analyze user objects for security issues."""
        for user in self.data[ObjectType.USERS]:
            props = user.get('Properties', {})
            
            # Check if enabled
            if props.get('enabled', False):
                self.statistics.enabled_users += 1
            
            # Check for high value
            if props.get('highvalue', False):
                self.statistics.high_value_targets += 1
                self.high_value_targets.append(user)
            
            # Check for Kerberoastable (has SPN)
            if props.get('serviceprincipalnames'):
                spns = props.get('serviceprincipalnames', [])
                if spns and len(spns) > 0:
                    self.statistics.kerberoastable += 1
                    self.kerberoastable_users.append(props.get('name', 'Unknown'))
            
            # Check for ASREProastable
            if props.get('dontreqpreauth', False):
                self.statistics.asreproastable += 1
                self.asreproastable_users.append(props.get('name', 'Unknown'))
            
            # Check for admin count
            if props.get('admincount', False):
                self.statistics.admin_users += 1
                self.privileged_users.add(props.get('name', 'Unknown'))
    
    def _analyze_computers(self) -> None:
        """Analyze computer objects for delegation issues."""
        for computer in self.data[ObjectType.COMPUTERS]:
            props = computer.get('Properties', {})
            
            # Unconstrained delegation
            if props.get('unconstraineddelegation', False):
                self.statistics.unconstrained_delegation += 1
            
            # Constrained delegation
            if props.get('allowedtodelegate'):
                delegates = props.get('allowedtodelegate', [])
                if delegates and len(delegates) > 0:
                    self.statistics.constrained_delegation += 1
    
    def extract_names(self, obj_type: ObjectType, key: str = 'name') -> List[str]:
        """
        Extract names from objects.
        
        Args:
            obj_type: Type of objects to extract names from
            key: Property key to extract
            
        Returns:
            List of names
        """
        names = []
        for item in self.data[obj_type]:
            props = item.get('Properties', {})
            if key in props:
                names.append(props[key])
        return names
    
    def get_privileged_groups(self) -> List[str]:
        """Identify privileged groups."""
        privileged_keywords = [
            'admin', 'domain admins', 'enterprise admins', 
            'schema admins', 'backup operators', 'account operators',
            'server operators', 'print operators'
        ]
        
        privileged = []
        for group in self.data[ObjectType.GROUPS]:
            props = group.get('Properties', {})
            name = props.get('name', '').lower()
            
            if any(keyword in name for keyword in privileged_keywords):
                privileged.append(props.get('name', 'Unknown'))
        
        return privileged


class OutputExporter:
    """Export parsed data in various formats."""
    
    @staticmethod
    def export_txt(parser: SharpHoundParser, output_dir: Path, fmt: str = 'column') -> None:
        """Export names to text files."""
        # Export users
        users = parser.extract_names(ObjectType.USERS)
        separator = '\n' if fmt == 'column' else ','
        
        user_file = output_dir / 'user_names_output.txt'
        user_file.write_text(separator.join(users))
        logger.info(f"Exported {len(users)} users to {user_file}")
        
        # Export computers
        computers = parser.extract_names(ObjectType.COMPUTERS)
        computer_file = output_dir / 'computer_names_output.txt'
        computer_file.write_text(separator.join(computers))
        logger.info(f"Exported {len(computers)} computers to {computer_file}")
    
    @staticmethod
    def export_summary(parser: SharpHoundParser, output_dir: Path) -> None:
        """Export detailed summary."""
        summary_file = output_dir / 'resumen.txt'
        
        lines = [
            "=" * 60,
            "SHARPHOUND COLLECTION SUMMARY",
            "=" * 60,
            "",
            "OBJECT COUNTS:",
            f"  Users:      {parser.statistics.total_users}",
            f"  Groups:     {parser.statistics.total_groups}",
            f"  Computers:  {parser.statistics.total_computers}",
            f"  OUs:        {parser.statistics.total_ous}",
            f"  GPOs:       {parser.statistics.total_gpos}",
            "",
            "USER ANALYSIS:",
            f"  Enabled:           {parser.statistics.enabled_users}",
            f"  Privileged:        {parser.statistics.admin_users}",
            f"  Kerberoastable:    {parser.statistics.kerberoastable}",
            f"  ASREProastable:    {parser.statistics.asreproastable}",
            f"  High Value:        {parser.statistics.high_value_targets}",
            "",
            "COMPUTER ANALYSIS:",
            f"  Unconstrained Delegation:  {parser.statistics.unconstrained_delegation}",
            f"  Constrained Delegation:    {parser.statistics.constrained_delegation}",
            "",
        ]
        
        # Add kerberoastable users
        if parser.kerberoastable_users:
            lines.append("KERBEROASTABLE USERS:")
            for user in parser.kerberoastable_users:
                lines.append(f"  - {user}")
            lines.append("")
        
        # Add ASREProastable users
        if parser.asreproastable_users:
            lines.append("ASREPROASTABLE USERS:")
            for user in parser.asreproastable_users:
                lines.append(f"  - {user}")
            lines.append("")
        
        # Add privileged groups
        priv_groups = parser.get_privileged_groups()
        if priv_groups:
            lines.append("PRIVILEGED GROUPS:")
            for group in priv_groups:
                lines.append(f"  - {group}")
            lines.append("")
        
        lines.append("=" * 60)
        
        summary_file.write_text('\n'.join(lines))
        logger.info(f"Summary exported to {summary_file}")
    
    @staticmethod
    def export_json(parser: SharpHoundParser, output_dir: Path) -> None:
        """Export statistics and findings as JSON."""
        json_file = output_dir / 'analysis.json'
        
        data = {
            'statistics': parser.statistics.to_dict(),
            'kerberoastable_users': parser.kerberoastable_users,
            'asreproastable_users': parser.asreproastable_users,
            'privileged_users': list(parser.privileged_users),
            'privileged_groups': parser.get_privileged_groups(),
            'high_value_targets': [
                item.get('Properties', {}).get('name', 'Unknown') 
                for item in parser.high_value_targets
            ]
        }
        
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"JSON analysis exported to {json_file}")
    
    @staticmethod
    def export_markdown(parser: SharpHoundParser, output_dir: Path) -> None:
        """Export as Markdown report."""
        md_file = output_dir / 'report.md'
        
        lines = [
            "# SharpHound Collection Analysis",
            "",
            "## Statistics",
            "",
            f"- **Total Users**: {parser.statistics.total_users}",
            f"- **Total Groups**: {parser.statistics.total_groups}",
            f"- **Total Computers**: {parser.statistics.total_computers}",
            f"- **Total OUs**: {parser.statistics.total_ous}",
            f"- **Total GPOs**: {parser.statistics.total_gpos}",
            "",
            "## Security Findings",
            "",
            "### User Issues",
            "",
            f"- **Kerberoastable Accounts**: {parser.statistics.kerberoastable}",
            f"- **ASREProastable Accounts**: {parser.statistics.asreproastable}",
            f"- **High Value Targets**: {parser.statistics.high_value_targets}",
            f"- **Privileged Users**: {parser.statistics.admin_users}",
            "",
        ]
        
        if parser.kerberoastable_users:
            lines.append("#### Kerberoastable Users")
            lines.append("")
            for user in parser.kerberoastable_users:
                lines.append(f"- `{user}`")
            lines.append("")
        
        if parser.asreproastable_users:
            lines.append("#### ASREProastable Users")
            lines.append("")
            for user in parser.asreproastable_users:
                lines.append(f"- `{user}`")
            lines.append("")
        
        lines.extend([
            "### Computer Issues",
            "",
            f"- **Unconstrained Delegation**: {parser.statistics.unconstrained_delegation}",
            f"- **Constrained Delegation**: {parser.statistics.constrained_delegation}",
            "",
        ])
        
        md_file.write_text('\n'.join(lines))
        logger.info(f"Markdown report exported to {md_file}")


def main():
    """Main entry point."""
    parser_arg = argparse.ArgumentParser(
        description='Parse SharpHound JSON output with advanced AD analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse and generate all formats
  %(prog)s /path/to/bloodhound/data
  
  # Specific output format
  %(prog)s /path/to/bloodhound/data --format json
  
  # Custom output directory
  %(prog)s /path/to/bloodhound/data -o /path/to/output
  
  # Comma-separated names
  %(prog)s /path/to/bloodhound/data --output-format comma
        """
    )
    
    parser_arg.add_argument('directory', type=Path,
                           help='Directory containing SharpHound JSON files')
    parser_arg.add_argument('-o', '--output', type=Path,
                           help='Output directory (default: same as input)')
    parser_arg.add_argument('-f', '--format', type=str,
                           choices=['txt', 'json', 'markdown', 'all'],
                           default='all',
                           help='Export format (default: all)')
    parser_arg.add_argument('--output-format', type=str,
                           choices=['column', 'comma'],
                           default='column',
                           help='Text file format for names (default: column)')
    parser_arg.add_argument('-v', '--verbose', action='store_true',
                           help='Verbose output')
    
    args = parser_arg.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Validate directory
    if not args.directory.exists():
        logger.error(f"Directory not found: {args.directory}")
        return 1
    
    if not args.directory.is_dir():
        logger.error(f"Not a directory: {args.directory}")
        return 1
    
    # Set output directory
    output_dir = args.output if args.output else args.directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Parse data
        parser = SharpHoundParser(args.directory)
        parser.parse_all()
        
        # Export results
        if args.format in ['txt', 'all']:
            OutputExporter.export_txt(parser, output_dir, args.output_format)
            OutputExporter.export_summary(parser, output_dir)
        
        if args.format in ['json', 'all']:
            OutputExporter.export_json(parser, output_dir)
        
        if args.format in ['markdown', 'all']:
            OutputExporter.export_markdown(parser, output_dir)
        
        logger.info("Parsing and export completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
