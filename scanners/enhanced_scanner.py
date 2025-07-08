#!/usr/bin/env python3
"""
Enhanced Dependency Scanner that focuses on requirements.txt parsing
"""
import json
import requests
import re
import sys
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

class EnhancedDependencyScanner:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.osv_url = "https://api.osv.dev/v1/query"
        self.headers = {"Content-Type": "application/json"}
        
    def parse_requirements(self) -> List[Dict[str, Any]]:
        """Parse requirements.txt file directly"""
        dependencies = []
        
        try:
            with open(self.file_path, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package==version or package>=version etc.
                    match = re.match(r'^([a-zA-Z0-9_-]+)([>=<~!]+)([0-9.]+)', line)
                    if match:
                        package_name = match.group(1).lower()
                        operator = match.group(2)
                        version = match.group(3)
                        
                        dependencies.append({
                            'name': package_name,
                            'version': version,
                            'operator': operator,
                            'original_line': line
                        })
                    else:
                        # Handle simple package names without versions
                        package_name = line.split()[0].lower()
                        dependencies.append({
                            'name': package_name,
                            'version': None,
                            'operator': None,
                            'original_line': line
                        })
        
        except FileNotFoundError:
            print(f"Error: Requirements file '{self.file_path}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error parsing requirements file: {e}")
            sys.exit(1)
        
        return dependencies
    
    def check_vulnerabilities(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check each dependency for vulnerabilities using OSV.dev API"""
        vulnerabilities = []
        
        print(f"Checking {len(dependencies)} dependencies from {self.file_path}...")
        print("=" * 60)
        
        for i, dep in enumerate(dependencies):
            package_name = dep['name']
            version = dep['version']
            
            print(f"[{i+1}/{len(dependencies)}] Checking {package_name}", end="")
            if version:
                print(f" {version}")
            else:
                print(" (no version specified)")
            
            # OSV API expects ecosystem-specific names
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                }
            }
            
            # Add version if available
            if version:
                payload["package"]["version"] = version
            
            try:
                response = requests.post(
                    self.osv_url, 
                    headers=self.headers, 
                    json=payload, 
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('vulnerabilities'):
                        for vuln in data['vulnerabilities']:
                            vuln['affected_package'] = {
                                'name': package_name,
                                'version': version or 'unknown',
                                'original_line': dep['original_line']
                            }
                            vulnerabilities.append(vuln)
                        print(f"  ⚠️  Found {len(data['vulnerabilities'])} vulnerabilities")
                    else:
                        print(f"  ✅ No vulnerabilities found")
                else:
                    print(f"  ❌ Error: HTTP {response.status_code}")
                    if response.status_code == 429:
                        print("  Rate limited - waiting 1 second...")
                        time.sleep(1)
                    
            except requests.RequestException as e:
                print(f"  ❌ Network error: {e}")
            
            # Small delay to avoid overwhelming the API
            time.sleep(0.1)
        
        return vulnerabilities
    
    def generate_human_readable_report(self, vulnerabilities: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]) -> None:
        """Generate human-readable console output"""
        print("\n" + "=" * 80)
        print("DEPENDENCY VULNERABILITY REPORT")
        print("=" * 80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Requirements file: {self.file_path}")
        print(f"Total dependencies: {len(dependencies)}")
        
        vulnerable_packages = list(set(v['affected_package']['name'] for v in vulnerabilities))
        print(f"Vulnerable packages: {len(vulnerable_packages)}")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        
        if vulnerabilities:
            print("\n" + "=" * 80)
            print("VULNERABILITIES FOUND")
            print("=" * 80)
            
            # Group by package
            vuln_by_package = {}
            for vuln in vulnerabilities:
                pkg_name = vuln['affected_package']['name']
                if pkg_name not in vuln_by_package:
                    vuln_by_package[pkg_name] = []
                vuln_by_package[pkg_name].append(vuln)
            
            for pkg_name, pkg_vulns in vuln_by_package.items():
                print(f"\n📦 {pkg_name.upper()}")
                print(f"   Version: {pkg_vulns[0]['affected_package']['version']}")
                print(f"   Vulnerabilities: {len(pkg_vulns)}")
                print("-" * 60)
                
                for vuln in pkg_vulns:
                    print(f"   🆔 ID: {vuln.get('id', 'N/A')}")
                    
                    # Extract severity from different possible locations
                    severity = "Unknown"
                    if vuln.get('database_specific', {}).get('severity'):
                        severity = vuln['database_specific']['severity']
                    elif vuln.get('severity'):
                        severity = vuln['severity']
                    
                    print(f"   📊 Severity: {severity}")
                    print(f"   📝 Summary: {vuln.get('summary', 'No summary available')}")
                    
                    # Show affected versions
                    if vuln.get('affected'):
                        for affected in vuln['affected']:
                            if affected.get('package', {}).get('name') == pkg_name:
                                if affected.get('ranges'):
                                    print(f"   🎯 Affected versions: {affected['ranges']}")
                    
                    # Show references
                    if vuln.get('references'):
                        print("   🔗 References:")
                        for ref in vuln['references'][:2]:  # Show first 2 references
                            print(f"      - {ref.get('url', 'N/A')}")
                    
                    print()
        else:
            print("\n✅ No vulnerabilities found!")
    
    def generate_json_report(self, vulnerabilities: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]) -> None:
        """Generate structured JSON report"""
        vulnerable_packages = list(set(v['affected_package']['name'] for v in vulnerabilities))
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "file_scanned": self.file_path,
                "total_dependencies": len(dependencies),
                "vulnerable_packages": len(vulnerable_packages),
                "total_vulnerabilities": len(vulnerabilities)
            },
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "vulnerable_packages": vulnerable_packages,
                "severity_breakdown": self._get_severity_breakdown(vulnerabilities)
            }
        }
        
        output_file = "vulnerability_report.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 JSON report saved to: {output_file}")
    
    def _get_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity"""
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for vuln in vulnerabilities:
            severity = "UNKNOWN"
            if vuln.get('database_specific', {}).get('severity'):
                severity = vuln['database_specific']['severity'].upper()
            elif vuln.get('severity'):
                severity = vuln['severity'].upper()
            
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count['UNKNOWN'] += 1
        
        return severity_count

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Dependency Risk Scanner')
    parser.add_argument('requirements', help='Path to requirements.txt file')
    parser.add_argument('--json-only', action='store_true', help='Output only JSON report')
    args = parser.parse_args()

    if not os.path.exists(args.requirements):
        print(f"Error: File '{args.requirements}' not found")
        sys.exit(1)

    scanner = EnhancedDependencyScanner(args.requirements)
    dependencies = scanner.parse_requirements()
    vulnerabilities = scanner.check_vulnerabilities(dependencies)
    
    if not args.json_only:
        scanner.generate_human_readable_report(vulnerabilities, dependencies)
    
    scanner.generate_json_report(vulnerabilities, dependencies)

if __name__ == "__main__":
    main()
