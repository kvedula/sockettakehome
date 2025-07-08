#!/usr/bin/env python3
"""
Multi-Ecosystem Dependency Scanner with Bonus Features
Supports Python and JavaScript ecosystems with ignore lists and maintenance checks
"""
import json
import requests
import re
import sys
import os
import time
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

class MultiEcosystemScanner:
    def __init__(self, file_path: str, ignore_file: str = ".vulnignore", maintenance_months: int = 12):
        self.file_path = file_path
        self.ignore_file = ignore_file
        self.maintenance_months = maintenance_months
        self.osv_url = "https://api.osv.dev/v1/query"
        self.pypi_url = "https://pypi.org/pypi/{}/json"
        self.npm_url = "https://registry.npmjs.org/{}"
        self.headers = {"Content-Type": "application/json"}
        self.ignored_advisories = self._load_ignore_list()
        
    def _load_ignore_list(self) -> Set[str]:
        """Load ignored advisories from ignore file"""
        ignored = set()
        if os.path.exists(self.ignore_file):
            try:
                with open(self.ignore_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ignored.add(line)
                print(f"📋 Loaded {len(ignored)} ignored advisories from {self.ignore_file}")
            except Exception as e:
                print(f"⚠️  Error loading ignore file: {e}")
        return ignored
    
    def detect_ecosystem(self) -> str:
        """Detect the ecosystem based on file name and content"""
        file_name = os.path.basename(self.file_path)
        
        if file_name in ['requirements.txt', 'requirements-dev.txt']:
            return 'python'
        elif file_name == 'package.json':
            return 'javascript'
        elif file_name in ['yarn.lock', 'package-lock.json']:
            return 'javascript'
        elif file_name.endswith('.txt') and self._looks_like_requirements():
            return 'python'
        else:
            # Try to auto-detect from content
            try:
                with open(self.file_path, 'r') as f:
                    content = f.read()
                    if '"dependencies"' in content or '"devDependencies"' in content:
                        return 'javascript'
                    elif any(op in content for op in ['==', '>=', '<=', '~=']):
                        return 'python'
            except:
                pass
        
        return 'unknown'
    
    def _looks_like_requirements(self) -> bool:
        """Check if file looks like a Python requirements file"""
        try:
            with open(self.file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if re.match(r'^[a-zA-Z0-9_-]+[>=<~!]*[0-9.]*', line):
                            return True
        except:
            pass
        return False
    
    def parse_python_dependencies(self) -> List[Dict[str, Any]]:
        """Parse Python requirements.txt file"""
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
                            'original_line': line,
                            'ecosystem': 'PyPI'
                        })
                    else:
                        # Handle simple package names without versions
                        package_name = line.split()[0].lower()
                        dependencies.append({
                            'name': package_name,
                            'version': None,
                            'operator': None,
                            'original_line': line,
                            'ecosystem': 'PyPI'
                        })
        
        except Exception as e:
            print(f"Error parsing Python dependencies: {e}")
            sys.exit(1)
        
        return dependencies
    
    def parse_javascript_dependencies(self) -> List[Dict[str, Any]]:
        """Parse JavaScript package.json file"""
        dependencies = []
        
        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
            
            # Parse dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for package_name, version_spec in data[dep_type].items():
                        # Parse version spec (e.g., "^1.0.0", "~2.3.1", ">=3.0.0")
                        version_match = re.search(r'([0-9.]+)', version_spec)
                        version = version_match.group(1) if version_match else None
                        
                        dependencies.append({
                            'name': package_name,
                            'version': version,
                            'version_spec': version_spec,
                            'dep_type': dep_type,
                            'ecosystem': 'npm'
                        })
        
        except Exception as e:
            print(f"Error parsing JavaScript dependencies: {e}")
            sys.exit(1)
        
        return dependencies
    
    def check_vulnerabilities(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check each dependency for vulnerabilities using OSV.dev API"""
        vulnerabilities = []
        
        print(f"🔍 Checking {len(dependencies)} dependencies for vulnerabilities...")
        print("=" * 60)
        
        for i, dep in enumerate(dependencies):
            package_name = dep['name']
            version = dep['version']
            ecosystem = dep['ecosystem']
            
            print(f"[{i+1}/{len(dependencies)}] Checking {package_name}", end="")
            if version:
                print(f" {version} ({ecosystem})")
            else:
                print(f" (no version, {ecosystem})")
            
            # OSV API payload
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
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
                        filtered_vulns = []
                        for vuln in data['vulnerabilities']:
                            vuln_id = vuln.get('id', '')
                            if vuln_id not in self.ignored_advisories:
                                vuln['affected_package'] = {
                                    'name': package_name,
                                    'version': version or 'unknown',
                                    'ecosystem': ecosystem,
                                    'original_line': dep.get('original_line', f"{package_name}@{version}")
                                }
                                filtered_vulns.append(vuln)
                            else:
                                print(f"    🚫 Ignored: {vuln_id}")
                        
                        vulnerabilities.extend(filtered_vulns)
                        if filtered_vulns:
                            print(f"    ⚠️  Found {len(filtered_vulns)} vulnerabilities")
                        else:
                            print(f"    ✅ No vulnerabilities (after filtering)")
                    else:
                        print(f"    ✅ No vulnerabilities found")
                else:
                    print(f"    ❌ Error: HTTP {response.status_code}")
                    if response.status_code == 429:
                        print("    Rate limited - waiting 1 second...")
                        time.sleep(1)
                    
            except requests.RequestException as e:
                print(f"    ❌ Network error: {e}")
            
            # Small delay to avoid overwhelming the API
            time.sleep(0.1)
        
        return vulnerabilities
    
    def check_maintenance_status(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check if packages are unmaintained based on last release date"""
        unmaintained = []
        cutoff_date = datetime.now() - timedelta(days=self.maintenance_months * 30)
        
        print(f"\n🔧 Checking maintenance status (packages older than {self.maintenance_months} months)...")
        print("=" * 60)
        
        for i, dep in enumerate(dependencies):
            package_name = dep['name']
            ecosystem = dep['ecosystem']
            
            print(f"[{i+1}/{len(dependencies)}] Checking {package_name} ({ecosystem})", end="")
            
            try:
                last_release = None
                
                if ecosystem == 'PyPI':
                    # Check PyPI API
                    response = requests.get(self.pypi_url.format(package_name), timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        releases = data.get('releases', {})
                        if releases:
                            # Get the latest release date
                            latest_version = max(releases.keys(), key=lambda v: releases[v][0]['upload_time'] if releases[v] else '0')
                            if releases[latest_version]:
                                last_release = datetime.fromisoformat(releases[latest_version][0]['upload_time'].replace('Z', '+00:00'))
                
                elif ecosystem == 'npm':
                    # Check npm registry API
                    response = requests.get(self.npm_url.format(package_name), timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        time_info = data.get('time', {})
                        if 'modified' in time_info:
                            last_release = datetime.fromisoformat(time_info['modified'].replace('Z', '+00:00'))
                
                if last_release:
                    days_ago = (datetime.now() - last_release.replace(tzinfo=None)).days
                    if last_release.replace(tzinfo=None) < cutoff_date:
                        unmaintained.append({
                            'package': package_name,
                            'ecosystem': ecosystem,
                            'last_release': last_release.strftime('%Y-%m-%d'),
                            'days_ago': days_ago
                        })
                        print(f" ⚠️  Unmaintained (last release: {last_release.strftime('%Y-%m-%d')})")
                    else:
                        print(f" ✅ Active (last release: {last_release.strftime('%Y-%m-%d')})")
                else:
                    print(f" ❓ Cannot determine release date")
                
            except requests.RequestException as e:
                print(f" ❌ Network error: {e}")
            except Exception as e:
                print(f" ❌ Error: {e}")
            
            time.sleep(0.1)  # Rate limiting
        
        return unmaintained
    
    def generate_human_readable_report(self, vulnerabilities: List[Dict[str, Any]], 
                                     dependencies: List[Dict[str, Any]], 
                                     unmaintained: List[Dict[str, Any]]) -> None:
        """Generate human-readable console output"""
        print("\n" + "=" * 80)
        print("MULTI-ECOSYSTEM DEPENDENCY VULNERABILITY REPORT")
        print("=" * 80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"File scanned: {self.file_path}")
        print(f"Ecosystem: {self.detect_ecosystem()}")
        print(f"Total dependencies: {len(dependencies)}")
        
        vulnerable_packages = list(set(v['affected_package']['name'] for v in vulnerabilities))
        print(f"Vulnerable packages: {len(vulnerable_packages)}")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        print(f"Unmaintained packages: {len(unmaintained)}")
        
        if len(self.ignored_advisories) > 0:
            print(f"Ignored advisories: {len(self.ignored_advisories)}")
        
        # Show vulnerabilities
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
                print(f"   Ecosystem: {pkg_vulns[0]['affected_package']['ecosystem']}")
                print(f"   Vulnerabilities: {len(pkg_vulns)}")
                print("-" * 60)
                
                for vuln in pkg_vulns:
                    print(f"   🆔 ID: {vuln.get('id', 'N/A')}")
                    
                    # Extract severity
                    severity = "Unknown"
                    if vuln.get('database_specific', {}).get('severity'):
                        severity = vuln['database_specific']['severity']
                    elif vuln.get('severity'):
                        severity = vuln['severity']
                    
                    print(f"   📊 Severity: {severity}")
                    print(f"   📝 Summary: {vuln.get('summary', 'No summary available')}")
                    
                    # Show references
                    if vuln.get('references'):
                        print("   🔗 References:")
                        for ref in vuln['references'][:2]:
                            print(f"      - {ref.get('url', 'N/A')}")
                    
                    print()
        
        # Show unmaintained packages
        if unmaintained:
            print("\n" + "=" * 80)
            print("UNMAINTAINED PACKAGES")
            print("=" * 80)
            
            for pkg in unmaintained:
                print(f"📦 {pkg['package']} ({pkg['ecosystem']})")
                print(f"   Last release: {pkg['last_release']} ({pkg['days_ago']} days ago)")
                print()
        
        if not vulnerabilities and not unmaintained:
            print("\n✅ No vulnerabilities or maintenance issues found!")
    
    def generate_json_report(self, vulnerabilities: List[Dict[str, Any]], 
                           dependencies: List[Dict[str, Any]], 
                           unmaintained: List[Dict[str, Any]]) -> None:
        """Generate structured JSON report"""
        vulnerable_packages = list(set(v['affected_package']['name'] for v in vulnerabilities))
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "file_scanned": self.file_path,
                "ecosystem": self.detect_ecosystem(),
                "total_dependencies": len(dependencies),
                "vulnerable_packages": len(vulnerable_packages),
                "total_vulnerabilities": len(vulnerabilities),
                "unmaintained_packages": len(unmaintained),
                "ignored_advisories": len(self.ignored_advisories),
                "maintenance_check_months": self.maintenance_months
            },
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities,
            "unmaintained_packages": unmaintained,
            "ignored_advisories": list(self.ignored_advisories),
            "summary": {
                "vulnerable_packages": vulnerable_packages,
                "severity_breakdown": self._get_severity_breakdown(vulnerabilities)
            }
        }
        
        output_file = "multi_vulnerability_report.json"
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
    
    parser = argparse.ArgumentParser(description='Multi-Ecosystem Dependency Risk Scanner')
    parser.add_argument('file', help='Path to dependency file (requirements.txt, package.json, etc.)')
    parser.add_argument('--ignore-file', default='.vulnignore', help='Path to ignore file (default: .vulnignore)')
    parser.add_argument('--maintenance-months', type=int, default=12, help='Months for maintenance check (default: 12)')
    parser.add_argument('--json-only', action='store_true', help='Output only JSON report')
    parser.add_argument('--skip-maintenance', action='store_true', help='Skip maintenance status check')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found")
        sys.exit(1)

    scanner = MultiEcosystemScanner(args.file, args.ignore_file, args.maintenance_months)
    
    # Detect ecosystem and parse dependencies
    ecosystem = scanner.detect_ecosystem()
    print(f"🔍 Detected ecosystem: {ecosystem}")
    
    if ecosystem == 'python':
        dependencies = scanner.parse_python_dependencies()
    elif ecosystem == 'javascript':
        dependencies = scanner.parse_javascript_dependencies()
    else:
        print(f"❌ Unsupported ecosystem or unable to detect from file: {args.file}")
        sys.exit(1)
    
    # Check vulnerabilities
    vulnerabilities = scanner.check_vulnerabilities(dependencies)
    
    # Check maintenance status
    unmaintained = []
    if not args.skip_maintenance:
        unmaintained = scanner.check_maintenance_status(dependencies)
    
    # Generate reports
    if not args.json_only:
        scanner.generate_human_readable_report(vulnerabilities, dependencies, unmaintained)
    
    scanner.generate_json_report(vulnerabilities, dependencies, unmaintained)

if __name__ == "__main__":
    main()
