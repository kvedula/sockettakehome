import json
import requests
import subprocess
import argparse
import sys
import os
from datetime import datetime
from typing import List, Dict, Any

class DependencyScanner:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.osv_url = "https://api.osv.dev/v1/query"
        self.headers = {"Content-Type": "application/json"}
        
    def resolve_dependencies(self) -> List[Dict[str, Any]]:
        """Resolve all dependencies using pipdeptree"""
        try:
            result = subprocess.run(
                ['pipdeptree', '-f', '-w', 'silence', '-j'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error running pipdeptree: {e}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error parsing pipdeptree output: {e}")
            sys.exit(1)
        except FileNotFoundError:
            print("pipdeptree not found. Please install it with: pip install pipdeptree")
            sys.exit(1)

    def check_vulnerabilities(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check each dependency for vulnerabilities using OSV.dev API"""
        vulnerabilities = []
        vulnerable_packages = []
        
        print(f"Checking {len(dependencies)} dependencies for vulnerabilities...")
        
        for i, dep in enumerate(dependencies):
            package_name = dep['package']['package_name']
            version = dep['package']['installed_version']
            
            print(f"[{i+1}/{len(dependencies)}] Checking {package_name} {version}")
            
            payload = {
                "package": {
                    "name": package_name,
                    "version": version
                }
            }
            
            try:
                response = requests.post(self.osv_url, headers=self.headers, json=payload, timeout=10)
                
                if response.ok:
                    data = response.json()
                    if data.get('vulnerabilities'):
                        for vuln in data['vulnerabilities']:
                            vuln['affected_package'] = {
                                'name': package_name,
                                'version': version
                            }
                            vulnerabilities.append(vuln)
                        vulnerable_packages.append(package_name)
                        print(f"  ⚠️  Found {len(data['vulnerabilities'])} vulnerabilities")
                    else:
                        print(f"  ✅ No vulnerabilities found")
                else:
                    print(f"  ❌ Error checking {package_name}: {response.status_code}")
            except requests.RequestException as e:
                print(f"  ❌ Network error checking {package_name}: {e}")
        
        return vulnerabilities

    def generate_human_readable_report(self, vulnerabilities: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]) -> None:
        """Generate human-readable console output"""
        print("\n" + "="*80)
        print("DEPENDENCY VULNERABILITY REPORT")
        print("="*80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total dependencies scanned: {len(dependencies)}")
        print(f"Vulnerable packages found: {len(set(v['affected_package']['name'] for v in vulnerabilities))}")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        
        if vulnerabilities:
            print("\n" + "="*80)
            print("VULNERABILITIES FOUND")
            print("="*80)
            
            for vuln in vulnerabilities:
                print(f"\n📦 Package: {vuln['affected_package']['name']} {vuln['affected_package']['version']}")
                print(f"🆔 ID: {vuln.get('id', 'N/A')}")
                print(f"📊 Severity: {vuln.get('database_specific', {}).get('severity', 'Unknown')}")
                print(f"📝 Summary: {vuln.get('summary', 'No summary available')}")
                
                if vuln.get('references'):
                    print("🔗 References:")
                    for ref in vuln['references'][:3]:  # Show first 3 references
                        print(f"   - {ref.get('url', 'N/A')}")
                
                print("-" * 40)
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
            "vulnerabilities": vulnerabilities,
            "summary": {
                "vulnerable_packages": vulnerable_packages,
                "severity_breakdown": self._get_severity_breakdown(vulnerabilities)
            }
        }
        
        with open("vulnerability_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 JSON report saved to: vulnerability_report.json")
    
    def _get_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity"""
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('database_specific', {}).get('severity', 'UNKNOWN').upper()
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count['UNKNOWN'] += 1
        
        return severity_count


def main():
    parser = argparse.ArgumentParser(description='Open Source Dependency Risk Scanner')
    parser.add_argument('requirements', help='Path to requirements.txt')
    args = parser.parse_args()

    # Check if requirements file exists
    if not os.path.exists(args.requirements):
        print(f"Error: File '{args.requirements}' not found")
        sys.exit(1)

    scanner = DependencyScanner(args.requirements)
    dependencies = scanner.resolve_dependencies()
    vulnerabilities = scanner.check_vulnerabilities(dependencies)
    
    # Generate both human-readable and JSON reports
    scanner.generate_human_readable_report(vulnerabilities, dependencies)
    scanner.generate_json_report(vulnerabilities, dependencies)

if __name__ == "__main__":
    main()

