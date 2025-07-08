# 🛡️ Multi-Ecosystem Dependency Scanner

A comprehensive CLI tool and web application that scans project dependencies for security vulnerabilities and maintenance issues across multiple ecosystems.

## ✨ Features

### Core Features
- 🔍 **Dependency Resolution**: Resolves all direct and transitive dependencies
- 🛡️ **Vulnerability Detection**: Queries OSV.dev database for known security vulnerabilities
- 📊 **Structured Reporting**: Human-readable console output and JSON reports
- ⚡ **Fast Scanning**: Efficient vulnerability checking with progress tracking
- 🧪 **Comprehensive Testing**: Full test coverage with unit and integration tests

### 🎯 Bonus Features
- 🌍 **Multi-Ecosystem Support**: Python (requirements.txt) and JavaScript (package.json)
- 🚫 **Advisory Filtering**: Suppress specific advisories using ignore files
- 🔧 **Maintenance Checks**: Flag unmaintained packages with configurable thresholds
- 🌐 **Web Interface**: Flask-based UI with real-time progress and scan history

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dependency-scanner.git
cd dependency-scanner

# Install dependencies
pip install -r requirements.txt
# or use the setup script
python setup.py
```

### Basic Usage

```bash
# Scan Python dependencies
python multi_scanner.py requirements.txt

# Scan JavaScript dependencies
python multi_scanner.py package.json

# Launch web interface
python web_ui.py
# Open http://localhost:8000
```

## 📋 Usage Examples

### Command Line Interface

```bash
# Basic scan
python multi_scanner.py requirements.txt

# With custom settings
python multi_scanner.py requirements.txt \
  --ignore-file .vulnignore \
  --maintenance-months 6

# JSON-only output
python multi_scanner.py package.json --json-only

# Skip maintenance check for faster scanning
python multi_scanner.py requirements.txt --skip-maintenance
```

### Web Interface

1. Start the web server:
   ```bash
   python web_ui.py
   ```

2. Open your browser to [http://localhost:8000](http://localhost:8000)

3. Upload your dependency file (requirements.txt or package.json)

4. Configure scan options and start scanning

5. View results, download reports, and browse scan history

## 🔧 Configuration

### Advisory Filtering

Create a `.vulnignore` file to suppress specific vulnerabilities:

```
# Vulnerability ignore file
CVE-2021-23337
GHSA-35jh-r3h4-6jhm

# Comments are supported
# Add one vulnerability ID per line
```

### Supported File Types

- **Python**: `requirements.txt`, `requirements-dev.txt`
- **JavaScript**: `package.json`, `package-lock.json`, `yarn.lock`

## 📊 Output Examples

### Console Output
```
================================================================================
MULTI-ECOSYSTEM DEPENDENCY VULNERABILITY REPORT
================================================================================
Generated: 2025-07-08 20:30:15
File scanned: requirements.txt
Ecosystem: python
Total dependencies: 25
Vulnerable packages: 3
Total vulnerabilities: 5
Unmaintained packages: 1

📦 REQUESTS
   Version: 2.25.1
   Ecosystem: PyPI
   Vulnerabilities: 2
------------------------------------------------------------
   🆔 ID: CVE-2023-32681
   📊 Severity: MEDIUM
   📝 Summary: Requests library vulnerable to unintended proxy usage
```

### JSON Report Structure
```json
{
  "scan_info": {
    "timestamp": "2025-07-08T20:30:15.123456",
    "file_scanned": "requirements.txt",
    "ecosystem": "python",
    "total_dependencies": 25,
    "vulnerable_packages": 3,
    "total_vulnerabilities": 5,
    "unmaintained_packages": 1
  },
  "vulnerabilities": [...],
  "unmaintained_packages": [...],
  "summary": {
    "severity_breakdown": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 1,
      "LOW": 1
    }
  }
}
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python test_complete.py

# Run specific test modules
python test_scanner.py
python test_all.py

# Test individual scanners
python enhanced_scanner.py test_requirements.txt
python multi_scanner.py package.json --skip-maintenance
```

## 📁 Project Structure

```
dependency-scanner/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── setup.py                      # Dependency installer
├── .vulnignore                   # Example ignore file
├── .gitignore                    # Git ignore rules
├── LICENSE                       # MIT License
│
├── scanners/
│   ├── scanner.py                # Original scanner (pipdeptree-based)
│   ├── enhanced_scanner.py       # Enhanced requirements parser
│   └── multi_scanner.py          # Multi-ecosystem scanner
│
├── web/
│   ├── web_ui.py                 # Flask web application
│   └── templates/                # HTML templates
│       ├── base.html
│       ├── index.html
│       ├── scan_status.html
│       ├── results.html
│       └── history.html
│
├── tests/
│   ├── test_scanner.py           # Unit tests for original scanner
│   ├── test_all.py               # Comprehensive test suite
│   └── test_complete.py          # Integration tests
│
└── examples/
    ├── requirements.txt           # Python example
    ├── test_requirements.txt      # Test file with older versions
    └── package.json               # JavaScript example
```

## 🔒 Security Considerations

- All vulnerability data is sourced from the [OSV.dev](https://osv.dev) database
- No sensitive data is stored or transmitted
- Web interface includes file upload validation
- Rate limiting is implemented for API calls

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 Requirements

- Python 3.6+
- Internet connection for vulnerability database queries
- Dependencies listed in `requirements.txt`

## 🐛 Known Limitations

- Requires internet access for vulnerability and maintenance checks
- Rate limiting may affect large dependency trees
- Some package registries may have API limitations
- Web interface stores scan results in memory (not persistent)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OSV.dev](https://osv.dev) for vulnerability data
- [PyPI](https://pypi.org) and [npm](https://npmjs.com) for package information
- Flask and Bootstrap for the web interface
- All contributors and maintainers

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/yourusername/dependency-scanner/issues) page
2. Review the test examples in the `examples/` directory
3. Run the test suite to verify your setup
4. Create a new issue with detailed information

---

**⭐ Star this repository if you find it useful!**
