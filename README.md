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
git clone https://github.com/kvedula/sockettakehome.git
cd sockettakehome

# Install dependencies
pip install -r requirements.txt
# or use the setup script
python setup.py
```

### Basic Usage

```bash
# Scan Python dependencies
python scan.py examples/demo_requirements.txt

# Scan JavaScript dependencies
python scan.py examples/package.json

# Launch web interface
python web.py
# Open http://localhost:8000
```

## 📋 Usage Examples

### Command Line Interface

```bash
# Basic scan
python scan.py examples/demo_requirements.txt

# With custom settings
python scan.py examples/demo_requirements.txt \
  --ignore-file .vulnignore \
  --maintenance-months 6

# JSON-only output
python scan.py examples/package.json --json-only

# Skip maintenance check for faster scanning
python scan.py examples/demo_requirements.txt --skip-maintenance
```

### Web Interface

1. Start the web server:
   ```bash
   python web.py
   ```

2. Open your browser to [http://localhost:8000](http://localhost:8000)

3. Upload your dependency file (requirements.txt or package.json)

4. Configure scan options and start scanning

5. View results, download reports, and browse scan history

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python tests/test_complete.py

# Run specific test modules
python tests/test_scanner.py
python tests/test_all.py
```

## 📁 Project Structure

```
sockettakehome/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── setup.py                       # Dependency installer
├── .vulnignore                    # Example ignore file
├── .gitignore                     # Git ignore rules
├── LICENSE                        # MIT License
│
├── scanners/
│   ├── scanner.py                 # Original scanner (pipdeptree-based)
│   ├── enhanced_scanner.py        # Enhanced requirements parser
│   └── multi_scanner.py           # Multi-ecosystem scanner
│
├── web/
│   ├── web_ui.py                  # Flask web application
│   └── templates/                 # HTML templates
│       ├── base.html
│       ├── index.html
│       ├── scan_status.html
│       ├── results.html
│       └── history.html
│
├── tests/
│   ├── test_scanner.py            # Unit tests for original scanner
│   ├── test_all.py                # Comprehensive test suite
│   └── test_complete.py           # Integration tests
│
└── examples/
    ├── demo_requirements.txt      # Python example
    ├── test_requirements.txt      # Test file with older versions
    └── package.json               # JavaScript example
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/kvedula/sockettakehome/issues) page
2. Review the test examples in the `examples/` directory
3. Run the test suite to verify your setup
4. Create a new issue with detailed information

---

**⭐ Star this repository if you find it useful!**
