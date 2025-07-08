#!/usr/bin/env python3
"""
Flask Web UI for Multi-Ecosystem Dependency Scanner
"""
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
import os
import json
import tempfile
from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanners'))
from multi_scanner import MultiEcosystemScanner
import threading
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Store scan results in memory (in production, use a database)
scan_results = {}
active_scans = {}

ALLOWED_EXTENSIONS = {'txt', 'json', 'lock'}
UPLOAD_FOLDER = 'uploads'

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def run_scan(scan_id, file_path, ignore_file, maintenance_months, skip_maintenance):
    """Run the scanner in a background thread"""
    try:
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 'Initializing scanner...',
            'start_time': datetime.now()
        }
        
        scanner = MultiEcosystemScanner(file_path, ignore_file, maintenance_months)
        
        # Detect ecosystem
        ecosystem = scanner.detect_ecosystem()
        active_scans[scan_id]['progress'] = f'Detected ecosystem: {ecosystem}'
        
        if ecosystem == 'python':
            dependencies = scanner.parse_python_dependencies()
        elif ecosystem == 'javascript':
            dependencies = scanner.parse_javascript_dependencies()
        else:
            raise Exception(f"Unsupported ecosystem: {ecosystem}")
        
        active_scans[scan_id]['progress'] = f'Checking {len(dependencies)} dependencies...'
        
        # Check vulnerabilities
        vulnerabilities = scanner.check_vulnerabilities(dependencies)
        
        # Check maintenance status
        unmaintained = []
        if not skip_maintenance:
            active_scans[scan_id]['progress'] = 'Checking maintenance status...'
            unmaintained = scanner.check_maintenance_status(dependencies)
        
        # Generate report
        active_scans[scan_id]['progress'] = 'Generating report...'
        vulnerable_packages = list(set(v['affected_package']['name'] for v in vulnerabilities))
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "file_scanned": os.path.basename(file_path),
                "ecosystem": ecosystem,
                "total_dependencies": len(dependencies),
                "vulnerable_packages": len(vulnerable_packages),
                "total_vulnerabilities": len(vulnerabilities),
                "unmaintained_packages": len(unmaintained),
                "ignored_advisories": len(scanner.ignored_advisories),
                "maintenance_check_months": maintenance_months
            },
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities,
            "unmaintained_packages": unmaintained,
            "ignored_advisories": list(scanner.ignored_advisories),
            "summary": {
                "vulnerable_packages": vulnerable_packages,
                "severity_breakdown": scanner._get_severity_breakdown(vulnerabilities)
            }
        }
        
        # Store results
        scan_results[scan_id] = {
            'status': 'completed',
            'report': report,
            'end_time': datetime.now()
        }
        
        # Clean up active scan
        if scan_id in active_scans:
            del active_scans[scan_id]
            
    except Exception as e:
        scan_results[scan_id] = {
            'status': 'error',
            'error': str(e),
            'end_time': datetime.now()
        }
        if scan_id in active_scans:
            del active_scans[scan_id]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        scan_id = str(uuid.uuid4())
        file_path = os.path.join(UPLOAD_FOLDER, f"{scan_id}_{filename}")
        file.save(file_path)
        
        # Get form parameters
        ignore_file = request.form.get('ignore_file', '.vulnignore')
        maintenance_months = int(request.form.get('maintenance_months', 12))
        skip_maintenance = 'skip_maintenance' in request.form
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan,
            args=(scan_id, file_path, ignore_file, maintenance_months, skip_maintenance)
        )
        thread.daemon = True
        thread.start()
        
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    flash('Invalid file type. Please upload .txt, .json, or .lock files.')
    return redirect(request.url)

@app.route('/scan/<scan_id>')
def scan_status(scan_id):
    return render_template('scan_status.html', scan_id=scan_id)

@app.route('/api/scan/<scan_id>')
def api_scan_status(scan_id):
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    elif scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'status': 'not_found'}), 404

@app.route('/results/<scan_id>')
def scan_results_view(scan_id):
    if scan_id not in scan_results:
        return "Scan not found", 404
    
    result = scan_results[scan_id]
    if result['status'] != 'completed':
        return f"Scan {result['status']}: {result.get('error', 'Unknown error')}", 400
    
    return render_template('results.html', scan_id=scan_id, report=result['report'])

@app.route('/api/results/<scan_id>')
def api_scan_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/download/<scan_id>')
def download_results(scan_id):
    if scan_id not in scan_results or scan_results[scan_id]['status'] != 'completed':
        return "Results not available", 404
    
    # Create temporary file with results
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(scan_results[scan_id]['report'], f, indent=2)
        temp_path = f.name
    
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=f'vulnerability_report_{scan_id}.json',
        mimetype='application/json'
    )

@app.route('/history')
def scan_history():
    history = []
    for scan_id, result in scan_results.items():
        history.append({
            'scan_id': scan_id,
            'status': result['status'],
            'timestamp': result.get('end_time', datetime.now()).isoformat(),
            'file_name': result.get('report', {}).get('scan_info', {}).get('file_scanned', 'Unknown'),
            'ecosystem': result.get('report', {}).get('scan_info', {}).get('ecosystem', 'Unknown'),
            'vulnerabilities': result.get('report', {}).get('scan_info', {}).get('total_vulnerabilities', 0),
            'dependencies': result.get('report', {}).get('scan_info', {}).get('total_dependencies', 0)
        })
    
    # Sort by timestamp, newest first
    history.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('history.html', history=history)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
