import nmap
import ipaddress
import threading
import time
import json
import csv
import os
from datetime import datetime
from flask import Flask, request, render_template, jsonify, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
limiter = Limiter(app=app, key_func=get_remote_address)

SCAN_RESULTS_DIR = "scan_results"
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)

class RiskEyeScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_cache = {}
        self.cache_timeout = 300

    def validate_target(self, target):
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 256:
                return False, "Maximum /24 subnet allowed for security reasons"
            return True, network
        except Exception:
            try:
                ipaddress.ip_address(target)
                return True, target
            except Exception:
                return False, "Invalid IP address or subnet"

    def get_scan_arguments(self, scan_type):
        scan_profiles = {
            'quick': '-T4 -F --host-timeout 2m',
            'standard': '-T4 -sS -sV -O --version-intensity 5',
            'aggressive': '-T4 -A -v -sS -sV -sC -O',
            'udp': '-T4 -sU --top-ports 100',
            'full': '-T4 -p- -A -v -sS -sV -sC -O'
        }
        return scan_profiles.get(scan_type, scan_profiles['quick'])

    def parse_scan_results(self, scan_data):
        results = []
        for host in scan_data.all_hosts():
            host_info = {
                'host': host,
                'hostname': scan_data[host].hostname(),
                'state': scan_data[host].state(),
                'ports': []
            }

            for proto in scan_data[host].all_protocols():
                ports = scan_data[host][proto].keys()
                for port in ports:
                    port_info = scan_data[host][proto][port]
                    host_info['ports'].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extra': port_info.get('extrainfo', '')
                    })
            
            if 'osmatch' in scan_data[host]:
                host_info['os'] = scan_data[host]['osmatch'][0]['name'] if scan_data[host]['osmatch'] else 'Unknown'
            
            results.append(host_info)
        return results

    def calculate_risk_score(self, host_info):
        risk_score = 0
        open_ports = [p for p in host_info['ports'] if p['state'] == 'open']
        
        high_risk_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080}
        
        for port in open_ports:
            if port['port'] in high_risk_ports:
                risk_score += 10
            elif port['port'] < 1024:
                risk_score += 5
            else:
                risk_score += 2
            
            if 'ftp' in port['service'].lower() and 'anonymous' in port.get('extra', '').lower():
                risk_score += 20
            
            if 'ssh' in port['service'].lower() and port.get('version'):
                risk_score += 15
        
        return min(risk_score, 100)

    def scan_network(self, target, scan_type='quick'):
        cache_key = f"{target}_{scan_type}"
        current_time = time.time()
        
        if cache_key in self.scan_cache:
            if current_time - self.scan_cache[cache_key]['timestamp'] < self.cache_timeout:
                return self.scan_cache[cache_key]['results']
        
        is_valid, valid_target = self.validate_target(target)
        if not is_valid:
            return {'error': valid_target}
        
        scan_args = self.get_scan_arguments(scan_type)
        
        try:
            print(f"Scanning {target} with arguments: {scan_args}")
            scan_result = self.nm.scan(hosts=str(valid_target), arguments=scan_args)
            
            if scan_result['nmap']['scanstats']['uphosts'] == '0':
                return {'error': 'No hosts found online'}
            
            parsed_results = self.parse_scan_results(self.nm)
            
            for host in parsed_results:
                host['risk_score'] = self.calculate_risk_score(host)
            
            result_data = {
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'results': parsed_results
            }
            
            self.scan_cache[cache_key] = {
                'timestamp': current_time,
                'results': result_data
            }
            
            self.save_scan_report(result_data)
            return result_data
            
        except nmap.PortScannerError as e:
            return {'error': f'Nmap error: {str(e)}'}
        except Exception as e:
            return {'error': f'Scan failed: {str(e)}'}

    def save_scan_report(self, scan_data):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_{timestamp}.json"
        filepath = os.path.join(SCAN_RESULTS_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        csv_filename = f"scan_{timestamp}.csv"
        csv_filepath = os.path.join(SCAN_RESULTS_DIR, csv_filename)
        
        with open(csv_filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Host', 'Port', 'State', 'Service', 'Version', 'Risk Score'])
            
            for host in scan_data['results']:
                for port in host['ports']:
                    writer.writerow([
                        host['host'],
                        port['port'],
                        port['state'],
                        port['service'],
                        port.get('version', ''),
                        host.get('risk_score', 0)
                    ])
        
        return filename

scanner = RiskEyeScanner()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>RiskEye - Advanced Port Scanner</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .risk-high { background-color: #ffebee; border-left: 4px solid #f44336; }
        .risk-medium { background-color: #fff3e0; border-left: 4px solid #ff9800; }
        .risk-low { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
        .host-card { margin-bottom: 20px; border-radius: 8px; }
        .port-badge { font-size: 0.8em; margin: 2px; }
        .scanning { opacity: 0.6; pointer-events: none; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h1 class="h3 mb-0"><i class="fas fa-eye me-2"></i>RiskEye Port Scanner</h1>
                    </div>
                    <div class="card-body">
                        <form id="scanForm" method="post">
                            <div class="row g-3">
                                <div class="col-md-6">
                                    <label for="target" class="form-label">Target IP/Subnet:</label>
                                    <input type="text" class="form-control" id="target" name="target" 
                                           placeholder="192.168.1.0/24 or 192.168.1.1" required>
                                    <div class="form-text">Maximum /24 subnet allowed</div>
                                </div>
                                <div class="col-md-4">
                                    <label for="scan_type" class="form-label">Scan Type:</label>
                                    <select class="form-select" id="scan_type" name="scan_type">
                                        <option value="quick">Quick Scan</option>
                                        <option value="standard">Standard Scan</option>
                                        <option value="aggressive">Aggressive Scan</option>
                                        <option value="udp">UDP Scan</option>
                                        <option value="full">Full Port Scan</option>
                                    </select>
                                </div>
                                <div class="col-md-2 d-flex align-items-end">
                                    <button type="submit" class="btn btn-danger w-100" id="scanBtn">
                                        <i class="fas fa-search me-1"></i> Scan
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                <div id="loading" class="text-center mt-4" style="display: none;">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Scanning...</span>
                    </div>
                    <p class="mt-2">Scanning network, please wait...</p>
                </div>

                <div id="results" class="mt-4"></div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const scanBtn = document.getElementById('scanBtn');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            
            scanBtn.disabled = true;
            loading.style.display = 'block';
            results.innerHTML = '';
            
            const formData = new FormData(this);
            
            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                loading.style.display = 'none';
                scanBtn.disabled = false;
                
                if (data.error) {
                    results.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                } else {
                    displayResults(data);
                }
            })
            .catch(error => {
                loading.style.display = 'none';
                scanBtn.disabled = false;
                results.innerHTML = `<div class="alert alert-danger">Scan failed: ${error}</div>`;
            });
        });

        function displayResults(data) {
            let html = `
                <div class="card shadow">
                    <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="fas fa-list-alt me-2"></i>Scan Results</h5>
                        <small>Scan Type: ${data.scan_type} | ${new Date(data.timestamp).toLocaleString()}</small>
                    </div>
                    <div class="card-body">
            `;

            data.results.forEach(host => {
                const riskClass = host.risk_score >= 70 ? 'risk-high' : 
                                host.risk_score >= 30 ? 'risk-medium' : 'risk-low';
                
                html += `
                    <div class="card host-card ${riskClass}">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h6 class="mb-0">
                                <i class="fas fa-desktop me-2"></i>${host.host}
                                ${host.hostname ? `<small class="text-muted">(${host.hostname})</small>` : ''}
                            </h6>
                            <div>
                                <span class="badge bg-${host.state === 'up' ? 'success' : 'secondary'} me-2">
                                    ${host.state}
                                </span>
                                <span class="badge bg-danger">
                                    Risk: ${host.risk_score}%
                                </span>
                            </div>
                        </div>
                        <div class="card-body">
                            ${host.os ? `<p><strong>OS:</strong> ${host.os}</p>` : ''}
                            <h6>Open Ports:</h6>
                            <div class="row">
                `;

                host.ports.forEach(port => {
                    if (port.state === 'open') {
                        html += `
                            <div class="col-md-3 mb-2">
                                <div class="card">
                                    <div class="card-body py-2">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <span class="badge bg-primary port-badge">${port.port}</span>
                                            <small>${port.service}</small>
                                        </div>
                                        ${port.version ? `<small class="text-muted">${port.version}</small>` : ''}
                                    </div>
                                </div>
                            </div>
                        `;
                    }
                });

                html += `
                            </div>
                        </div>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
                
                <div class="text-center mt-3">
                    <a href="/download/csv" class="btn btn-outline-primary me-2">
                        <i class="fas fa-download me-1"></i> Download CSV
                    </a>
                    <a href="/download/json" class="btn btn-outline-secondary">
                        <i class="fas fa-download me-1"></i> Download JSON
                    </a>
                </div>
            `;

            document.getElementById('results').innerHTML = html;
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template('string:' + HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    target = request.form.get('target', '').strip()
    scan_type = request.form.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target is required'})
    
    result = scanner.scan_network(target, scan_type)
    return jsonify(result)

@app.route('/download/<file_type>')
def download_file(file_type):
    scan_files = os.listdir(SCAN_RESULTS_DIR)
    scan_files.sort(reverse=True)
    
    if not scan_files:
        return jsonify({'error': 'No scan results available'})
    
    latest_scan = None
    for file in scan_files:
        if file_type == 'csv' and file.endswith('.csv'):
            latest_scan = file
            break
        elif file_type == 'json' and file.endswith('.json'):
            latest_scan = file
            break
    
    if not latest_scan:
        return jsonify({'error': 'File not found'})
    
    filepath = os.path.join(SCAN_RESULTS_DIR, latest_scan)
    return send_file(filepath, as_attachment=True)

@app.route('/api/scan', methods=['POST'])
@limiter.limit("30 per minute")
def api_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target is required'})
    
    result = scanner.scan_network(target, scan_type)
    return jsonify(result)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
