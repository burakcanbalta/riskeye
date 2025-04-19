# riskeye.py
# Flask + Nmap tabanlı port tarayıcı

import nmap
import ipaddress
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = ''
    if request.method == 'POST':
        ip = request.form.get('ip')
        scanner = nmap.PortScanner()
        try:
            network = ipaddress.ip_network(ip, strict=False)
            scanner.scan(hosts=str(network), arguments='-T4 -F')
            for host in scanner.all_hosts():
                results += f'<b>{host}</b><br>'
                for port in scanner[host].get('tcp', {}):
                    state = scanner[host]['tcp'][port]['state']
                    name = scanner[host]['tcp'][port]['name']
                    results += f'Port {port} ({name}): {state}<br>'
        except Exception as e:
            results = f'Error: {e}'
    return render_template_string('''
        <form method="post">
            IP / Subnet: <input name="ip" required>
            <button type="submit">Scan</button>
        </form>
        <div>{{ results|safe }}</div>
    ''', results=results)

if __name__ == '__main__':
    app.run(debug=True)
