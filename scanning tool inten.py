import nmap
import requests
from packaging import version
nm = nmap.PortScanner()
target_ip = '192.168.1.1'
target_url = 'http://example.com'
known_vulnerabilities = {
    'nginx': '1.19.0',  
    'apache': '2.4.0',
}
def scan_ports(ip):
    print(f"Scanning ports on {ip}...")
    nm.scan(ip, '1-1024')  
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                if 'product' in nm[host][proto][port]:
                    service = nm[host][proto][port]['product']
                    version = nm[host][proto][port].get('version', 'unknown')
                    check_vulnerability(service, version)
def check_vulnerability(service, version_detected):
    if service.lower() in known_vulnerabilities:
        if version.parse(version_detected) <= version.parse(known_vulnerabilities[service.lower()]):
            print(f"Vulnerability Detected: {service} {version_detected} is outdated!")
def check_http_headers(url):
    print(f"Checking HTTP headers for {url}...")
    try:
        response = requests.get(url)
        headers = response.headers
        if 'Server' in headers:
            print(f"Server Header: {headers['Server']}")
        if 'X-Powered-By' in headers:
            print(f"X-Powered-By Header: {headers['X-Powered-By']}")
        if 'Strict-Transport-Security' not in headers:
            print("Warning: Strict-Transport-Security header is missing!")
    except requests.RequestException as e:
        print(f"Failed to connect to {url}: {e}")
def main():
    scan_ports(target_ip)
    check_http_headers(target_url)
if __name__ == "__main__":
    main()
