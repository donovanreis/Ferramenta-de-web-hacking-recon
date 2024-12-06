import requests
from bs4 import BeautifulSoup
import socket
import pyfiglet
from datetime import datetime
import re
from colorama import Fore, Style, init

# Inicializa o colorama
init()

def find_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = list(set([entry['name_value'].lower() for entry in data]))
    except Exception as e:
        print(f"Erro ao buscar subdomínios: {e}")
    return subdomains

def check_open_ports(subdomain):
    open_ports = []
    common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 143, 3389]
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((subdomain, port))
        except:
            continue
        else:
            open_ports.append(port)
        s.close()
    return open_ports

def get_status_code(subdomain, port):
    try:
        url = f"http://{subdomain}:{port}"
        response = requests.get(url)
        return response.status_code
    except requests.ConnectionError:
        return None
    except requests.exceptions.InvalidURL:
        print(f"URL inválida: {url}")
        return None

def crawl_js(subdomain):
    js_files = []
    try:
        response = requests.get(f"http://{subdomain}")
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_files.append(src)
    except requests.ConnectionError:
        pass
    return js_files

def create_report(domain, results):
    banner = pyfiglet.figlet_format("MALVADEZA")
    report = banner + f"\nRelatório de Recon para: {domain}\n\n"
    for result in results:
        report += f"Subdomínio: {result['subdomain']}\n"
        report += f"Status Code: {result['status_code']}\n"
        report += f"Portas Abertas: {', '.join(map(str, result['open_ports']))}\n"
        report += f"Arquivos JS: {', '.join(result['js_files'])}\n\n"
    
    with open(f"{domain}_recon_report.txt", "w") as f:
        f.write(report)
    print(f"Relatório salvo como {domain}_recon_report.txt")

def is_valid_subdomain(subdomain, domain):
    # Use regex to validate the subdomain format
    regex = re.compile(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]+$")
    return subdomain.endswith(domain) and regex.match(subdomain)

def run_recon(domain):
    banner = pyfiglet.figlet_format("MALVADEZA")
    print(banner)
    
    subdomains = find_subdomains(domain)
    if not subdomains:
        print("Nenhum subdomínio encontrado.")
        return
    
    results = []
    for subdomain in subdomains:
        if not is_valid_subdomain(subdomain, domain):
            print(f"Subdomínio inválido ignorado: {subdomain}")
            continue  # Ignora entradas inválidas
        open_ports = check_open_ports(subdomain)
        status_code = get_status_code(subdomain, 80)  # Verifica status code da porta 80 como exemplo
        js_files = crawl_js(subdomain)
        
        # Exibir subdomínio e status code de forma colorida
        status_color = Fore.GREEN if status_code == 200 else Fore.RED
        print(f"{Fore.CYAN}{subdomain}{Style.RESET_ALL} - Status Code: {status_color}{status_code}{Style.RESET_ALL}")
        
        results.append({
            'subdomain': subdomain,
            'status_code': status_code,
            'open_ports': open_ports,
            'js_files': js_files
        })
    
    create_report(domain, results)

if __name__ == "__main__":
    target_domain = input("Digite o domínio alvo: ")
    run_recon(target_domain)
