
import os
import subprocess
import json
import time
import datetime
import base64
import shutil
import threading
import hashlib
import random
import re
from getpass import getpass
from urllib.parse import quote

# --- Tratamento de Erros de Importação ---
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import psutil
    import pygetwindow
    from pynput import mouse, keyboard
    import qrcode
    from colorama import init, Fore, Style
    import requests
    from bs4 import BeautifulSoup
    import speedtest
    import pyperclip
except ImportError as e:
    print(f"Erro: Biblioteca '{e.name}' não está instalada.")
    print("Por favor, instale todas as dependências com o comando:")
    print("pip install cryptography psutil pygetwindow pynput qrcode colorama requests Pillow beautifulsoup4 speedtest-cli pyperclip")
    input("Pressione Enter para sair...")
    exit()

# --- INICIALIZAÇÃO DE BIBLIOTECAS ---
init(autoreset=True)

# --- CONSTANTES E ARQUIVOS ---
SALT_FILE = "salt.bin"
PASSWORDS_FILE = "data_passwords.enc"
APPS_FILE = "data_apps.enc"
WINDOW_TRACK_FILE = "data_window_times.json"
ECONOMY_FILE = "data_economy.json"
STUDIES_FILE = "data_studies.json"
# NOVOS ARQUIVOS
JOURNAL_FILE = "data_journal.enc"
HABITS_FILE = "data_habits.json"
CLIPBOARD_FILE = "data_clipboard.json"
FILE_ORGANIZER_RULES = "data_organizer_rules.json"


# --- VARIÁVEIS GLOBAIS DE CONTROLE ---
MASTER_PASSWORD = None
stop_event = threading.Event()
window_tracker_thread = None
autoclicker_thread = None
autoclicker_running = threading.Event()
hotkey_listener = None
# NOVAS VARIÁVEIS
clipboard_listener_thread = None
stop_clipboard_event = threading.Event()


# --- FUNÇÕES UTILITÁRIAS ---
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title, color=Fore.CYAN):
    clear_screen()
    print(color + "+" + "=" * 80 + "+")
    print(color + f"| {title.upper():^78} |")
    print(color + "+" + "=" * 80 + "+")
    print(Style.RESET_ALL)

def format_seconds(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}h {m:02d}m {s:02d}s"

# --- FUNÇÕES DE CRIPTOGRAFIA ---
def get_key_from_password(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key):
    return Fernet(key).encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data, key):
    try:
        return Fernet(key).decrypt(encrypted_data).decode('utf-8')
    except Exception:
        return None

def load_data(file_path, key, is_encrypted=True):
    default_structure = [] if any(s in file_path for s in ['journal', 'clipboard', 'history']) else {}
    if not os.path.exists(file_path):
        return default_structure
    mode = 'rb' if is_encrypted else 'r'
    encoding = None if is_encrypted else 'utf-8'
    try:
        with open(file_path, mode, encoding=encoding) as f:
            content = f.read()
    except Exception:
        return default_structure
    
    if is_encrypted:
        decrypted_json = decrypt_data(content, key)
        return json.loads(decrypted_json) if decrypted_json else None
    else:
        try:
            return json.loads(content) if content else default_structure
        except json.JSONDecodeError:
            return default_structure

def save_data(data, file_path, key, is_encrypted=True):
    json_data = json.dumps(data, indent=4, ensure_ascii=False)
    if is_encrypted:
        content_to_save = encrypt_data(json_data, key)
        mode = 'wb'
    else:
        content_to_save = json_data
        mode = 'w'
    encoding = None if is_encrypted else 'utf-8'
    with open(file_path, mode, encoding=encoding) as f:
        f.write(content_to_save)

# --- MÓDULO: GERENCIADOR DE SENHAS ---
def password_manager_menu(key):
    while True:
        print_header("Gerenciador de Senhas")
        print("1. Adicionar nova senha\n2. Ver senhas salvas\n3. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': add_password(key)
        elif choice == '2': view_passwords(key)
        elif choice == '3': break
def add_password(key):
    print_header("Adicionar Nova Senha")
    service = input("Nome do serviço/app (ex: Google, Steam): ")
    login = input(f"Login/Email para {service}: ")
    password = getpass("Senha: ")
    data = load_data(PASSWORDS_FILE, key)
    if data is None: data = {}
    data[service] = {'login': login, 'password': password}
    save_data(data, PASSWORDS_FILE, key)
    print("\nSenha salva e criptografada com sucesso!")
    input("Pressione Enter...")
def view_passwords(key):
    print_header("Senhas Salvas")
    data = load_data(PASSWORDS_FILE, key)
    if not data: print("Nenhuma senha salva ainda.")
    else:
        for i, service in enumerate(data.keys(), 1): print(f"{i}. {service}")
        try:
            choice = int(input("\nDigite o número para ver os detalhes (ou 0 para voltar): "))
            if choice == 0: return
            service_name = list(data.keys())[choice - 1]
            details = data[service_name]
            print_header(f"Detalhes de: {service_name}")
            print(f"Login: {details['login']}\nSenha: {details['password']}")
        except (ValueError, IndexError): print("\nSeleção inválida.")
    input("\nPressione Enter...")

# --- MÓDULO: LANÇADOR DE APPS ---
def app_locker_menu(key):
    while True:
        print_header("Lançador de Apps Protegido")
        print("1. Configurar novo app\n2. Lançar app\n3. Ver apps configurados\n4. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': add_app(key)
        elif choice == '2': launch_app(key)
        elif choice == '3': view_apps(key)
        elif choice == '4': break
def add_app(key):
    print_header("Configurar App")
    app_path = input("Cole o caminho do executável: ")
    if not os.path.exists(app_path) or not app_path.endswith('.exe'):
        print("\nCaminho inválido.")
        input("Pressione Enter...")
        return
    app_name = input("Dê um apelido para este app: ")
    data = load_data(APPS_FILE, key)
    if data is None: data = {}
    data[app_name] = app_path
    save_data(data, APPS_FILE, key)
    print(f"\nApp '{app_name}' configurado!")
    input("Pressione Enter...")
def launch_app(key):
    print_header("Lançar App")
    apps = load_data(APPS_FILE, key)
    if not apps:
        print("Nenhum app configurado.")
        input("Pressione Enter...")
        return
    app_list = list(apps.keys())
    for i, name in enumerate(app_list, 1): print(f"{i}. {name}")
    try:
        choice = int(input("\nEscolha uma opção (ou 0 para voltar): "))
        if choice == 0: return
        app_name = app_list[choice - 1]
        subprocess.Popen([apps[app_name]])
        print(f"\nLançando '{app_name}'...")
    except (ValueError, IndexError): print("\nSeleção inválida.")
    input("Pressione Enter...")
def view_apps(key):
    print_header("Apps Configurados")
    apps = load_data(APPS_FILE, key)
    if not apps: print("Nenhum app configurado.")
    else:
        for name, path in apps.items(): print(f"- {name}: {path}")
    input("\nPressione Enter...")

# --- MÓDULO: LIMPADOR DE SISTEMA (BÁSICO) ---
def cleaner_menu():
    while True:
        print_header("Limpador de Sistema")
        print("1. Apagar arquivos temporários\n2. Esvaziar lixeira\n3. Aviso sobre cache\n4. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': clean_temp_files()
        elif choice == '2': empty_recycle_bin()
        elif choice == '3': browser_cache_info()
        elif choice == '4': break
def clean_temp_files():
    print_header("Limpando Arquivos Temporários")
    temp_dir = os.environ.get('TEMP')
    deleted_count = 0
    for item in os.listdir(temp_dir):
        path = os.path.join(temp_dir, item)
        try:
            if os.path.isfile(path) or os.path.islink(path): os.unlink(path)
            elif os.path.isdir(path): shutil.rmtree(path)
            deleted_count += 1
        except Exception: pass
    print(f"\nLimpeza concluída! {deleted_count} itens removidos.")
    input("Pressione Enter...")
def empty_recycle_bin():
    print_header("Esvaziando a Lixeira")
    try:
        if os.name == 'nt':
            subprocess.run(["powershell.exe", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"], check=True)
            print("\nLixeira esvaziada com sucesso!")
        else: print("Função disponível apenas para Windows.")
    except Exception as e: print(f"\nFalha ao esvaziar a lixeira: {e}")
    input("Pressione Enter...")
def browser_cache_info():
    print_header("Aviso sobre Cache")
    print("A limpeza de cache de navegadores é mais segura feita pelo próprio navegador.")
    input("\nPressione Enter...")

# --- MÓDULO: FERRAMENTAS DE SISTEMA (AVANÇADO) ---
def system_tools_menu(key):
    while True:
        print_header("Ferramentas de Sistema", color=Fore.RED)
        print("1. Gerenciador de Processos (Ver e Finalizar)")
        print("2. Monitor de Saúde do Hardware (Temperaturas)")
        print("3. Organizador de Arquivos")
        print("4. Limpador de Arquivos Duplicados")
        print("5. Voltar ao menu principal")
        choice = input("\nEscolha uma opção: ")

        if choice == '1': process_manager()
        elif choice == '2': hardware_monitor()
        elif choice == '3': file_organizer(key)
        elif choice == '4': duplicate_cleaner()
        elif choice == '5': break
def process_manager():
    print_header("Gerenciador de Processos", color=Fore.RED)
    try:
        procs = {p.pid: p.info for p in psutil.process_iter(['name', 'username', 'cpu_percent', 'memory_info'])}
    except psutil.AccessDenied:
        print(f"{Fore.RED}Acesso negado para listar processos. Tente executar como administrador.")
        input("Pressione Enter..."); return

    print(f"{'PID':>6} | {'CPU%':>5} | {'Memória (MB)':>12} | {'Nome do Processo':<40}")
    print("-" * 80)
    for pid, info in procs.items():
        try:
            mem_mb = info['memory_info'].rss / (1024 * 1024)
            print(f"{pid:>6} | {info['cpu_percent']:>5.1f} | {mem_mb:>12.2f} | {info['name']:<40}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue

    try:
        pid_to_kill = input("\nDigite o PID do processo para finalizar (ou Enter para voltar): ")
        if pid_to_kill:
            proc_id = int(pid_to_kill)
            confirm = input(f"{Fore.YELLOW}Tem certeza que deseja finalizar o processo {proc_id} ({procs.get(proc_id, {}).get('name')})? (s/n): ").lower()
            if confirm == 's':
                p = psutil.Process(proc_id)
                p.kill()
                print(f"{Fore.GREEN}Processo {proc_id} finalizado.")
            else:
                print("Operação cancelada.")
    except (ValueError, psutil.NoSuchProcess):
        print(f"{Fore.RED}PID inválido ou processo não encontrado.")
    except psutil.AccessDenied:
        print(f"{Fore.RED}Acesso negado. Tente executar o script como administrador.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
    input("\nPressione Enter para continuar...")
def hardware_monitor():
    print_header("Monitor de Saúde do Hardware", color=Fore.RED)
    print("Verificando temperaturas...")
    if hasattr(psutil, "sensors_temperatures"):
        temps = psutil.sensors_temperatures()
        if not temps:
            print(f"{Fore.YELLOW}Não foi possível ler os sensores de temperatura. Tente executar como Admin.")
        else:
            for name, entries in temps.items():
                print(f"\n--- Sensor: {name} ---")
                for entry in entries:
                    color = Fore.GREEN if entry.current < 60 else Fore.YELLOW if entry.current < 80 else Fore.RED
                    print(f"  {entry.label or 'Core':<20}: {color}{entry.current}°C")
    else:
        print("Esta função não é suportada no seu sistema operacional.")
    input("\nPressione Enter para continuar...")
def file_organizer(key):
    print_header("Organizador Automático de Arquivos", color=Fore.RED)
    rules = load_data(FILE_ORGANIZER_RULES, key, is_encrypted=False)
    if not rules:
        rules = {
            "Imagens": [".jpg", ".jpeg", ".png", ".gif", ".bmp"],
            "Documentos": [".pdf", ".docx", ".txt", ".xlsx", ".pptx"],
            "Videos": [".mp4", ".mov", ".avi", ".mkv"],
            "Arquivos Compactados": [".zip", ".rar", ".7z", ".tar.gz"]
        }
        save_data(rules, FILE_ORGANIZER_RULES, key, is_encrypted=False)
    
    print("Regras Atuais:")
    for folder, extensions in rules.items():
        print(f"  - Pasta '{folder}': {', '.join(extensions)}")

    try:
        target_dir = input("\nDigite o caminho da pasta para organizar (ex: C:/Users/SeuUsuario/Downloads): ")
        if not os.path.isdir(target_dir):
            print(f"{Fore.RED}Diretório não encontrado.")
            input("Pressione Enter..."); return

        moved_count = 0
        for filename in os.listdir(target_dir):
            source_path = os.path.join(target_dir, filename)
            if os.path.isfile(source_path):
                for folder, extensions in rules.items():
                    if any(filename.lower().endswith(ext) for ext in extensions):
                        dest_folder = os.path.join(target_dir, folder)
                        os.makedirs(dest_folder, exist_ok=True)
                        dest_path = os.path.join(dest_folder, filename)
                        shutil.move(source_path, dest_path)
                        print(f"Movido: {filename} -> {dest_folder}")
                        moved_count += 1
                        break
        print(f"\n{Fore.GREEN}Organização concluída! {moved_count} arquivos movidos.")
    except Exception as e:
        print(f"\n{Fore.RED}Ocorreu um erro: {e}")
    input("Pressione Enter...")
def duplicate_cleaner():
    print_header("Limpador de Arquivos Duplicados", color=Fore.RED)
    target_dir = input("Digite o caminho da pasta para verificar: ")
    if not os.path.isdir(target_dir):
        print(f"{Fore.RED}Diretório não encontrado.")
        input("Pressione Enter..."); return

    print("\nCalculando hashes... Isso pode demorar em pastas grandes.")
    hashes = {}
    duplicates = []
    for dirpath, _, filenames in os.walk(target_dir):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash in hashes:
                    duplicates.append((filepath, hashes[file_hash]))
                else:
                    hashes[file_hash] = filepath
            except (IOError, OSError):
                continue

    if not duplicates:
        print(f"\n{Fore.GREEN}Nenhum arquivo duplicado encontrado.")
    else:
        print(f"\n{Fore.YELLOW}Encontrados {len(duplicates)} arquivos duplicados.")
        confirm = input("Deseja ver a lista e escolher quais apagar? (s/n): ").lower()
        if confirm == 's':
            deleted_count = 0
            for dup_file, original_file in duplicates:
                try:
                    print(f"\nDuplicado: {dup_file} (Original: {original_file})")
                    choice = input(f"{Fore.YELLOW}Apagar o arquivo duplicado? (s/n): ").lower()
                    if choice == 's':
                        os.remove(dup_file)
                        print(f"{Fore.GREEN}Arquivo removido.")
                        deleted_count += 1
                except Exception as e:
                    print(f"{Fore.RED}Erro ao remover {dup_file}: {e}")
            print(f"\nLimpeza finalizada. {deleted_count} arquivos removidos.")

    input("\nPressione Enter...")

# --- MÓDULO: MONITOR DE TEMPO DE USO ---
def pc_time_menu():
    global window_tracker_thread
    while True:
        tracking_status = "ATIVO" if window_tracker_thread and window_tracker_thread.is_alive() else "INATIVO"
        print_header("Monitor de Tempo de Uso")
        print(f"Status do rastreamento: {Fore.GREEN if tracking_status == 'ATIVO' else Fore.RED}{tracking_status}{Style.RESET_ALL}\n")
        print("1. Ver tempo de PC ligado\n2. Ver tempo por programa (hoje)\n3. Ver histórico semanal")
        print("4. " + ("Parar" if tracking_status == "ATIVO" else "Iniciar") + " rastreamento\n5. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': show_pc_uptime()
        elif choice == '2': show_window_times()
        elif choice == '3': show_weekly_history()
        elif choice == '4':
            if tracking_status == "ATIVO":
                stop_event.set(); window_tracker_thread.join(); window_tracker_thread = None; stop_event.clear()
            else:
                window_tracker_thread = threading.Thread(target=track_window_activity, args=(stop_event,)); window_tracker_thread.daemon = True; window_tracker_thread.start()
            input("Pressione Enter...")
        elif choice == '5': break
def track_window_activity(stop_event):
    data = load_data(WINDOW_TRACK_FILE, None, is_encrypted=False)
    today_str = str(datetime.date.today())
    if today_str not in data: data[today_str] = {}
    last_active_window = None
    time_start = time.time()
    while not stop_event.is_set():
        try:
            active_window = pygetwindow.getActiveWindow()
            current_time = time.time()
            if active_window and active_window.title and active_window != last_active_window:
                if last_active_window and last_active_window.title:
                    duration = current_time - time_start
                    data[today_str][last_active_window.title] = data[today_str].get(last_active_window.title, 0) + duration
                last_active_window = active_window
                time_start = current_time
            if current_time - time_start > 30 and last_active_window and last_active_window.title: # Salva a cada 30s
                duration = current_time - time_start
                data[today_str][last_active_window.title] = data[today_str].get(last_active_window.title, 0) + duration
                save_data(data, WINDOW_TRACK_FILE, None, is_encrypted=False)
                time_start = current_time
        except pygetwindow.PyGetWindowException: pass
        time.sleep(1)
def show_pc_uptime():
    print_header("Tempo de PC Ligado Hoje"); print(f"O PC está ligado há: {Fore.GREEN}{format_seconds(time.time() - psutil.boot_time())}"); input("\nPressione Enter...")
def show_window_times():
    print_header("Tempo de Uso por Programa (Hoje)")
    data = load_data(WINDOW_TRACK_FILE, None, is_encrypted=False)
    today_str = str(datetime.date.today())
    if not data.get(today_str): print("Nenhum dado para hoje. Ative o rastreamento.")
    else:
        sorted_times = sorted(data[today_str].items(), key=lambda item: item[1], reverse=True)
        for title, seconds in sorted_times: print(f"{Fore.YELLOW}{format_seconds(seconds)}{Style.RESET_ALL} - {title[:60]}")
    input("\nPressione Enter...")
def show_weekly_history():
    print_header("Histórico da Semana (Uso de Janelas)")
    data = load_data(WINDOW_TRACK_FILE, None, is_encrypted=False)
    today = datetime.date.today()
    print("Tempo total rastreado por dia:\n")
    for i in range(7):
        day = today - datetime.timedelta(days=i)
        total_seconds = sum(data.get(str(day), {}).values())
        print(f"{day.strftime('%d/%m/%Y (%A)'):<25}: {Fore.GREEN}{format_seconds(total_seconds)}")
    input("\nPressione Enter...")

# --- MÓDULO: CHEATS (AUTOCLICKER) ---
def cheats_menu():
    global hotkey_listener
    if hotkey_listener: hotkey_listener.stop(); hotkey_listener = None
    print_header("Cheats - Autoclicker com Hotkey F6"); print("Esta função ativa a tecla F6 para LIGAR e DESLIGAR um autoclicker.")
    try:
        interval = float(input("\nDefina o intervalo entre cliques (em segundos, ex: 0.1): "))
        if interval <= 0: print(f"{Fore.RED}O intervalo deve ser um número positivo."); input("Pressione Enter..."); return
    except ValueError: print(f"{Fore.RED}Intervalo inválido."); input("Pressione Enter..."); return
    def on_press(key):
        if key == keyboard.Key.f6: toggle_autoclicker(interval)
    hotkey_listener = keyboard.Listener(on_press=on_press); hotkey_listener.start()
    print(f"\n{Fore.GREEN}Hotkey F6 ativada com intervalo de {interval}s!"); input("\nPressione Enter para voltar ao menu principal...")
def autoclicker_task(interval, button):
    mouse_controller = mouse.Controller()
    while autoclicker_running.is_set():
        mouse_controller.click(button)
        time.sleep(interval)
def toggle_autoclicker(interval):
    global autoclicker_thread
    if autoclicker_running.is_set():
        autoclicker_running.clear();
        if autoclicker_thread: autoclicker_thread.join()
        autoclicker_thread = None
        print(f"\n{Fore.GREEN}Autoclicker DESATIVADO via F6.")
    else:
        print(f"\n{Fore.YELLOW}Autoclicker ATIVADO via F6. Pressione F6 novamente para parar.")
        autoclicker_running.set()
        autoclicker_thread = threading.Thread(target=autoclicker_task, args=(interval, mouse.Button.left)); autoclicker_thread.daemon = True; autoclicker_thread.start()

# --- MÓDULO: FERRAMENTAS DE REDE ---
def network_tools_menu():
    while True:
        print_header("Ferramentas de Rede", color=Fore.BLUE)
        print("1. Teste de Velocidade da Internet (Speed Test)")
        print("2. Consultar Informações de IP")
        print("3. Verificador de Status de Website")
        print("4. Voltar ao menu principal")
        choice = input("\nEscolha uma opção: ")

        if choice == '1': run_speed_test()
        elif choice == '2': ip_lookup()
        elif choice == '3': check_website_status()
        elif choice == '4': break
def run_speed_test():
    print_header("Teste de Velocidade da Internet", color=Fore.BLUE)
    try:
        print("Iniciando o teste... Isso pode levar um minuto.")
        st = speedtest.Speedtest()
        st.get_best_server()
        
        print("Medindo velocidade de Download...")
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        
        print("Medindo velocidade de Upload...")
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        
        ping = st.results.ping

        print("\n--- Resultados ---")
        print(f"Download: {Fore.GREEN}{download_speed:.2f} Mbps")
        print(f"Upload:   {Fore.CYAN}{upload_speed:.2f} Mbps")
        print(f"Ping:     {Fore.YELLOW}{ping:.2f} ms")

    except speedtest.ConfigRetrievalError:
        print(f"{Fore.RED}Não foi possível conectar para buscar a configuração do teste.")
    except Exception as e:
        print(f"{Fore.RED}Ocorreu um erro inesperado: {e}")
    input("\nPressione Enter...")
def ip_lookup():
    print_header("Consulta de Informações de IP", color=Fore.BLUE)
    ip_address = input("Digite o endereço de IP (ou deixe em branco para seu IP público): ")
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            print("\n--- Informações Encontradas ---")
            print(f"IP: {data.get('query')}")
            print(f"País: {data.get('country')}")
            print(f"Cidade: {data.get('city')}")
            print(f"Provedor (ISP): {data.get('isp')}")
            print(f"Organização: {data.get('org')}")
        else:
            print(f"{Fore.RED}Não foi possível obter informações para o IP: {ip_address}")
    except requests.RequestException as e:
        print(f"{Fore.RED}Erro de conexão: {e}")
    input("\nPressione Enter...")
def check_website_status():
    print_header("Verificador de Status de Website", color=Fore.BLUE)
    urls_input = input("Digite uma ou mais URLs, separadas por vírgula: ")
    urls = [url.strip() for url in urls_input.split(',')]
    
    print("\nVerificando...\n")
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code >= 200 and response.status_code < 400:
                print(f"{Fore.GREEN}[ONLINE]  {url} (Status: {response.status_code})")
            else:
                print(f"{Fore.YELLOW}[PROBLEMA] {url} (Status: {response.status_code})")
        except requests.ConnectionError:
            print(f"{Fore.RED}[OFFLINE] {url} (Falha na conexão)")
        except requests.Timeout:
            print(f"{Fore.RED}[OFFLINE] {url} (Tempo esgotado)")
        except Exception as e:
            print(f"{Fore.RED}[ERRO]    {url} ({e})")
    input("\nPressione Enter...")

# --- MÓDULO: FERRAMENTAS DE LINK ---
def link_tools_menu():
    while True:
        print_header("Ferramentas de Link")
        print("1. Encurtar um link\n2. Gerar QR Code\n3. Criar link de WhatsApp\n4. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': shorten_link()
        elif choice == '2': generate_qr_code()
        elif choice == '3': create_whatsapp_link()
        elif choice == '4': break
def shorten_link():
    print_header("Encurtador de Link"); long_url = input("Cole a URL longa: ")
    try:
        response = requests.get(f"http://tinyurl.com/api-create.php?url={long_url}"); response.raise_for_status()
        print(f"\n{Fore.GREEN}Link encurtado: {response.text}")
    except requests.RequestException as e: print(f"\n{Fore.RED}Erro: {e}")
    input("\nPressione Enter...")
def generate_qr_code():
    print_header("Gerador de QR Code"); data = input("Digite o texto ou link para o QR Code: ")
    print("\n1. Mostrar no terminal\n2. Salvar como imagem (qrcode.png)"); choice = input("Escolha: ")
    qr = qrcode.QRCode(version=1, box_size=10, border=4); qr.add_data(data); qr.make(fit=True)
    if choice == '1': qr.print_tty()
    elif choice == '2':
        img = qr.make_image(fill='black', back_color='white'); img.save("qrcode.png"); print(f"\n{Fore.GREEN}QR Code salvo como 'qrcode.png'")
    else: print(f"{Fore.RED}Opção inválida.")
    input("\nPressione Enter...")
def create_whatsapp_link():
    print_header("Gerador de Link para WhatsApp"); phone = input("Digite o número (DDI+DDD+Numero, ex: 55119...): "); message = input("Digite a mensagem padrão (opcional): ")
    link = f"https://wa.me/{phone}" + (f"?text={quote(message)}" if message else ""); print(f"\n{Fore.GREEN}Seu link: {link}"); input("\nPressione Enter...")

# --- MÓDULO: PRODUTIVIDADE E PESSOAL ---
def productivity_menu(key):
    while True:
        print_header("Produtividade e Gerenciamento Pessoal", color=Fore.MAGENTA)
        print("1. Diário Pessoal Criptografado")
        print("2. Rastreador de Hábitos")
        print("3. Gerenciador de Clipboard (Área de Transferência)")
        print("4. Voltar ao menu principal")
        choice = input("\nEscolha uma opção: ")

        if choice == '1': journal_menu(key)
        elif choice == '2': habit_tracker_menu(key)
        elif choice == '3': clipboard_manager_menu(key)
        elif choice == '4': break
def journal_menu(key):
    while True:
        print_header("Diário Pessoal Criptografado", color=Fore.MAGENTA)
        print("1. Adicionar Nova Entrada")
        print("2. Ver Entradas Antigas")
        print("3. Voltar")
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            entry_content = input("Escreva sua entrada (pressione Enter para finalizar):\n> ")
            journal_data = load_data(JOURNAL_FILE, key, is_encrypted=True)
            if journal_data is None: journal_data = [] # Trata erro de descriptografia inicial
            
            new_entry = {
                'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'content': entry_content
            }
            journal_data.append(new_entry)
            save_data(journal_data, JOURNAL_FILE, key, is_encrypted=True)
            print(f"\n{Fore.GREEN}Entrada salva com segurança!")
            input("Pressione Enter...")
        elif choice == '2':
            journal_data = load_data(JOURNAL_FILE, key, is_encrypted=True)
            if not journal_data:
                print("Nenhuma entrada no diário ainda.")
            else:
                for entry in reversed(journal_data):
                    print("-" * 40)
                    print(f"{Fore.YELLOW}Data: {entry['date']}")
                    print(f"{entry['content']}")
            input("\nPressione Enter...")
        elif choice == '3':
            break
def habit_tracker_menu(key):
    data = load_data(HABITS_FILE, key, is_encrypted=False)
    if 'habits' not in data: data['habits'] = []
    if 'log' not in data: data['log'] = {}

    while True:
        print_header("Rastreador de Hábitos", color=Fore.MAGENTA)
        print("1. Adicionar/Remover Hábito")
        print("2. Registrar Hábitos de Hoje")
        print("3. Ver Estatísticas (Últimos 7 dias)")
        print("4. Voltar")
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            print("Hábitos atuais:", ", ".join(data['habits']) if data['habits'] else "Nenhum")
            sub_choice = input("Digite 'add <nome>' ou 'rem <nome>': ").split(" ", 1)
            action = sub_choice[0].lower()
            if len(sub_choice) > 1:
                habit_name = sub_choice[1]
                if action == 'add' and habit_name not in data['habits']:
                    data['habits'].append(habit_name)
                    print(f"Hábito '{habit_name}' adicionado.")
                elif action == 'rem' and habit_name in data['habits']:
                    data['habits'].remove(habit_name)
                    print(f"Hábito '{habit_name}' removido.")
                save_data(data, HABITS_FILE, key, is_encrypted=False)
            input("Pressione Enter...")
        elif choice == '2':
            today_str = str(datetime.date.today())
            if today_str not in data['log']: data['log'][today_str] = {}
            for habit in data['habits']:
                if habit not in data['log'][today_str]:
                    answer = input(f"Você completou o hábito '{habit}' hoje? (s/n): ").lower()
                    data['log'][today_str][habit] = (answer == 's')
            save_data(data, HABITS_FILE, key, is_encrypted=False)
            print("Registro de hoje salvo!")
            input("Pressione Enter...")
        elif choice == '3':
            print_header("Estatísticas de Hábitos", color=Fore.MAGENTA)
            today = datetime.date.today()
            for i in range(7):
                day = today - datetime.timedelta(days=i)
                day_str = str(day)
                print(f"\n--- {day.strftime('%d/%m/%Y')} ---")
                if not data['habits']:
                    print("Nenhum hábito definido.")
                    break
                for habit in data['habits']:
                    status = data['log'].get(day_str, {}).get(habit)
                    if status is True:
                        print(f"  {Fore.GREEN}✔ {habit}")
                    elif status is False:
                        print(f"  {Fore.RED}❌ {habit}")
                    else:
                        print(f"  {Fore.YELLOW}? {habit} (Não registrado)")
            input("\nPressione Enter...")
        elif choice == '4':
            break
def clipboard_listener_task(stop_event):
    last_value = ""
    history = load_data(CLIPBOARD_FILE, None, is_encrypted=False)
    if not isinstance(history, list): history = []
    
    while not stop_event.is_set():
        try:
            current_value = pyperclip.paste()
            if current_value != last_value and current_value:
                if not history or history[0] != current_value:
                    history.insert(0, current_value)
                    history = history[:20] # Limita o histórico
                    save_data(history, CLIPBOARD_FILE, None, is_encrypted=False)
                last_value = current_value
        except pyperclip.PyperclipException:
            pass
        time.sleep(1)
def clipboard_manager_menu(key):
    global clipboard_listener_thread
    while True:
        tracking_status = "ATIVO" if clipboard_listener_thread and clipboard_listener_thread.is_alive() else "INATIVO"
        print_header("Gerenciador de Clipboard", color=Fore.MAGENTA)
        print(f"Status do monitoramento: {Fore.GREEN if tracking_status == 'ATIVO' else Fore.RED}{tracking_status}{Style.RESET_ALL}\n")
        print("1. " + ("Parar" if tracking_status == "ATIVO" else "Iniciar") + " Monitoramento")
        print("2. Ver Histórico e Copiar")
        print("3. Voltar")
        choice = input("\nEscolha uma opção: ")
        
        if choice == '1':
            if tracking_status == "ATIVO":
                stop_clipboard_event.set()
                if clipboard_listener_thread: clipboard_listener_thread.join()
                clipboard_listener_thread = None
                stop_clipboard_event.clear()
            else:
                clipboard_listener_thread = threading.Thread(target=clipboard_listener_task, args=(stop_clipboard_event,))
                clipboard_listener_thread.daemon = True
                clipboard_listener_thread.start()
            input("Pressione Enter...")
        elif choice == '2':
            history = load_data(CLIPBOARD_FILE, key, is_encrypted=False)
            if not history:
                print("Histórico vazio. Ative o monitoramento para começar.")
            else:
                print("--- Histórico da Área de Transferência ---")
                for i, item in enumerate(history, 1):
                    # Tenta formatar para evitar quebras de linha longas
                    formatted_item = str(item).replace('\n', ' ').replace('\r', '')
                    print(f"{i}. {formatted_item[:70]}...")
                try:
                    num_choice = int(input("\nDigite o número do item para copiar (ou 0 para voltar): "))
                    if 0 < num_choice <= len(history):
                        pyperclip.copy(history[num_choice - 1])
                        print(f"{Fore.GREEN}Item {num_choice} copiado para a área de transferência!")
                    elif num_choice != 0:
                        print(f"{Fore.RED}Número inválido.")
                except ValueError:
                    print(f"{Fore.RED}Entrada inválida.")
            input("Pressione Enter...")
        elif choice == '3':
            break

# --- MÓDULO: ECONOMIA ---
def economy_menu(key):
    while True:
        print_header("Módulo de Economia", color=Fore.YELLOW)
        print("1. Pesquisar preço de produto\n2. Organizador de Orçamento\n3. Rastreador de Meta de Economia\n4. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': search_product_price()
        elif choice == '2': budget_organizer()
        elif choice == '3': savings_goal_tracker(key)
        elif choice == '4': break
def search_product_price():
    print_header("Pesquisar Preço de Produto", color=Fore.YELLOW)
    product_name = input("Digite o nome do produto: ")
    print(f"\nPesquisando por '{product_name}'...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        url = f"https://www.google.com/search?q=preço+{product_name.replace(' ', '+')}&tbm=shop"
        response = requests.get(url, headers=headers); response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find_all('div', class_='sh-dgr__content')
        if not results:
            print(f"{Fore.YELLOW}Não foram encontrados resultados diretos no Shopping.")
            input("Pressione Enter..."); return
        print("\n--- Preços Encontrados (Google Shopping) ---\n")
        for item in results[:5]:
            title = item.find('h3', class_='sh-np__product-title').get_text(strip=True) if item.find('h3') else "N/A"
            price = item.find('span', class_='a8Pemb').get_text(strip=True) if item.find('span', class_='a8Pemb') else "N/A"
            source = item.find('div', class_='sh-np__seller-container').get_text(strip=True) if item.find('div', class_='sh-np__seller-container') else "N/A"
            print(f"{Fore.GREEN}{price:<15} {Style.RESET_ALL}- {title} ({source})")
    except requests.RequestException as e: print(f"\n{Fore.RED}Erro de conexão: {e}")
    except Exception as e: print(f"\n{Fore.RED}Erro inesperado: {e}")
    print("\nAVISO: Os preços são uma estimativa."); input("Pressione Enter...")
def budget_organizer():
    print_header("Organizador de Orçamento", color=Fore.YELLOW)
    try: budget = float(input("Digite o seu orçamento total: R$ "))
    except ValueError: print(f"{Fore.RED}Valor inválido."); input("Pressione Enter..."); return
    items = []
    while True:
        item_name = input("Digite o nome do item (ou enter para terminar): ")
        if not item_name: break
        try:
            item_price = float(input(f"Preço de '{item_name}': R$ "))
            item_priority = int(input(f"Prioridade de '{item_name}' (1=mais importante): "))
            items.append({'name': item_name, 'price': item_price, 'priority': item_priority})
        except ValueError: print(f"{Fore.RED}Valor inválido.")
    items.sort(key=lambda x: x['priority'])
    print_header("Plano de Compra Sugerido", color=Fore.YELLOW)
    print(f"Orçamento Total: {Fore.GREEN}R$ {budget:.2f}\n")
    cumulative_cost = 0
    for item in items:
        cumulative_cost += item['price']
        status = f"{Fore.GREEN}DENTRO DO ORÇAMENTO" if cumulative_cost <= budget else f"{Fore.RED}ACIMA DO ORÇAMENTO"
        print(f"Prioridade {item['priority']}: {item['name']} - R$ {item['price']:.2f}")
        print(f"Custo acumulado: R$ {cumulative_cost:.2f} ({status}{Style.RESET_ALL})\n")
    input("Pressione Enter...")
def savings_goal_tracker(key):
    while True:
        data = load_data(ECONOMY_FILE, key, is_encrypted=True) # Alterado para True
        if data is None: data = {}
        goal_name = data.get('goal_name', 'Nenhuma meta definida')
        goal_amount = data.get('goal_amount', 0)
        current_savings = data.get('current_savings', 0)
        print_header("Rastreador de Metas", color=Fore.YELLOW)
        print(f"Sua meta atual: {Fore.CYAN}{goal_name}{Style.RESET_ALL}")
        if goal_amount > 0:
            progress = (current_savings / goal_amount) * 100 if goal_amount > 0 else 0
            bar = '█' * int(20 * progress / 100) + '░' * (20 - int(20 * progress / 100))
            print(f"Progresso: {Fore.GREEN}R$ {current_savings:.2f} / R$ {goal_amount:.2f}")
            print(f"[{bar}] {progress:.1f}%")
        print("\n1. Definir/Alterar meta\n2. Adicionar economia\n3. Ver histórico\n4. Voltar")
        choice = input("\nEscolha uma opção: ")
        if choice == '1':
            try:
                data['goal_name'] = input("Qual o nome da sua meta? ")
                data['goal_amount'] = float(input("Qual o valor da meta? R$ "))
                data.setdefault('current_savings', 0)
                data.setdefault('history', [])
                save_data(data, ECONOMY_FILE, key, is_encrypted=True)
                print(f"{Fore.GREEN}Meta salva!")
            except ValueError: print(f"{Fore.RED}Valor inválido.")
            input("Pressione Enter...")
        elif choice == '2':
            if not data.get('goal_name'): print(f"{Fore.RED}Defina uma meta primeiro."); input("Pressione Enter..."); continue
            try:
                amount_saved = float(input("Quanto você economizou? R$ ")); note = input("Nota (opcional): ")
                data['current_savings'] = data.get('current_savings', 0) + amount_saved
                data.setdefault('history', []).append({'date': datetime.date.today().isoformat(), 'amount': amount_saved, 'note': note})
                save_data(data, ECONOMY_FILE, key, is_encrypted=True)
                print(f"{Fore.GREEN}Economia registrada!")
            except ValueError: print(f"{Fore.RED}Valor inválido.")
            input("Pressione Enter...")
        elif choice == '3':
            print_header("Histórico de Economias", color=Fore.YELLOW)
            for record in reversed(data.get('history', [])): print(f"{record['date']}: {Fore.GREEN}+R$ {record['amount']:.2f}{Style.RESET_ALL} - {record['note']}")
            input("\nPressione Enter...")
        elif choice == '4': break

# --- MÓDULO: ESTUDOS ---
def studies_menu(key):
    while True:
        print_header("Módulo de Estudos", color=Fore.MAGENTA)
        print("1. Organização de Tarefas da Escola")
        print("2. Notas por Matéria")
        print("3. Voltar ao menu principal")
        choice = input("\nEscolha uma opção: ")
        if choice == '1': school_task_organizer(key)
        elif choice == '2': grade_tracker(key)
        elif choice == '3': break
        else: print(f"{Fore.RED}Opção inválida."); input("Pressione Enter...")
def school_task_organizer(key):
    while True:
        data = load_data(STUDIES_FILE, key, is_encrypted=True) # Alterado para True
        if data is None: data = {}
        tasks = data.get('tasks', [])
        
        print_header("Organizador de Tarefas", color=Fore.MAGENTA)
        print("Tarefas Pendentes:")
        pending_tasks = [t for t in tasks if t['status'] == 'pending']
        if not pending_tasks:
            print("Nenhuma tarefa pendente. Parabéns!")
        else:
            pending_tasks.sort(key=lambda x: x.get('due_date', ''))
            for task in pending_tasks:
                print(f"  [ID: {task.get('id', 'N/A')}] {task.get('due_date', 'N/A')} - {task.get('subject', 'N/A')}: {task.get('description', 'N/A')}")

        print("\n1. Adicionar tarefa\n2. Marcar como concluída\n3. Remover tarefa\n4. Ver concluídas\n5. Voltar")
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            desc = input("Descrição da tarefa: "); subj = input("Matéria: "); due = input("Data de entrega (AAAA-MM-DD): ")
            tasks = data.setdefault('tasks', []); new_id = data.get('last_task_id', 0) + 1
            tasks.append({'id': new_id, 'description': desc, 'subject': subj, 'due_date': due, 'status': 'pending'})
            data['last_task_id'] = new_id; save_data(data, STUDIES_FILE, key, is_encrypted=True)
        elif choice == '2':
            try:
                task_id = int(input("Digite o ID da tarefa concluída: "))
                task_found = any(t['id'] == task_id and t.update({'status': 'completed'}) for t in data.get('tasks', []))
                if task_found: save_data(data, STUDIES_FILE, key, is_encrypted=True); print(f"{Fore.GREEN}Tarefa concluída!")
                else: print(f"{Fore.RED}ID não encontrado.")
            except ValueError: print(f"{Fore.RED}ID inválido.")
            input("Pressione Enter...")
        elif choice == '3':
            try:
                task_id = int(input("Digite o ID da tarefa para remover: "))
                original_len = len(data.get('tasks', []))
                data['tasks'] = [t for t in data.get('tasks', []) if t.get('id') != task_id]
                if len(data['tasks']) < original_len:
                    save_data(data, STUDIES_FILE, key, is_encrypted=True); print(f"{Fore.GREEN}Tarefa removida.")
                else: print(f"{Fore.RED}ID não encontrado.")
            except ValueError: print(f"{Fore.RED}ID inválido.")
            input("Pressione Enter...")
        elif choice == '4':
            print_header("Tarefas Concluídas", color=Fore.MAGENTA)
            completed_tasks = [t for t in data.get('tasks', []) if t.get('status') == 'completed']
            if not completed_tasks: print("Nenhuma tarefa concluída ainda.")
            else:
                for task in completed_tasks: print(f"  [CONCLUÍDA] {task.get('due_date','N/A')} - {task.get('subject','N/A')}: {task.get('description','N/A')}")
            input("\nPressione Enter...")
        elif choice == '5': break
def grade_tracker(key):
    while True:
        data = load_data(STUDIES_FILE, key, is_encrypted=True) # Alterado para True
        if data is None: data = {}
        grades = data.get('grades', {})
        print_header("Notas por Matéria", color=Fore.MAGENTA)
        
        if not grades: print("Nenhuma nota registrada ainda.")
        else:
            for subject, notes in grades.items():
                avg = sum(notes) / len(notes) if notes else 0
                avg_color = Fore.GREEN if avg >= 7 else Fore.YELLOW if avg >= 5 else Fore.RED
                print(f"- {subject}: Notas {notes} -> Média: {avg_color}{avg:.2f}{Style.RESET_ALL}")
        
        print("\n1. Adicionar nota\n2. Remover matéria\n3. Voltar")
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            subj = input("Digite o nome da matéria: ")
            try:
                note = float(input(f"Digite a nota para {subj}: "))
                data.setdefault('grades', {}).setdefault(subj, []).append(note)
                save_data(data, STUDIES_FILE, key, is_encrypted=True)
            except ValueError: print(f"{Fore.RED}Nota inválida.")
        elif choice == '2':
            subj = input("Qual matéria deseja remover? ")
            if subj in data.get('grades', {}):
                del data['grades'][subj]; save_data(data, STUDIES_FILE, key, is_encrypted=True); print(f"{Fore.GREEN}Matéria removida.")
            else: print(f"{Fore.RED}Matéria não encontrada.")
            input("Pressione Enter...")
        elif choice == '3': break

# --- MÓDULO: MODO HACKER ---
def hacker_mode():
    print_header("MODO HACKER", color=Fore.GREEN); print(Fore.GREEN + "Iniciando simulação... Pressione CTRL+C para sair.\n"); time.sleep(1)
    lines = [ "Iniciando varredura...", "Conectando ao servidor...", "Bypassando firewall...", "Acesso concedido.", "Baixando arquivos...", "[##########] 100%", "AVISO: Rastreamento detectado...", "Apagando logs...", "Conexão encerrada." ]
    try:
        while True:
            for line in lines:
                for char in line: print(Fore.GREEN + char, end='', flush=True); time.sleep(0.02)
                print(); time.sleep(random.uniform(0.3, 0.8))
            print("\nReiniciando sequência...\n"); time.sleep(2)
    except KeyboardInterrupt: print(Style.RESET_ALL + "\n\nSimulação terminada."); input("Pressione Enter...")

# --- INICIALIZAÇÃO E LOOP PRINCIPAL ---
def main():
    global MASTER_PASSWORD
    if not os.path.exists(SALT_FILE):
        print_header("Configuração Inicial")
        while True:
            password = getpass("Crie sua senha mestra: ")
            if password and password == getpass("Confirme sua senha mestra: "): break
            print("As senhas não coincidem ou estão vazias.")
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f: f.write(salt)
        MASTER_PASSWORD = password
    else:
        with open(SALT_FILE, 'rb') as f: salt = f.read()

    if MASTER_PASSWORD is None:
        print_header("Login")
        while True:
            password_attempt = getpass("Digite sua senha mestra: ")
            key_attempt = get_key_from_password(password_attempt, salt)
            # Testa a chave tentando descriptografar um arquivo. Se falhar, a senha está errada.
            if load_data(PASSWORDS_FILE, key_attempt, is_encrypted=True) is not None:
                MASTER_PASSWORD = password_attempt
                break
            print("Senha mestra incorreta.")
    
    key = get_key_from_password(MASTER_PASSWORD, salt)
    MASTER_PASSWORD = None # Limpa a senha da memória por segurança

    while True:
        print_header("Painel de Controle PRO")
        print(f"{Fore.CYAN}--- Gerenciamento e Segurança ---")
        print("1. Gerenciador de Senhas")
        print("2. Lançador de Apps Protegido")
        print("3. Limpador de Sistema (Básico)")

        print(f"\n{Fore.RED}--- Ferramentas de Sistema e Automação ---")
        print("4. Ferramentas Avançadas de Sistema")
        print("5. Monitor de Tempo de Uso")
        print("6. Cheats Offline (Autoclicker F6)")

        print(f"\n{Fore.BLUE}--- Rede e Internet ---")
        print("7. Ferramentas de Rede")
        print("8. Ferramentas de Link (Encurtador, QR Code)")

        print(f"\n{Fore.MAGENTA}--- Produtividade e Pessoal ---")
        print("9. Módulo de Produtividade")
        print(f"{Fore.YELLOW}10. Módulo de Economia")
        print(f"11. Módulo de Estudos")
        
        print(f"\n{Fore.GREEN}12. MODO HACKER{Style.RESET_ALL}")
        print("\n13. Sair")
        choice = input("\nEscolha uma opção: ")

        if choice == '1': password_manager_menu(key)
        elif choice == '2': app_locker_menu(key)
        elif choice == '3': cleaner_menu()
        elif choice == '4': system_tools_menu(key)
        elif choice == '5': pc_time_menu()
        elif choice == '6': cheats_menu()
        elif choice == '7': network_tools_menu()
        elif choice == '8': link_tools_menu()
        elif choice == '9': productivity_menu(key)
        elif choice == '10': economy_menu(key)
        elif choice == '11': studies_menu(key)
        elif choice == '12': hacker_mode()
        elif choice == '13':
            print("\nEncerrando processos em segundo plano...")
            stop_event.set()
            stop_clipboard_event.set() # Para o novo listener
            if autoclicker_running.is_set(): autoclicker_running.clear()
            if hotkey_listener: hotkey_listener.stop()
            print("Até logo!")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPrograma interrompido pelo usuário. Encerrando...")
    except Exception as e:
        print(f"\n\nOcorreu um erro inesperado: {e}")
        import traceback
        traceback.print_exc()
        input("Pressione Enter para sair.")
    finally:
        # Garante que os threads sejam parados na saída
        stop_event.set()
        stop_clipboard_event.set()
        if autoclicker_running.is_set(): autoclicker_running.clear()
        if hotkey_listener: hotkey_listener.stop()