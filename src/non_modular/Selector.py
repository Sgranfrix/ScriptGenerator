from collections import Counter
import re
import pm4py
#######
import networkx as nx
import xml.etree.ElementTree as ET
#per la parte GUI
import tkinter as tk
from tkinter import ttk


#####################################################################
#Prova stampa primi x percorsi del dfg

def analyze_dfg_costly_paths(dfg, start_activities, end_activities):
    """
    Analizza il DFG e trova i percorsi più costosi dalla start alla end activity, mettendoli in ordine decrescente a partire dal path col costo più alto
    """
    dfg_activities = set()
    for (act1, act2) in dfg:
        dfg_activities.add(act1)
        dfg_activities.add(act2)

    # Debug print
    print("DFG activities:", dfg_activities)
    print("Start activities:", start_activities)
    print("End activities:", end_activities)

    # se non lo sono già converte a set
    if isinstance(start_activities, dict):
        start_set = set(start_activities.keys())
    else:
        start_set = set(start_activities)

    if isinstance(end_activities, dict):
        end_set = set(end_activities.keys())
    else:
        end_set = set(end_activities)

    valid_starts = start_set & dfg_activities
    valid_ends = end_set & dfg_activities

    print("Valid starts:", valid_starts)
    print("Valid ends:", valid_ends)

    if not valid_starts or not valid_ends:
        raise ValueError("Nessuna attività di start/end valida trovata nel DFG")

    G = nx.DiGraph()
    for (act1, act2), weight in dfg.items():
        G.add_edge(act1, act2, weight=weight)

    costly_paths = []
    for start in valid_starts:
        if start not in G:
            continue  # salto i nodi che non esistono nel grafo
        for end in valid_ends:
            try:
                paths = nx.all_simple_paths(G, start, end)
                for path in paths:
                    cost = sum(dfg.get((path[i], path[i + 1]), 0)
                               for i in range(len(path) - 1))
                    costly_paths.append((path, cost))
            except nx.NetworkXNoPath:
                continue

    costly_paths.sort(key=lambda x: x[1], reverse=True)
    return costly_paths


################################################################################################
#Prova isolamento inditizzo ip macchinata attaccata
def analyze_xes_attack_logs(file_path):
    """
    Analizza i file XES per identificare l'indirizzo IP dell'host attaccato.

    Args:
        file_path (str): Percorso del file XES da analizzare

    Returns:
        dict: Informazioni sull'host attaccato
    """
    try:
        # Parsifica il file XES
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Namespace per XES
        ns = {'xes': 'http://www.xes-standard.org/'}

        # Raccogli tutti gli indirizzi IP nei log
        ip_addresses = []

        # Cerca gli IP nelle varie parti del log
        for log_entry in root.findall('.//xes:event', namespaces=ns):
            # Cerca IP in vari campi potenziali
            ip_fields = [
                './/xes:string[@key="ip"]',
                './/xes:string[@key="dst_ip"]',
                './/xes:string[@key="dest_ip"]',
                './/xes:string[@key="destination_ip"]'
            ]

            for field in ip_fields:
                ip_elem = log_entry.find(field, namespaces=ns)
                if ip_elem is not None:
                    ip = ip_elem.get('value')
                    if ip:
                        ip_addresses.append(ip)

        # Trova l'IP più frequente (probabile host attaccato)
        if ip_addresses:
            ip_counter = Counter(ip_addresses)
            most_common_ip = ip_counter.most_common(1)[0]

            return {
                'attacked_ip': most_common_ip[0],
                'occurrence_count': most_common_ip[1],
                'total_ip_mentions': len(ip_addresses)
            }

        return None

    except ET.ParseError:
        print("Errore nel parsing del file XES")
        return None
    except Exception as e:
        print(f"Errore durante l'analisi: {e}")
        return None




################################################################################################
#Funzione per la generazione dello script

# https://www.w3schools.com/python/ref_requests_post.asp
from urllib.parse import urljoin


def create_attack_script(attack_path):
    """
    Crea uno script di attacco basato su un path di attacco specificato

    Args:
        target_ip (str): Indirizzo IP della macchina target
        attack_path (tuple): Tupla contenente lista di richieste e codice
    """

    # Estrai la lista di richieste dalla tupla
    if isinstance(attack_path, tuple) and len(attack_path) > 0:
        requests_list = attack_path[0]
    else:
        requests_list = attack_path

    # Verifica che requests_list sia una lista
    if not isinstance(requests_list, (list, tuple)):
        requests_list = [requests_list]

    # Controlla se c'è una richiesta POST a un endpoint di register
    has_post_register = any(
        str(req).strip().upper().startswith("POST") and "register" in str(req).lower()
        for req in requests_list
    )

    # Genera il codice completo, inserisco gli import e l'inizializzazione della funzione (parte in comune con ogni script)
    full_code = """
import requests
import uuid
import json

# Configurazione dell'indirizzo IP target default
TARGET_IP = "0.0.0.0"  # Modifica questo valore con l'indirizzo IP desiderato
"""

    # Aggiungi variabili user e password se c'è una richiesta POST di tipo register
    if has_post_register:
        full_code += """
# Credenziali di default per la registrazione
USERNAME = "root"  # Modifica questo valore con l'username desiderato
PASSWORD = "root"  # Modifica questo valore con la password desiderata
"""

    full_code += """
def execute_attack():
    # Prepara l'URL base

    base_url = f'http://{TARGET_IP}'

    session = requests.Session()
"""

    # Processa ogni richiesta
    for req in requests_list:
        # Ignora le righe che iniziano con un numero (codici di risposta)
        if str(req).strip().split()[0].isdigit():
            continue

        # Estrai metodo e path
        parts = str(req).strip().split(None, 3)
        if len(parts) >= 2:
            method, path = parts[0].upper(), parts[1]
            flag = parts[2] if len(
                parts) > 2 else None  # Se c'è un terzo elemento, lo cattura, altrimenti no, in modo tale da includere FLAG_OUT_REQ

            # Verifica se è una richiesta POST register
            is_register_request = method.upper() == "POST" and "register" in path.lower()
            # Prepara il codice della richiesta
            if is_register_request:
                request_code = f"""
    # {method} {path} - Registrazione utente
    url = urljoin(base_url, '{path}')
    data = {{"username": USERNAME, "password": PASSWORD}}
    response = session.{method.lower()}(url, json=data)"""
            elif flag != None:
                request_code = f"""
    # {method} {path}
    url = urljoin(base_url, '{path}{flag}')
    response = session.{method.lower()}(url)"""
            elif method.upper() == "POST":
                request_code = f"""
    # {method} {path} 
    url = urljoin(base_url, '{path}')
    data = {{"defaultParam": - }}
    response = session.{method.lower()}(url, json=data)"""
            else:
                request_code = f"""
    # {method} {path}
    url = urljoin(base_url, '{path}')
    response = session.{method.lower()}(url)"""

            full_code += request_code + "\n"

    full_code += "\n    return 'Attack completed'\n"
    return full_code





###############################
#funzione con l'aggiunta dello script
def show_attack_path(ip, attack_steps):
    root = tk.Tk()
    root.title("Attack Path Visualization")

    # Imposta una dimensione iniziale grande
    root.geometry("1200x800")

    # Frame principale con divisione orizzontale
    paned_window = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
    paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Intestazione con IP target
    header = ttk.Label(root, text=f"Target IP: {ip}", font=("Arial", 16, "bold"))
    header.pack(pady=10, padx=10, anchor="w")

    # Frame sinistro per i path
    left_frame = ttk.Frame(paned_window, relief="groove", borderwidth=2)
    paned_window.add(left_frame, weight=1)

    # Frame destro per lo script
    right_frame = ttk.Frame(paned_window, relief="groove", borderwidth=2)
    paned_window.add(right_frame, weight=1)

    # Intestazione per la parte sinistra
    ttk.Label(left_frame, text="Attack Paths", font=("Arial", 14, "bold")).pack(pady=10)

    # Frame interno per i path con scrollbar
    paths_canvas = tk.Canvas(left_frame)
    paths_scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=paths_canvas.yview)
    paths_scrollable_frame = ttk.Frame(paths_canvas)

    # Configura il canvas e scrollbar
    paths_scrollable_frame.bind(
        "<Configure>",
        lambda e: paths_canvas.configure(scrollregion=paths_canvas.bbox("all"))
    )
    paths_canvas.create_window((0, 0), window=paths_scrollable_frame, anchor="nw")
    paths_canvas.configure(yscrollcommand=paths_scrollbar.set)

    # Pack canvas e scrollbar
    paths_scrollbar.pack(side="right", fill="y")
    paths_canvas.pack(side="left", fill="both", expand=True)

    # Intestazione per la parte destra
    ttk.Label(right_frame, text="Script Preview", font=("Arial", 14, "bold")).pack(pady=10)

    # Text widget per lo script con scrollbar
    script_text = tk.Text(right_frame, wrap="word", font=("Courier", 11))
    script_scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=script_text.yview)

    script_text.configure(yscrollcommand=script_scrollbar.set)
    script_scrollbar.pack(side="right", fill="y")
    script_text.pack(side="left", fill="both", expand=True)

    # Messaggio iniziale
    script_text.insert(tk.END, "Seleziona un path per visualizzare lo script corrispondente")

    # Funzione per mostrare lo script
    def view_script(attack_path):
        script = create_attack_script(attack_path)
        script_text.delete(1.0, tk.END)
        script_text.insert(tk.END, script)

    # Aggiunta dei path
    path_counter = 1
    for step in attack_steps:
        step_str = str(step)
        steps_filtered = [s for s in re.split(r" -> ", step_str) if not re.fullmatch(r"\d{3}", s)]

        if steps_filtered:
            # Frame per ogni path
            path_frame = ttk.Frame(paths_scrollable_frame)
            path_frame.pack(fill="x", expand=True, pady=5, padx=5)

            # Titolo e pulsante sul frame principale
            path_header_frame = ttk.Frame(path_frame)
            path_header_frame.pack(fill="x", pady=3)

            # Etichetta per il path
            path_label = ttk.Label(path_header_frame, text=f"Path {path_counter}:",
                                   font=("Arial", 12, "bold"))
            path_label.pack(side="left", anchor="w", padx=5)

            # Pulsante ben visibile
            view_button = ttk.Button(
                path_header_frame,
                text="View Script",
                command=lambda s=step: view_script(s),
                width=15  # Larghezza fissa più grande
            )
            view_button.pack(side="right", padx=10)

            # Frame separato per i dettagli
            details_frame = ttk.Frame(path_frame)
            details_frame.pack(fill="x", padx=20, pady=5)

            # Aggiungi ogni passo
            for sub_step in steps_filtered:
                step_label = ttk.Label(details_frame, text=f"• {sub_step}",
                                       font=("Arial", 11), wraplength=400)
                step_label.pack(anchor="w", pady=2)

            # Separatore
            ttk.Separator(path_frame, orient="horizontal").pack(fill="x", pady=5)

            path_counter += 1

    # Configurazione finale per il canvas
    paths_scrollable_frame.update_idletasks()

    root.mainloop()
def main():

    log_path = '../../xes_logs/captureProva.xes'
    result = analyze_xes_attack_logs(log_path)

    if result:
        print(f"IP attaccato: {result['attacked_ip']}")
        print(f"Numero di occorrenze: {result['occurrence_count']}")
        print(f"Menzioni totali IP: {result['total_ip_mentions']}")
    else:
        print("Nessun IP identificato")


    #Prova di lettura "classica"
    log = pm4py.read_xes(log_path)


    dfg, sa, ea = pm4py.discover_dfg_typed(log)
    #versione 0.44
    act_count = pm4py.get_event_attribute_values(log, "concept:name")
    dfg, sa, ea, act_count = pm4py.algo.filtering.dfg.dfg_filtering.filter_dfg_on_paths_percentage(dfg, sa, ea, act_count, 0.44)

    #versione 0.3
    #act_count = pm4py.get_event_attribute_values(log, "concept:name")
    #dfg, sa, ea, act_count = pm4py.algo.filtering.dfg.dfg_filtering.filter_dfg_on_paths_percentage(dfg, sa, ea, act_count, 0.3)

    #versione 0.1 (lineare)
    #act_count = pm4py.get_event_attribute_values(log, "concept:name")
    #dfg, sa, ea, act_count = pm4py.algo.filtering.dfg.dfg_filtering.filter_dfg_on_paths_percentage(dfg, sa, ea, act_count, 0.1)

    pm4py.view_dfg(dfg, sa, ea, format="pdf")

    print("DFG Edges:")
    for (src, dst), freq in dfg.items():
        print(f"{src} -> {dst}: {freq}")

    print("\nStart activities:", sa)
    print("End activities:", ea)



    paths = analyze_dfg_costly_paths(dfg, sa, ea)
    #proviamo lo script generator
    script=create_attack_script( paths[0])
    print(script)

    for path, cost in paths:
        print(f"Percorso: {' -> '.join(path)}")

    # Avvia la visualizzazione GUI
    show_attack_path(result['attacked_ip'], paths)

if __name__ == "__main__":
    main()




