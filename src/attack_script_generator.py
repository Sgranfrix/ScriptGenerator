"""
Modulo per la generazione di script di attacco basati su percorsi identificati.
"""
import json
from urllib.parse import urljoin

from pycparser.ply.lex import TOKEN


def create_attack_script(target_ip, attack_path):
    """
    Crea uno script di attacco basato su un path di attacco specificato

    Args:
        target_ip (str): Indirizzo IP della macchina target
        attack_path (tuple): Tupla contenente lista di richieste e codice

    Returns:
        str: Codice Python generato per eseguire l'attacco
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

# Configurazione dell'indirizzo IP target
TARGET_IP = "{}"  # Modifica questo valore con l'indirizzo IP desiderato
""".format(target_ip)

    # Aggiungi variabili user e password se c'è una richiesta POST register
    if has_post_register:
        full_code += """
# Credenziali per la registrazione
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
            else:
                request_code = f"""
    # {method} {path}
    url = urljoin(base_url, '{path}')
    response = session.{method.lower()}(url)"""

            full_code += request_code + "\n"

    full_code += "\n    return 'Attack completed'\n"
    return full_code

######################


