import xml.etree.ElementTree as ET
import json
import os
import traceback


def parse_xes(file_path):
    try:
        # Verifica che il file esista
        if not os.path.exists(file_path):
            print(f"❌ Errore: Il file {file_path} non esiste!")
            return []

        print(f"📂 Analizzando il file: {file_path}")

        tree = ET.parse(file_path)
        root = tree.getroot()

        # Debug - stampa la struttura del root
        print(f"🌲 Root tag: {root.tag}")

        # Gestione automatica del namespace
        ns = {}
        if '}' in root.tag:
            ns = {'xes': root.tag.split('}')[0].strip('{')}
            print(f"🔹 Namespace rilevato: {ns['xes']}")

        # Array per memorizzare ogni richiesta POST con il suo path e parametri
        post_requests = []
        found_post = False

        # Prova a trovare gli eventi con e senza namespace
        eventi = root.findall('.//xes:event', namespaces=ns) if ns else []
        if not eventi:
            # Prova senza namespace
            eventi = root.findall('.//event')

        print(f"🔹 Eventi trovati: {len(eventi)}")

        for i, event in enumerate(eventi):
            request_type = None
            path = None
            body_content = None
            token = None
            method = None  # Aggiungiamo una variabile per il metodo HTTP
            uri = None  # Aggiungiamo una variabile per l'URI

            print(f"\n🔍 Evento #{i + 1}:")

            # Lista di tutti gli attributi trovati (per debug)
            all_attrs = {}

            # Debug - stampa tutti gli attributi dell'evento
            for string in event.findall('.//string') if not ns else event.findall('.//xes:string', namespaces=ns):
                key = string.get("key")
                value = string.get("value")
                all_attrs[key] = value
                print(f"🔹 Attributo: {key} = {value}")

                # Salva metodo HTTP
                if key and key.lower() == "method":
                    method = value.upper()
                    if method == "POST":
                        request_type = "POST"
                        found_post = True
                        print("✅ Identificata richiesta POST!")

                # Identifica richiesta POST (metodo alternativo)
                if key and key.lower() in ["type", "concept:name"] and value and "POST" in value.upper():
                    request_type = "POST"
                    found_post = True
                    print("✅ Identificata richiesta POST (da concept:name)!")
                    # Prova a estrarre il path dal concept:name se ha formato "POST /path"
                    if key.lower() == "concept:name" and " " in value:
                        parts = value.split(" ", 1)
                        if len(parts) > 1 and parts[0].upper() == "POST":
                            path = parts[1]
                            print(f"🔗 Path estratto da concept:name: {path}")

                # Estrai il path della richiesta - INCLUDE URI
                if key and key.lower() in ["path", "url", "resource", "uri"]:
                    if key.lower() == "uri":
                        uri = value
                        print(f"🔗 URI trovato: {uri}")
                    else:
                        path = value
                        print(f"🔗 Path trovato: {path}")

                if key and key.lower() in ["body", "payload", "data"]:
                    body_content = value
                    print(f"📝 Body JSON: {body_content}")

                if key and key.lower() in ["response_token", "token", "auth_token"]:
                    token = value
                    print(f"🔑 Token trovato: {token}")

            # Usa l'URI se disponibile e il path non è stato definito
            if not path and uri:
                path = uri
                print(f"🔄 Usando URI come path: {path}")

            # Debug - mostra tutti gli attributi trovati
            print(f"📑 Tutti gli attributi dell'evento: {json.dumps(all_attrs, indent=2)}")

            # Se troviamo una richiesta POST con un body valido e un path
            if request_type == "POST" and body_content:
                try:
                    # Gestisce sia json con singoli che doppi apici
                    # Prima convertiamo le virgolette singole in doppie per il parsing JSON
                    body_content = body_content.replace("'", '"')

                    # Debug - stampa il body dopo la sostituzione
                    print(f"📝 Body JSON dopo sostituzione: {body_content}")

                    body_json = json.loads(body_content)

                    # Estrai i nomi dei campi in base al tipo di body_json
                    if isinstance(body_json, dict):
                        # È un dizionario, prendi le chiavi
                        field_names = list(body_json.keys())
                        print(f"📋 Campi estratti (dict): {field_names}")
                    elif isinstance(body_json, list):
                        # È una lista, estrai i nomi dei campi degli oggetti nella lista
                        field_names = []
                        for item in body_json:
                            if isinstance(item, dict):
                                # Aggiungi le chiavi dal dizionario
                                for key in item.keys():
                                    if key not in field_names:
                                        field_names.append(key)
                            elif isinstance(item, str):
                                # Se è una stringa, aggiungila come campo "value"
                                if "value" not in field_names:
                                    field_names.append("value")
                        print(f"📋 Campi estratti (list): {field_names}")
                    else:
                        field_names = ["data"]  # Fallback generico
                        print(f"📋 Tipo non supportato: {type(body_json)}, usando campo generico")

                    # Verifica se il path deve iniziare con / e normalizzalo
                    if path and not path.startswith('/'):
                        path = '/' + path
                        print(f"🔧 Path normalizzato: {path}")

                    path_value = path if path else "/api/endpoint"

                    post_data = {
                        "path": path_value,
                        "fields": field_names,
                        "body_type": "dict" if isinstance(body_json, dict) else "list"
                    }

                    # Controlla se è una richiesta di registrazione (per il token)
                    is_register = False
                    if isinstance(body_json, dict) and "action" in body_json and "register" in body_json.get("action",
                                                                                                             "").lower():
                        is_register = True
                    elif path and "register" in path.lower():
                        is_register = True

                    if is_register:
                        post_data["is_register"] = True

                    if token:
                        post_data["token"] = token

                    post_requests.append(post_data)
                    print(f"✅ Dati POST aggiunti: {post_data}")

                except json.JSONDecodeError as e:
                    print(f"❌ Errore nel parsing JSON: {e}")
                    # Se il body è in un formato non valido, tenta di creare un campo generico
                    path_value = path if path else "/api/endpoint"
                    post_data = {
                        "path": path_value,
                        "fields": ["data"],  # Campo generico
                        "body_type": "raw",
                        "parse_error": str(e)
                    }
                    post_requests.append(post_data)
                    print(f"⚠️ Aggiunto campo generico per: {path}")
                except Exception as e:
                    print(f"❌ Errore durante l'elaborazione del body: {e}")
                    traceback.print_exc()

        # Se non abbiamo trovato nessuna POST, avvisiamo
        if not found_post:
            print("⚠ Nessuna richiesta POST trovata!")
        else:
            print(f"✅ Trovate {len(post_requests)} richieste POST")

        return post_requests

    except ET.ParseError as e:
        print(f"❌ Errore nel parsing del file XES! Controlla la sintassi XML. Errore: {e}")
        return []
    except Exception as e:
        print(f"❌ Errore generico: {e}")
        traceback.print_exc()
        return []


def create_attack_script_finale(target_ip, attack_path, post_data_list):
    if not post_data_list:
        print("⚠ Errore: Nessun dato POST trovato!")
        return ""

    print(f"📊 Creazione script con {len(post_data_list)} richieste POST e {len(attack_path)} paths di attacco")

    # Crea un dizionario per associare i path alle informazioni POST
    post_data_by_path = {}
    # Aggiungi un post_data generico che verrà usato come fallback
    default_post_data = {
        "fields": ["data"],
        "body_type": "dict"
    }

    for post_data in post_data_list:
        if "path" in post_data:
            # Estrai solo il percorso dalla URL (rimuovi parametri query se presenti)
            path = post_data["path"].split("?")[0]
            # Normalizza il path
            if path.startswith('/'):
                normalized_path = path
            else:
                normalized_path = '/' + path

            # Aggiungi sia il path completo che le sue parti per un matching più flessibile
            post_data_by_path[normalized_path] = post_data

            # Ottieni l'ultimo segmento del path per un matching più flessibile
            segments = normalized_path.strip('/').split('/')
            if segments:
                last_segment = '/' + segments[-1]
                if last_segment != normalized_path:
                    print(f"🔍 Aggiungendo anche matching per il segmento finale: {last_segment}")
                    post_data_by_path[last_segment] = post_data

            # Debug
            print(f"🔍 Path mappato: {normalized_path} -> {post_data['fields']}")

    # Corretto il template string usando {{}} per i valori letterali e {} per le sostituzioni
    full_code = """
import requests
import json
from urllib.parse import urljoin

TARGET_IP = "0.0.0.0"
TOKEN = None

def execute_attack():
    base_url = f'http://{{TARGET_IP}}'
    session = requests.Session()
    results = []
""".format(target_ip)

    # Itera attraverso il percorso di attacco
    for req in attack_path:
        req_str = str(req).strip()
        parts = req_str.split(None, 3)

        if len(parts) < 2:
            continue

        method, path = parts[0].upper(), parts[1]

        # Normalizza il path dell'attacco
        if not path.startswith('/'):
            path = '/' + path

        # Debug
        print(f"🔍 Analisi richiesta: {method} {path}")

        # Pulisci il path (rimuovi parametri query o frammenti se presenti)
        clean_path = path.split("?")[0].split("#")[0]

        # Ottieni anche l'ultimo segmento del path per un matching più flessibile
        path_segments = clean_path.strip('/').split('/')
        last_segment = '/' + path_segments[-1] if path_segments else clean_path

        # Determina se questa è una richiesta POST
        if method == "POST":
            # Cerca il path corrispondente nei dati POST
            matching_path = None

            # Metodo 1: Match esatto
            if clean_path in post_data_by_path:
                matching_path = clean_path
                print(f"✅ Match esatto trovato: {clean_path}")

            # Metodo 2: Match parziale
            if not matching_path:
                for p in post_data_by_path.keys():
                    # Normalizza per il confronto: match su path completi o segmenti finali
                    if (clean_path.endswith(p) or p.endswith(clean_path) or
                            last_segment == p or p == last_segment):
                        matching_path = p
                        print(f"✅ Match parziale trovato: {clean_path} corrisponde a {p}")
                        break

            # Se ancora non troviamo un match, proviamo a cercare un path che contiene keyword simili
            if not matching_path:
                keywords = [seg.lower() for seg in path_segments if len(seg) > 3]
                for p in post_data_by_path.keys():
                    for keyword in keywords:
                        if keyword in p.lower():
                            matching_path = p
                            print(f"✅ Match per keyword trovato: keyword '{keyword}' trovata in {p}")
                            break
                    if matching_path:
                        break

            # Se non troviamo un match esatto, usiamo il primo post_data disponibile
            if not matching_path and post_data_by_path:
                matching_path = list(post_data_by_path.keys())[0]
                print(f"⚠️ Nessun match trovato per {clean_path}, usando il primo disponibile: {matching_path}")

            if matching_path:
                post_data = post_data_by_path[matching_path]
                fields = post_data.get("fields", [])
                body_type = post_data.get("body_type", "dict")

                # Genera dati appropriati in base al tipo di body
                if body_type == "dict":
                    # Genera un dizionario di dati fittizi per i campi
                    json_data = {field: f"value_{field}" for field in fields}
                elif body_type == "list":
                    # Genera una lista di elementi in base ai campi trovati
                    json_data = []
                    if fields:
                        # Crea un dizionario se abbiamo campi strutturati
                        item = {field: f"value_{field}" for field in fields}
                        json_data.append(item)
                    else:
                        # Fallback a un valore semplice se non abbiamo campi
                        json_data.append("data_value")
                else:
                    # Fallback generico
                    json_data = {"data": "generic_value"}

                # Determina se è una richiesta di registrazione
                is_register_request = post_data.get("is_register", False) or "register" in clean_path.lower()

                if method == "POST":
                    request_code = f"""
    # {method} {path}
    print(f"Sending {method} request to {{urljoin(base_url, '{path}')}}")
    data = {json.dumps(json_data, indent=4)}
    response = session.{method.lower()}(urljoin(base_url, '{path}'), json=data)
    print(f"Response status: {{response.status_code}}")
    results.append(f"{method} {path}: {{response.status_code}}")
                    """

            else:
                # Non abbiamo dati sui parametri per questa richiesta POST - usiamo un payload generico
                print(f"⚠ Nessun dato POST trovato per: {clean_path}, usando dati generici")
                # Crea un payload generico
                generic_data = {"data": "generic_value"}

                request_code = f"""
    # {method} {path} (Using generic data)
    print(f"Sending {method} request to {{urljoin(base_url, '{path}')}}")
    data = {json.dumps(generic_data, indent=4)}
    response = session.{method.lower()}(urljoin(base_url, '{path}'), headers=headers, json=data)
    print(f"Response status: {{response.status_code}}")
    results.append(f"{method} {path}: {{response.status_code}}")
"""
        else:
            # Per richieste non-POST come GET, DELETE, ecc.
            request_code = f"""
    # {method} {path}
    print(f"Sending {method} request to {{urljoin(base_url, '{path}')}}")
    response = session.{method.lower()}(urljoin(base_url, '{path}'), headers=headers)
    print(f"Response status: {{response.status_code}}")
    results.append(f"{method} {path}: {{response.status_code}}")
"""

        full_code += request_code

    full_code += """
    return results

if __name__ == "__main__":
    print(f"Iniziando attacco contro {TARGET_IP}")
    results = execute_attack()
    print("\\nRisultati:")
    for result in results:
        print(f"- {result}")
"""
    return full_code


def extract_attack_path_from_tuple(input_data):
    """
    Estrae il percorso di attacco da una tupla contenente una lista di log di richieste HTTP e un valore numerico.

    Args:
        input_data (tuple): Tupla contenente:
            - Una lista di stringhe che rappresentano log di richieste HTTP
              es. ['POST /register', '200 POST /register', 'POST /new', ...]
            - Un valore numerico (che sarà ignorato)

    Returns:
        list: Lista contenente solo le richieste (senza codici di stato) che formano il percorso di attacco
    """
    # Estrai la lista di log dalla tupla (il primo elemento)
    log_entries = input_data[0]

    # Il secondo elemento (numero) viene ignorato

    attack_path = []

    for entry in log_entries:
        # Ignora le voci che iniziano con un codice di stato (come '200 POST /register')
        if not entry[0].isdigit():
            # Se l'entry non inizia con un codice di stato, è una richiesta originale
            attack_path.append(entry)

    return attack_path

# Esempio di utilizzo con più controlli
if __name__ == "__main__":
    file_xes = '../xes_logs/captureProva.xes'
    # Controlla che il file esista
    if not os.path.exists(file_xes):
        print(f"⚠ Il file {file_xes} non esiste. Usa il percorso assoluto o controlla il path relativo.")
        # Usa un percorso alternativo per test
        file_xes = 'captureProva.xes'  # Prova nel path corrente

    post_data_list = parse_xes(file_xes)

    print("\n📊 Output di parse_xes():")
    print(json.dumps(post_data_list, indent=2))  # Output formattato

    # Esempio di attack_path (normalmente derivato da un'altra funzione)
    attack_path = [
        "POST /register",
        "POST /new",
        "POST /form/<uuid>FLAG_OUT_REQ"
    ]

    script = create_attack_script_finale("example.com", attack_path, post_data_list)
    print("\n🚀 Script generato:")
    print(script)

