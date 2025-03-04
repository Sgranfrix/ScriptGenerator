"""
Modulo per l'analisi dei file XES e l'identificazione di indirizzi IP attaccati.
"""

import xml.etree.ElementTree as ET
from collections import Counter

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