"""
Modulo principale dell'applicazione che coordina le diverse funzionalità.
"""
import json

import pm4py
import os

from dfg_analyzer import analyze_dfg_paths
from src.analyze_costly_path import trova_percorso_piu_costoso
from xes_analyzer import analyze_xes_attack_logs
from attack_script_generator import create_attack_script
from gui import show_attack_path
from xes_post_analyzer import parse_xes, create_attack_script_finale, extract_attack_path_from_tuple


def main():
    """Funzione principale che coordina l'esecuzione del programma."""

    # Percorso del file di log
    log_path = '../xes_logs/ccforms2_attack_and_checkers_complete.xes'

    # Analisi del file XES per trovare l'indirizzo IP attaccato
    result = analyze_xes_attack_logs(log_path)

    if result:
        print(f"IP attaccato: {result['attacked_ip']}")
        print(f"Numero di occorrenze: {result['occurrence_count']}")
        print(f"Menzioni totali IP: {result['total_ip_mentions']}")
    else:
        print("Nessun IP identificato")

    # Lettura del log XES con PM4Py
    log = pm4py.read_xes(log_path)

    # Estrazione del DFG dal log
    dfg, sa, ea = pm4py.discover_dfg_typed(log)

    # Filtro del DFG (versione 0.44)
    act_count = pm4py.get_event_attribute_values(log, "concept:name")
    dfg, sa, ea, act_count = pm4py.algo.filtering.dfg.dfg_filtering.filter_dfg_on_paths_percentage(
        dfg, sa, ea, act_count, 0.44)

    # Visualizzazione del DFG
    pm4py.view_dfg(dfg, sa, ea, format="pdf")

    # Stampa delle informazioni sul DFG
    print("DFG Edges:")
    for (src, dst), freq in dfg.items():
        print(f"{src} -> {dst}: {freq}")

    print("\nStart activities:", sa)
    print("End activities:", ea)


    # Commentare la linea di codice del selettore che non si desidera utilizzare
    # Analisi dei percorsi nel DFG, ordinati dal più al meno costoso
    #paths = analyze_dfg_paths(dfg, sa, ea)
    # Analisi solo del percorso più frequente
    paths=trova_percorso_piu_costoso(dfg, sa, ea)

    print(paths)
    post_data_list = parse_xes(log_path)
    # Generazione di uno script di esempio basato sul primo percorso
    if result and paths:
        script = create_attack_script(result['attacked_ip'], paths[0])
        print(script)
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

    attack_path=extract_attack_path_from_tuple(paths[0])
    script = create_attack_script_finale("example.com", attack_path, post_data_list)
    print(attack_path)
    print("\n🚀 Script generato:")
    print(script)

    #Parsing dei path da mandare alla gui
    paths_new=[]
    for path in paths:
        attack_path = extract_attack_path_from_tuple(path)
        paths_new.append(attack_path)



    # Avvio dell'interfaccia grafica se abbiamo trovato sia l'IP che i percorsi ora leggibili
    if result and paths:
        show_attack_path(result['attacked_ip'], paths_new,post_data_list)
    else:
        print("Non è possibile avviare la GUI: IP o percorsi non trovati")


if __name__ == "__main__":
    main()