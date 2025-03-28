import tkinter as tk
from tkinter import ttk
import re

import pm4py
from pm4py.visualization.dfg import visualizer as dfg_vis
from pm4py.objects.log.obj import EventLog, Trace, Event
from pm4py.objects.conversion.log import converter as log_converter

# Modifica dell'import per usare la nuova funzione
from xes_post_analyzer import create_attack_script_finale


def show_attack_path(ip, attack_steps, post_data_list):
    """
    Visualizza i percorsi di attacco e permette di generare script.

    Args:
        ip (str): Indirizzo IP della macchina target
        attack_steps (list): Lista di percorsi di attacco
        post_data_list (list): Lista di dati POST per le richieste
    """
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

    # Funzione per mostrare lo script - modificata per usare la nuova funzione
    def view_script(attack_path):
        # Utilizza la nuova funzione che richiede un parametro aggiuntivo
        script = create_attack_script_finale(ip, attack_path, post_data_list)
        script_text.delete(1.0, tk.END)
        script_text.insert(tk.END, script)
        """
            Genera un Directly-Follows Graph (DFG) utilizzando pm4py a partire da una lista di eventi.

            :param attack_path: Lista ordinata di eventi rappresentanti un percorso di attacco.
            """
        if(len(attack_path)>1):
            # Creazione delle coppie direttamente collegate
            dfg = {}

            # Dizionari separati per contare le occorrenze delle attività iniziali e finali
            start_activities = {}
            end_activities = {}

            # Aggiungi start ed end activities come nodi speciali
            start_activity = attack_path[0]
            end_activity = attack_path[-1]

            # Aggiungi le transizioni originali
            for i in range(len(attack_path) - 1):
                pair = (attack_path[i], attack_path[i + 1])
                dfg[pair] = dfg.get(pair, 0) + 1  # Conta le occorrenze delle transizioni


            # Definisci le attività iniziali e finali per la visualizzazione
            start_activities["●"] = 1
            end_activities["■"] = 1


            # Conta la prima attività
            start_activities[start_activity] = start_activities.get(start_activity, 0) + 1

            # Conta l'ultima attività
            end_activities[end_activity] = end_activities.get(end_activity, 0) + 1
            # Parametri di visualizzazione
            parameters = {
                dfg_vis.Variants.FREQUENCY.value.Parameters.FORMAT: "png",
                dfg_vis.Variants.FREQUENCY.value.Parameters.START_ACTIVITIES: start_activities,
                dfg_vis.Variants.FREQUENCY.value.Parameters.END_ACTIVITIES: end_activities
            }

            # Visualizzazione del DFG
            gviz = dfg_vis.apply(dfg, parameters=parameters)
            dfg_vis.view(gviz)
        else:
            """Crea una finestrella di errore usando Tkinter."""
            root = tk.Tk()
            root.title("Errore")
            label = ttk.Label(root, text="Impossibile creare un DFG con un solo elemento", foreground="red")
            label.pack(padx=20, pady=10)
            button = ttk.Button(root, text="OK", command=root.destroy)
            button.pack(pady=10)
            root.mainloop()

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
            if path_counter==1:
                path_label = ttk.Label(path_header_frame, text=f"Most Frequent Path:",
                                       font=("Arial", 12, "bold"))
                path_label.pack(side="left", anchor="w", padx=5)
            else:
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




