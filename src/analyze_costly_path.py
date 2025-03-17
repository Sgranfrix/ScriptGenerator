import networkx as nx


def trova_percorso_piu_costoso(dfg,start_activities,end_activities):
    """
    Trova il percorso con il costo più alto.

    Args:
        dfg (dict): Dictionary che rappresenta il DFG con pesi
        start_activities (dict/set): Attività iniziali
        end_activities (dict/set): Attività finali

    Returns:
        La tupla (percorso, costo) con il costo più alto
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
    return costly_paths[:1]
