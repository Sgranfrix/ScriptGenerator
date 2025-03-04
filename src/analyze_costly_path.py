
def trova_percorso_piu_costoso(percorsi):
    """
    Trova il percorso con il costo più alto.

    Args:
        percorsi: Una lista di tuple (percorso, costo) dove percorso è una lista di stringhe
                 e costo è un numero intero

    Returns:
        La tupla (percorso, costo) con il costo più alto
    """
    if not percorsi:
        return None

    # Inizializziamo con il primo percorso
    percorso_max = percorsi[0]
    costo_max = percorsi[0][1]

    # Iteriamo attraverso tutti i percorsi
    for percorso, costo in percorsi:
        if costo > costo_max:
            percorso_max = (percorso, costo)
            costo_max = costo

    return percorso_max
