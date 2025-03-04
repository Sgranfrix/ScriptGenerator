"""
Modulo per funzioni di utilità generiche usate dagli altri moduli.
"""

import re


def filter_status_codes(steps):
    """
    Filtra i codici di stato HTTP (es. "200", "404") da una stringa di passaggi.

    Args:
        steps (str): Stringa contenente i passaggi separati da " -> "

    Returns:
        list: Lista di passaggi filtrati
    """
    return [s for s in re.split(r" -> ", steps) if not re.fullmatch(r"\d{3}", s)]