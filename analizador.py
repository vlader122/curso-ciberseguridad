import time

from scapy.all import sniff, TCP, IP
from collections import defaultdict


intentos = defaultdict(list)
LIMITE_ALERTA = 5
VENTANA_TIEMPO = 10

def procesar_paquete(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == 'S':
        src_ip = pkt[IP].src
        tiempo_actual = time.time()

        intentos[src_ip].append(tiempo_actual)

        intentos[src_ip] = [t for t in intentos[src_ip] if tiempo_actual - t < VENTANA_TIEMPO]

        if len(intentos[src_ip]) >= LIMITE_ALERTA:
            print(f"[ALERTA] Posible SYN scan desde {src_ip}: {len(intentos[src_ip])} intentos en {VENTANA_TIEMPO}s")

sniff(filter="tcp", prn=procesar_paquete, store=0)