import os
import socket
import hashlib
import psutil
import requests

API_KEY = os.environ.get("VT_API_KEY", "64d2bd0afe56a5595c3b12652da555272bc67da326e5d7f2441db49e592591b4")

WHITELIST = {
    "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "explorer.exe", "taskhostw.exe", "spoolsv.exe", "csrss.exe", "smss.exe",
    "audiodg.exe", "dwm.exe", "fontdrvhost.exe", "lsm.exe", "msmpeng.exe",
    "ntoskrnl.exe", "registry", "system", "system idle process",
    # Comunes de desarrollo y red
    "python.exe", "pythonw.exe", "node.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "brave.exe", "discord.exe", "slack.exe", "teams.exe",
    "onedrive.exe", "dropbox.exe", "ssh.exe", "sshd.exe", "httpd.exe",
    "nginx.exe", "mongod.exe", "postgres.exe", "mysqld.exe",
}

MAX_CONSULTAS_VT = 3


def sha256_ejecutable(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def consultar_virustotal(hash_sha256):
    url = f"https://www.virustotal.com/api/v3/files/{hash_sha256}"
    headers = {"x-apikey": API_KEY}
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code == 404:
        return "no encontrado en VT"
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    maliciosos = stats.get("malicious", 0)
    sospechosos = stats.get("suspicious", 0)
    total = sum(stats.values())
    if maliciosos > 0:
        return f"MALICIOSO ({maliciosos}/{total} motores)"
    if sospechosos > 0:
        return f"SOSPECHOSO ({sospechosos}/{total} motores)"
    return f"limpio (0/{total} motores)"


def listar_puertos():
    print(f"{'IP':<20} {'PUERTO':<8} {'SERVICIO':<15} {'PROCESO':<25} {'VT'}")
    print("-" * 90)

    pendientes_vt = []
    filas = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.status != 'LISTEN':
            continue

        ip = conn.laddr.ip
        puerto = conn.laddr.port
        pid = conn.pid

        try:
            servicio = socket.getservbyport(puerto)
        except OSError:
            servicio = "desconocido"

        proceso = "Desconocido"
        ruta_exe = None
        try:
            if pid:
                proc = psutil.Process(pid)
                proceso = proc.name()
                ruta_exe = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        necesita_vt = proceso.lower() not in WHITELIST
        filas.append((ip, puerto, servicio, proceso, ruta_exe, necesita_vt))
        # Deduplicar por nombre de proceso: solo agregar si no está ya en la lista
        if necesita_vt and ruta_exe and proceso.lower() not in {p for _, p in pendientes_vt}:
            pendientes_vt.append((ruta_exe, proceso.lower()))

    # Analizar con VT solo los primeros MAX_CONSULTAS_VT únicos por proceso
    cache_vt = {}  # clave: nombre de proceso
    consultas = 0
    if not API_KEY:
        print("[AVISO] VT_API_KEY no configurada — omitiendo consultas a VirusTotal\n")
    else:
        for ruta, nombre in pendientes_vt[:MAX_CONSULTAS_VT]:
            try:
                sha = sha256_ejecutable(ruta)
                cache_vt[nombre] = consultar_virustotal(sha)
                consultas += 1
            except Exception as e:
                cache_vt[nombre] = f"error: {e}"

    for ip, puerto, servicio, proceso, ruta_exe, necesita_vt in filas:
        nombre = proceso.lower()
        if necesita_vt and nombre in cache_vt:
            vt = cache_vt[nombre]
        elif necesita_vt and not ruta_exe:
            vt = "sin ruta (acceso denegado)"
        elif necesita_vt:
            vt = "limite VT alcanzado" if consultas >= MAX_CONSULTAS_VT else "-"
        else:
            vt = "whitelist"

        print(f"{ip:<20} {puerto:<8} {servicio:<15} {proceso:<25} {vt}")

    if consultas:
        print(f"\n[INFO] {consultas} consulta(s) realizadas a VirusTotal")


listar_puertos()
