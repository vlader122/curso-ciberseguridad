import os
import requests

API_KEY = ""

def verificar_ip(ip):
    response = os.system(f"ping {ip}")
    if response == 0:
        print("La ip esta activa")
    else:
        print("La ip esta inactiva")

def analizar_virus_total(ip):
    url = f"https://www.virustotal.com/api/v3/urls?url={ip}"
    headers = {"x-apikey": API_KEY}
    try:
        r = requests.post(url, headers=headers)
        data = r.json()
        url_analisis = data['data']['links']['self']
        r2 = requests.get(url_analisis, headers=headers)
        data_result = r2.json()
        print(f"El sitio tiene esta informacion de analisis {data_result['data']['attributes']['stats']}")
    except Exception as e:
        print(f"Error al conectar {e}")

target = "xuper-tv.com"
verificar_ip(target)
analizar_virus_total(target)