import dns.resolver
import requests
from difflib import SequenceMatcher
import re

API_KEY_VT = "4976a6a0f45ce24b58c3a5f442f8c5750d9770fb106baca42a6e4c63550b337c"

def cargar_lista(nombre_archivo):
    with open(nombre_archivo, "r") as f:
        return [line.strip().lower() for line in f.readlines()]

dominios_legitimos = cargar_lista("verifier/whitelist.txt")

def validar_formato(correo):
    patron = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(patron, correo)

def obtener_dominio(correo):     
    try:
        return correo.split("@")[1].lower()
    except IndexError:
        return None

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

def verificar_registro_mx(dominio):
    try:
        registros_mx = dns.resolver.resolve(dominio, 'MX')
        return bool(registros_mx)
    except:
        return False

def verificar_virustotal(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {
        "x-apikey": API_KEY_VT
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return malicious > 0
        else:
            return False
    except:
        return False

def detectar_fraude(correo):
    if not validar_formato(correo):
        return "❌ Correo inválido (formato incorrecto)."

    dominio = obtener_dominio(correo)

    if verificar_virustotal(dominio):
        return f"❌ El dominio '{dominio}' está reportado como malicioso en VirusTotal."

    tiene_mx = verificar_registro_mx(dominio)
    if not tiene_mx:
        return f"⚠️ El dominio '{dominio}' no tiene registros MX válidos. Sospechoso."

    if dominio not in dominios_legitimos:
        return f"⚠️ El dominio '{dominio}' no está en la lista blanca. Cuidado."

    for legitimo in dominios_legitimos:
        if similar(dominio, legitimo) > 0.8 and dominio != legitimo:
            return f"⚠️ El dominio '{dominio}' se parece a '{legitimo}'. Posible suplantación."

    return f"✅ El correo '{correo}' parece legítimo."
