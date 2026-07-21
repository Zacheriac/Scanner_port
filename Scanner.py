#!/usr/bin/env python3
"""
Scanner de puertos TCP - Proyecto educativo de ciberseguridad
================================================================
Autor: [Tu nombre]
 
USO ÉTICO ÚNICAMENTE:
Este script debe usarse SOLO en:
  - Máquinas propias / homelab (localhost, contenedores Docker propios)
  - Máquinas de práctica autorizadas (TryHackMe, HackTheBox, DVWA, etc.)
  - Sistemas donde tengas autorización explícita por escrito
 
Escanear sistemas sin autorización es ilegal en la mayoría de
jurisdicciones (en Perú: Ley de Delitos Informáticos, Ley N° 30096).
 
Funcionalidad:
  - Escaneo de puertos TCP mediante sockets (connect scan)
  - Detección de servicio común por número de puerto
  - Banner grabbing + extracción de versión vía regex
  - Clasificación de riesgo por puerto/servicio
  - Mapeo a técnicas MITRE ATT&CK
  - Estimación de SO por TTL (reconocimiento pasivo)
  - Escaneo concurrente con ThreadPoolExecutor
  - Exportación de resultados a JSON y CSV
  - Logging automático a archivo con timestamp
  - Output con colores/tabla vía rich
  - Modo rápido (--top-ports) para escanear solo los puertos más comunes
"""
 
import socket
import argparse
import sys
import time
import re
import json
import csv
import subprocess
import platform
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
 
console = Console()
 
# --------------------------------------------------------------------------
# Bases de datos internas: servicios, riesgo y técnicas MITRE ATT&CK
# --------------------------------------------------------------------------
 
SERVICIOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5672: "RabbitMQ/AMQP", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}
 
# Top 20 puertos más comunes, para el modo rápido (--top-ports)
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
             443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
 
# Clasificación de riesgo por puerto: (nivel, motivo)
RIESGO_PUERTOS = {
    21:   ("MEDIO", "FTP sin cifrado; credenciales viajan en texto plano"),
    23:   ("ALTO",  "Telnet no cifra tráfico; reemplazado por SSH hace décadas"),
    135:  ("MEDIO", "MSRPC; usado en varios exploits de movimiento lateral en Windows"),
    139:  ("MEDIO", "NetBIOS; expone recursos compartidos, vector de reconocimiento"),
    445:  ("ALTO",  "SMB; históricamente explotado por EternalBlue/WannaCry (MS17-010)"),
    1433: ("MEDIO", "MSSQL expuesto; objetivo común de fuerza bruta si no está restringido"),
    3306: ("MEDIO", "MySQL expuesto; debería limitarse solo a red interna"),
    3389: ("ALTO",  "RDP; objetivo frecuente de fuerza bruta y ransomware (BlueKeep)"),
    5432: ("MEDIO", "PostgreSQL expuesto; debería limitarse solo a red interna"),
    5900: ("ALTO",  "VNC; con frecuencia mal configurado sin contraseña o con cifrado débil"),
    6379: ("ALTO",  "Redis; famoso por instancias sin autenticación expuestas a internet"),
    27017: ("ALTO", "MongoDB; múltiples incidentes históricos de bases expuestas sin auth"),
}
RIESGO_DEFAULT = ("BAJO", "Puerto sin riesgo documentado específico en esta base local")
 
# Mapeo a técnicas MITRE ATT&CK relevantes para reconocimiento de servicios
MITRE_TECNICAS = {
    "default": ("T1046", "Network Service Discovery",
                "https://attack.mitre.org/techniques/T1046/"),
    445: ("T1021.002", "Remote Services: SMB/Windows Admin Shares",
          "https://attack.mitre.org/techniques/T1021/002/"),
    3389: ("T1021.001", "Remote Services: Remote Desktop Protocol",
           "https://attack.mitre.org/techniques/T1021/001/"),
    22: ("T1021.004", "Remote Services: SSH",
         "https://attack.mitre.org/techniques/T1021/004/"),
}
 
# Patrones regex para extraer versión de banners comunes
PATRONES_VERSION = [
    re.compile(r"SSH-[\d.]+-(OpenSSH[_\s][\d.p]+)", re.IGNORECASE),
    re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE),          # HTTP
    re.compile(r"(nginx/[\d.]+)", re.IGNORECASE),
    re.compile(r"(Apache/[\d.]+)", re.IGNORECASE),
    re.compile(r"(Microsoft-IIS/[\d.]+)", re.IGNORECASE),
    re.compile(r"^220[- ]([^\r\n]+)"),                            # FTP/SMTP banners
]
 
 
def extraer_version(banner: str) -> str:
    """Intenta extraer la versión del servicio a partir del banner crudo."""
    if not banner:
        return ""
    for patron in PATRONES_VERSION:
        match = patron.search(banner)
        if match:
            return match.group(1).strip()
    return ""
 
 
def clasificar_riesgo(puerto: int) -> tuple:
    """Retorna (nivel, motivo) de riesgo para un puerto dado."""
    return RIESGO_PUERTOS.get(puerto, RIESGO_DEFAULT)
 
 
def obtener_mitre(puerto: int) -> tuple:
    """Retorna la técnica MITRE ATT&CK asociada al puerto (o la genérica de reconocimiento)."""
    return MITRE_TECNICAS.get(puerto, MITRE_TECNICAS["default"])
 
 
# --------------------------------------------------------------------------
# Escaneo
# --------------------------------------------------------------------------
 
def escanear_puerto(host: str, puerto: int, timeout: float = 1.0) -> dict | None:
    """Intenta conectar a un puerto TCP específico y recolecta metadata si está abierto."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    resultado = None
 
    try:
        codigo = sock.connect_ex((host, puerto))
        if codigo == 0:
            servicio = SERVICIOS_COMUNES.get(puerto, "Desconocido")
            banner = obtener_banner(sock, puerto)
            version = extraer_version(banner)
            nivel_riesgo, motivo_riesgo = clasificar_riesgo(puerto)
            tecnica_id, tecnica_nombre, tecnica_url = obtener_mitre(puerto)
 
            resultado = {
                "puerto": puerto,
                "estado": "abierto",
                "servicio": servicio,
                "banner": banner,
                "version": version,
                "riesgo_nivel": nivel_riesgo,
                "riesgo_motivo": motivo_riesgo,
                "mitre_id": tecnica_id,
                "mitre_nombre": tecnica_nombre,
                "mitre_url": tecnica_url,
            }
    except socket.error:
        pass
    finally:
        sock.close()
 
    return resultado
 
 
def obtener_banner(sock: socket.socket, puerto: int) -> str:
    """Intenta capturar el banner que el servicio envía al conectar."""
    try:
        sock.settimeout(0.8)
        if puerto in (80, 8080, 443, 8443):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: scan\r\nConnection: close\r\n\r\n")
        banner = sock.recv(300).decode(errors="ignore").strip()
        return banner.replace("\r", " ").split("\n")[0][:150] if banner else ""
    except (socket.timeout, socket.error, OSError):
        return ""
 
 
def estimar_so_por_ttl(host: str) -> str:
    """
    Estima el sistema operativo remoto según el TTL de respuesta a un ping.
    Windows suele usar TTL=128, Linux/Unix TTL=64, dispositivos de red TTL=255.
    No es 100% confiable (el TTL puede alterarse), pero es una señal común
    de reconocimiento pasivo.
    """
    try:
        sistema = platform.system().lower()
        if sistema == "windows":
            comando = ["ping", "-n", "1", "-w", "1000", host]
        else:
            comando = ["ping", "-c", "1", "-W", "1", host]
 
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=3)
        salida = resultado.stdout
 
        match = re.search(r"ttl[=\s]*(\d+)", salida, re.IGNORECASE)
        if not match:
            return "No determinado (sin respuesta ICMP)"
 
        ttl = int(match.group(1))
        if ttl <= 64:
            return f"Probable Linux/Unix (TTL={ttl})"
        elif ttl <= 128:
            return f"Probable Windows (TTL={ttl})"
        else:
            return f"Probable dispositivo de red/otro (TTL={ttl})"
    except Exception:
        return "No determinado (error al hacer ping)"
 
 
def resolver_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        console.print(f"[bold red][ERROR][/bold red] No se pudo resolver el host: {host}")
        sys.exit(1)
 
 
def parsear_rango_puertos(rango: str) -> list[int]:
    puertos = []
    for parte in rango.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fin = parte.split("-")
            puertos.extend(range(int(inicio), int(fin) + 1))
        else:
            puertos.append(int(parte))
    return sorted(set(puertos))
 
 
def escanear(host: str, puertos: list[int], hilos: int = 100, timeout: float = 1.0,
             detectar_so: bool = False) -> dict:
    ip = resolver_host(host)
 
    console.print()
    console.rule(f"[bold cyan]Escaneando {host} ({ip})[/bold cyan]")
    console.print(f"  Puertos a revisar: {len(puertos)}  |  Hilos: {hilos}  |  Timeout: {timeout}s")
    console.print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
 
    so_estimado = ""
    if detectar_so:
        console.print("  [dim]Estimando sistema operativo por TTL (ping)...[/dim]")
        so_estimado = estimar_so_por_ttl(ip)
        console.print(f"  Sistema operativo estimado: [yellow]{so_estimado}[/yellow]\n")
 
    abiertos = []
    inicio = time.time()
 
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} puertos"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        tarea = progress.add_task("Escaneando...", total=len(puertos))
 
        with ThreadPoolExecutor(max_workers=hilos) as executor:
            futuros = {executor.submit(escanear_puerto, ip, p, timeout): p for p in puertos}
            for futuro in as_completed(futuros):
                resultado = futuro.result()
                if resultado:
                    abiertos.append(resultado)
                progress.advance(tarea)
 
    duracion = time.time() - inicio
    abiertos.sort(key=lambda x: x["puerto"])
 
    mostrar_tabla_resultados(abiertos)
 
    console.print(
        f"\n[bold green]Escaneo completado[/bold green] en {duracion:.2f}s | "
        f"{len(abiertos)} puerto(s) abierto(s)\n"
    )
 
    return {
        "host": host,
        "ip": ip,
        "fecha": datetime.now().isoformat(),
        "duracion_segundos": round(duracion, 2),
        "so_estimado": so_estimado,
        "puertos_escaneados": len(puertos),
        "puertos_abiertos": abiertos,
    }
 
 
def mostrar_tabla_resultados(abiertos: list[dict]):
    """Muestra los resultados en una tabla usando rich, con colores según nivel de riesgo."""
    if not abiertos:
        console.print("\n  [dim]No se encontraron puertos abiertos en el rango especificado.[/dim]")
        return
 
    colores_riesgo = {"ALTO": "bold red", "MEDIO": "yellow", "BAJO": "green", "INFO": "cyan"}
 
    tabla = Table(title="\nPuertos abiertos encontrados", show_lines=False)
    tabla.add_column("Puerto", justify="right", style="bold")
    tabla.add_column("Servicio")
    tabla.add_column("Versión")
    tabla.add_column("Riesgo")
    tabla.add_column("MITRE ATT&CK")
 
    for r in abiertos:
        color = colores_riesgo.get(r["riesgo_nivel"], "white")
        tabla.add_row(
            str(r["puerto"]),
            r["servicio"],
            r["version"] or "-",
            f"[{color}]{r['riesgo_nivel']}[/{color}]",
            f"{r['mitre_id']} ({r['mitre_nombre']})",
        )
 
    console.print(tabla)
 
 
# --------------------------------------------------------------------------
# Exportación y logging
# --------------------------------------------------------------------------
 
def exportar_json(datos: dict, ruta: str):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)
    console.print(f"  [green]✓[/green] Resultados exportados a JSON: [bold]{ruta}[/bold]")
 
 
def exportar_csv(datos: dict, ruta: str):
    campos = ["puerto", "servicio", "version", "riesgo_nivel", "riesgo_motivo",
              "mitre_id", "mitre_nombre", "banner"]
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        for r in datos["puertos_abiertos"]:
            writer.writerow({k: r.get(k, "") for k in campos})
    console.print(f"  [green]✓[/green] Resultados exportados a CSV: [bold]{ruta}[/bold]")
 
 
def guardar_log(datos: dict, carpeta_logs: str = "logs"):
    """Guarda un registro del escaneo en logs/scan_YYYY-MM-DD_HHMMSS.log"""
    Path(carpeta_logs).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    ruta = Path(carpeta_logs) / f"scan_{timestamp}.log"
 
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(f"Scan log — {datos['fecha']}\n")
        f.write(f"Host: {datos['host']} ({datos['ip']})\n")
        f.write(f"SO estimado: {datos['so_estimado']}\n")
        f.write(f"Puertos escaneados: {datos['puertos_escaneados']}\n")
        f.write(f"Duración: {datos['duracion_segundos']}s\n")
        f.write(f"Puertos abiertos: {len(datos['puertos_abiertos'])}\n\n")
        for r in datos["puertos_abiertos"]:
            f.write(
                f"  Puerto {r['puerto']} | {r['servicio']} | Riesgo: {r['riesgo_nivel']} "
                f"| {r['riesgo_motivo']} | MITRE: {r['mitre_id']} - {r['mitre_nombre']}\n"
            )
 
    console.print(f"  [green]✓[/green] Log guardado en: [bold]{ruta}[/bold]")
 
 
# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
 
def main():
    parser = argparse.ArgumentParser(
        description="Scanner de puertos TCP educativo — usar solo en sistemas autorizados.",
        epilog="Ejemplo: python3 scanner.py -H 127.0.0.1 -p 1-1024 --json resultado.json",
    )
    parser.add_argument("-H", "--host", required=True, help="Host o IP a escanear")
    parser.add_argument("-p", "--puertos", default="1-1024",
                         help="Rango de puertos, ej: '1-1024' o '22,80,443' (default: 1-1024)")
    parser.add_argument("-t", "--hilos", type=int, default=100,
                         help="Número de hilos concurrentes (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Timeout por conexión en segundos (default: 1.0)")
    parser.add_argument("--top-ports", action="store_true",
                         help="Escanea solo los 20 puertos más comunes (modo rápido)")
    parser.add_argument("--json", metavar="ARCHIVO",
                         help="Exporta los resultados a un archivo JSON")
    parser.add_argument("--csv", metavar="ARCHIVO",
                         help="Exporta los resultados a un archivo CSV")
    parser.add_argument("--log", action="store_true",
                         help="Guarda un log del escaneo en carpeta logs/")
    parser.add_argument("--os-detect", action="store_true",
                         help="Estima el sistema operativo remoto vía TTL (ping)")
 
    args = parser.parse_args()
 
    puertos = TOP_PORTS if args.top_ports else parsear_rango_puertos(args.puertos)
 
    datos = escanear(args.host, puertos, hilos=args.hilos, timeout=args.timeout,
                      detectar_so=args.os_detect)
 
    if args.json:
        exportar_json(datos, args.json)
    if args.csv:
        exportar_csv(datos, args.csv)
    if args.log:
        guardar_log(datos)
 
 
if __name__ == "__main__":
    main()