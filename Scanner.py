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
  - Escaneo de puertos TCP mediante sockets crudos (connect scan)
  - Detección de servicio común por número de puerto
  - Banner grabbing básico (intenta leer respuesta del servicio)
  - Escaneo concurrente con ThreadPoolExecutor para velocidad
  - Reporte final con resumen de puertos abiertos
"""
 
import socket
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# Puertos comunes y su servicio asociado (para mostrar contexto al usuario)
SERVICIOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "RabbitMQ/AMQP",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}
 
 
def escanear_puerto(host: str, puerto: int, timeout: float = 1.0) -> dict | None:
    """
    Intenta conectar a un puerto TCP específico.
    Retorna un dict con info del puerto si está abierto, None si está cerrado/filtrado.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    resultado = None
 
    try:
        codigo = sock.connect_ex((host, puerto))  # devuelve 0 si la conexión fue exitosa
        if codigo == 0:
            servicio = SERVICIOS_COMUNES.get(puerto, "Desconocido")
            banner = obtener_banner(sock, puerto)
            resultado = {
                "puerto": puerto,
                "estado": "abierto",
                "servicio": servicio,
                "banner": banner,
            }
    except socket.error:
        pass
    finally:
        sock.close()
 
    return resultado
 
 
def obtener_banner(sock: socket.socket, puerto: int) -> str:
    """
    Intenta capturar el banner (mensaje inicial) que el servicio envía.
    Para servicios HTTP, envía una petición GET básica para forzar respuesta.
    """
    try:
        sock.settimeout(0.8)
        if puerto in (80, 8080, 443, 8443):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: scan\r\nConnection: close\r\n\r\n")
        banner = sock.recv(200).decode(errors="ignore").strip()
        # Nos quedamos solo con la primera línea para que el reporte sea legible
        return banner.split("\n")[0][:100] if banner else ""
    except (socket.timeout, socket.error, OSError):
        return ""
 
 
def resolver_host(host: str) -> str:
    """Resuelve un hostname a IP. Sale del programa si no se puede resolver."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[ERROR] No se pudo resolver el host: {host}")
        sys.exit(1)
 
 
def parsear_rango_puertos(rango: str) -> list[int]:
    """
    Convierte un string como '1-1000' o '22,80,443' en una lista de puertos.
    """
    puertos = []
    for parte in rango.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fin = parte.split("-")
            puertos.extend(range(int(inicio), int(fin) + 1))
        else:
            puertos.append(int(parte))
    return sorted(set(puertos))
 
 
def escanear(host: str, puertos: list[int], hilos: int = 100, timeout: float = 1.0):
    ip = resolver_host(host)
    print(f"\n{'='*60}")
    print(f"  Escaneando: {host} ({ip})")
    print(f"  Puertos: {len(puertos)} | Hilos: {hilos} | Timeout: {timeout}s")
    print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
 
    abiertos = []
    inicio = time.time()
 
    with ThreadPoolExecutor(max_workers=hilos) as executor:
        futuros = {
            executor.submit(escanear_puerto, ip, p, timeout): p for p in puertos
        }
        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado:
                abiertos.append(resultado)
                banner_txt = f" | {resultado['banner']}" if resultado["banner"] else ""
                print(
                    f"  [ABIERTO] Puerto {resultado['puerto']:>5} "
                    f"({resultado['servicio']}){banner_txt}"
                )
 
    duracion = time.time() - inicio
    abiertos.sort(key=lambda x: x["puerto"])
 
    print(f"\n{'='*60}")
    print(f"  Escaneo completado en {duracion:.2f}s")
    print(f"  Puertos abiertos encontrados: {len(abiertos)}")
    print(f"{'='*60}")
 
    if abiertos:
        print("\n  Resumen:")
        for r in abiertos:
            print(f"    - Puerto {r['puerto']} → {r['servicio']}")
    else:
        print("\n  No se encontraron puertos abiertos en el rango especificado.")
 
    return abiertos
 
 
def main():
    parser = argparse.ArgumentParser(
        description="Scanner de puertos TCP educativo — usar solo en sistemas autorizados.",
        epilog="Ejemplo: python3 scanner.py -H 127.0.0.1 -p 1-1024",
    )
    parser.add_argument("-H", "--host", required=True, help="Host o IP a escanear")
    parser.add_argument(
        "-p", "--puertos", default="1-1024",
        help="Rango de puertos, ej: '1-1024' o '22,80,443' (default: 1-1024)",
    )
    parser.add_argument(
        "-t", "--hilos", type=int, default=100,
        help="Número de hilos concurrentes (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Timeout por conexión en segundos (default: 1.0)",
    )
 
    args = parser.parse_args()
    puertos = parsear_rango_puertos(args.puertos)
    escanear(args.host, puertos, hilos=args.hilos, timeout=args.timeout)
 
 
if __name__ == "__main__":
    main()
 