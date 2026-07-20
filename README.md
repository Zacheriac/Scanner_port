🔍 TCP Port Scanner

Scanner de puertos TCP desarrollado en Python, con detección de servicios comunes, banner grabbing y escaneo concurrente mediante hilos.

⚠️ Uso ético

Este proyecto fue desarrollado con fines educativos y de práctica en ciberseguridad. Debe usarse únicamente en:

Máquinas propias (localhost, contenedores Docker propios, homelab)
Entornos de práctica autorizados (TryHackMe, HackTheBox, DVWA, etc.)
Sistemas donde exista autorización explícita por escrito

Escanear sistemas de terceros sin autorización es ilegal en la mayoría de jurisdicciones (en Perú: Ley de Delitos Informáticos, Ley N° 30096).

🚀 Características
Escaneo de puertos TCP mediante socket.connect_ex()
Identificación de servicios comunes (SSH, HTTP, MySQL, PostgreSQL, SMB, etc.)
Banner grabbing básico para detectar versión del servicio
Escaneo concurrente con ThreadPoolExecutor (rango 1-1024 en segundos, no minutos)
Soporte para rangos de puertos (1-1024) o listas específicas (22,80,443)
Reporte resumen al finalizar el escaneo
🛠️ Requisitos
Python 3.10 o superior

No requiere dependencias externas — usa únicamente la librería estándar de Python.

📦 Instalación
bash
git clone https://github.com/Zacheriac/Scanner_port.git
cd Scanner_port
▶️ Uso
bash
python scanner.py -H 127.0.0.1 -p 1-1024
Opciones disponibles
Flag	Descripción	Default
-H, --host	Host o IP a escanear (obligatorio)	—
-p, --puertos	Rango o lista de puertos	1-1024
-t, --hilos	Número de hilos concurrentes	100
--timeout	Timeout por conexión (segundos)	1.0
Ejemplos
bash
# Escanear puertos específicos
python scanner.py -H 127.0.0.1 -p 22,80,443,3306

# Escaneo rápido con más hilos
python scanner.py -H 127.0.0.1 -p 1-65535 --hilos 300

# Ajustar timeout para redes lentas
python scanner.py -H 192.168.1.1 -p 1-1024 --timeout 2.0
📸 Ejemplo de salida
============================================================
  Escaneando: 127.0.0.1 (127.0.0.1)
  Puertos: 1024 | Hilos: 100 | Timeout: 1.0s
============================================================

  [ABIERTO] Puerto   445 (SMB)
  [ABIERTO] Puerto  8080 (HTTP-Alt) | HTTP/1.1 200 OK

============================================================
  Escaneo completado en 0.85s
  Puertos abiertos encontrados: 2
============================================================
🧠 Conceptos técnicos aplicados
Connect scan: usa connect_ex() en lugar de sockets raw, por lo que no requiere privilegios de administrador/root (a diferencia de un SYN scan tipo nmap -sS)
Concurrencia con hilos: escanear 1024 puertos en serie con timeout de 1s tomaría hasta 17 minutos; con ThreadPoolExecutor se reduce a segundos
Banner grabbing: varios servicios (SSH, FTP, SMTP, HTTP) envían información de versión automáticamente al conectar, lo cual es clave en fases de reconocimiento y análisis de vulnerabilidades
🗺️ Roadmap
 Exportar resultados a JSON/CSV
 Clasificación de riesgo por puerto/servicio detectado
 Detección de versión de servicio vía regex
 Mapeo a técnicas de MITRE ATT&CK
 Detección básica de sistema operativo por TTL
📄 Licencia

MIT