# Analizador de Tramas LAN/WLAN

Este proyecto utiliza Scapy para analizar tramas LAN (IEEE 802.3) y WLAN (IEEE 802.11) para estudiar y entender mejor la estructura de los paquetes y tramas en redes de computadoras.

## Requisitos

- Python 3.x
- Scapy
- Acceso de superusuario (root)

## Instalación

1. **Instalar Python**
   
   Asegúrate de tener Python 3.x instalado en tu sistema. Puedes descargarlo desde [python.org](https://www.python.org/downloads/).

2. **Instalar Scapy**
   
   Abre una terminal y ejecuta el siguiente comando:
   
   ```sh
   pip install scapy

## Poner Interfaz en Modo Monitor

Antes de ejecutar el script, asegúrate de que tu interfaz de red esté en modo monitor. Aquí te dejo los comandos básicos para hacerlo:

```sh
sudo ifconfig [interfaz] down
sudo iwconfig [interfaz] mode monitor
sudo ifconfig [interfaz] up
```

Reemplaza [interfaz] con el nombre de tu interfaz de red, por ejemplo, wlan0.

```sh
sudo python3 main.py
```
Notas Adicionales

    Este README asume un sistema basado en Linux.
