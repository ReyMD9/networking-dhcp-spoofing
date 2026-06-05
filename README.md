# Informe Técnico — DHCP Spoofing
**Nombre:** Reymond Marte  
**Matrícula:** 2025-0684  
**Asignatura:** Seguridad en Redes  
**Práctica:** P3 — DHCP Spoofing  

---
Link de demostracion: https://youtu.be/IdJ8jFxmkyo?si=udDuOhgsgZmN-NBu
## 1. Objetivo del Laboratorio

Demostrar cómo un atacante puede suplantar un servidor DHCP legítimo para entregar configuración de red falsa a las víctimas, estableciendo un ataque Man in the Middle automático al asignar el gateway del atacante como puerta de enlace predeterminada. Se demuestra también la contramedida mediante DHCP Snooping con puertos de confianza.

---

## 2. Objetivo del Script

El script `dhcp_spoofing.py` implementa un servidor DHCP falso que escucha solicitudes DHCP en la red y responde antes que el servidor legítimo. Al ganarle la carrera al router, la víctima recibe una IP válida pero con el gateway del atacante, redirigiendo todo su tráfico por la máquina atacante sin que la víctima lo note.

**Flujo del ataque:**
1. El script escucha paquetes UDP en los puertos 67 y 68
2. Al detectar un DHCP Discover, responde inmediatamente con un DHCP Offer falso
3. La víctima acepta el Offer y envía un DHCP Request
4. El script confirma con un DHCP ACK entregando IP válida y gateway falso
5. La víctima configura su interfaz con el gateway del atacante — MitM establecido

### 2.1 Parámetros del Script

| Flag | Descripción | Default |
|------|-------------|---------|
| `-i` / `--iface` | Interfaz de red a usar | Requerido |
| `--gateway` | IP del gateway falso a entregar | IP del atacante |
| `--dns` | Servidor DNS a entregar | `8.8.8.8` |
| `--pool-start` | Inicio del pool de IPs falsas | `192.6.84.100` |
| `--pool-end` | Fin del pool de IPs falsas | `192.6.84.150` |
| `--lease` | Tiempo de lease en segundos | `86400` |
| `--burst` | Paquetes por respuesta para ganar al router legítimo | `5` |

### 2.2 Requisitos

| Requisito | Detalle |
|-----------|---------|
| Python | 3.x |
| Scapy | `pip install scapy` |
| Permisos | Root (`sudo`) |
| IP Forwarding | `sudo sysctl -w net.ipv4.ip_forward=1` |
| Conectividad | El atacante debe estar en el mismo segmento L2 que la víctima |
| Recomendado | Ejecutar DHCP Starvation primero para agotar el pool del servidor legítimo |

---

## 3. Funcionamiento del Script

### 3.1 Descripción por Función

| Función | Descripción |
|---------|-------------|
| `generate_pool(start, end)` | Genera la lista de IPs disponibles para asignar a las víctimas |
| `next_ip()` | Retorna la siguiente IP disponible del pool de forma thread-safe usando un lock |
| `build_offer(pkt, ...)` | Construye un DHCP Offer con los datos del atacante como servidor y gateway |
| `build_ack(pkt, ...)` | Construye un DHCP ACK confirmando la IP y el gateway falso |
| `process_packet(pkt, ...)` | Detecta el tipo de mensaje DHCP (Discover o Request) y responde en consecuencia |
| `handle_packet(pkt, ...)` | Lanza `process_packet` en un thread separado por cada paquete para no bloquear el sniffer |
| `signal_handler(...)` | Captura Ctrl+C y muestra estadísticas finales |
| `dhcp_spoof(...)` | Función principal: configura parámetros, verifica IP Forwarding e inicia el sniffer |

### 3.2 Ciclo del Ataque

Por cada DHCP Discover detectado:

1. Se asigna una IP del pool al cliente (o se reutiliza la ya asignada a esa MAC)
2. Se construye un DHCP Offer con gateway = IP del atacante
3. Se envía el Offer en **burst** (`--burst` veces con `inter=0`) para ganar al router legítimo
4. Al recibir el DHCP Request, se envía un DHCP ACK con los mismos parámetros falsos
5. La víctima queda configurada con el gateway del atacante

El uso de **threading** garantiza que el sniffer no se bloquee mientras se envían los paquetes de respuesta, maximizando la velocidad de respuesta.

---

## 4. Documentación de la Red

### 4.1 Topología

*(Ver captura de pantalla de la topología en PNetLab)*
![[Pasted image 20260604215533.png]]

### 4.2 Direccionamiento IP

| Dispositivo | Interfaz | IP          | Rol                            |
| ----------- | -------- | ----------- | ------------------------------ |
| Router      | e0/0     | 192.6.84.1  | Gateway / DHCP Server legítimo |
| SW1         | VLAN 1   | —           | Switch Central L2              |
| SW2         | VLAN 1   | —           | Switch L2                      |
| SW3         | VLAN 1   | —           | Switch L2                      |
| Atacante    | ens3     | 192.6.84.10 | Servidor DHCP falso            |
| Víctima     | eth0     | DHCP        | Host objetivo                  |
| VPCs        | eth0     | DHCP        | Hosts adicionales              |

### 4.3 Detalles de Red

| Parámetro          | Valor                       |
| ------------------ | --------------------------- |
| Red                | 192.6.84.0/24               |
| Máscara            | 255.255.255.0               |
| Gateway legítimo   | 192.6.84.1                  |
| Gateway falso      | 192.6.84.21 (atacante)      |
| Pool DHCP legítimo | 192.6.84.22 — 192.6.84.200  |
| Pool DHCP falso    | 192.6.84.100 — 192.6.84.150 |
| VLAN               | VLAN 1 (default)            |
| Plataforma         | PNetLab                     |
| Sistema atacante   | Ubuntu 20.04                |
| Herramienta        | Scapy 2.7.0                 |

---

## 5. Demostración del Ataque

### 5.1 Paso a Paso

**Paso 1 — Activar IP Forwarding:**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

**Paso 2 — (Recomendado) Agotar el pool del servidor legítimo con Starvation:**
```bash
sudo python3 dhcp_starvation.py -i ens3 -c 0 -d 0.01
```

Verificar en el Router que el pool esté agotado:
```cisco
show ip dhcp binding
show ip dhcp pool
```

**Paso 3 — Ejecutar el servidor DHCP falso:**
```bash
sudo python3 dhcp_spoofing.py -i ens3 --burst 20
```

**Paso 4 — Desde la víctima solicitar IP:**
```
dhcp
```

**Paso 5 — Verificar que la víctima recibió el gateway falso:**
```bash
# En la víctima Linux
ip route show
# Resultado esperado: default via 192.6.84.10 (atacante, no el router)

# En VPC
show ip
# GW debe ser 192.6.84.10
```

**Paso 6 — Capturar tráfico de la víctima en el atacante:**
```bash
sudo tcpdump -i ens3 host 192.6.84.15
```


## 6. Contramedida

### 6.1 Descripción

**DHCP Snooping** es una función de seguridad en switches Cisco que distingue entre puertos confiables (*trusted*) y no confiables (*untrusted*). Solo los puertos marcados como *trusted* pueden enviar mensajes DHCP Offer y DHCP ACK. Los puertos *untrusted* (donde están los clientes y potenciales atacantes) solo pueden enviar DHCP Discover y DHCP Request. Cualquier Offer o ACK proveniente de un puerto untrusted es descartado inmediatamente.

### 6.2 Configuración

```cisco
! Activar DHCP Snooping globalmente
SW1(config)# ip dhcp snooping
SW1(config)# ip dhcp snooping vlan 1
SW1(config)# no ip dhcp snooping information option

! Puerto del Router como trusted (único servidor DHCP legítimo)
SW1(config)# interface e0/0
SW1(config-if)# ip dhcp snooping trust
SW1(config-if)# exit

! Puerto del atacante como untrusted con rate limit
SW1(config)# interface e0/3
SW1(config-if)# ip dhcp snooping limit rate 10
SW1(config-if)# exit
```

### 6.3 Verificación

```cisco
! Ver configuración de DHCP Snooping
SW1# show ip dhcp snooping

! Ver estadísticas — paquetes descartados
SW1# show ip dhcp snooping statistics

! Ver bindings legítimos
SW1# show ip dhcp snooping binding
```

### 6.4 Resultado

Con DHCP Snooping activo, el switch descarta automáticamente los DHCP Offers y ACKs provenientes del puerto `e0/3` (atacante) por ser un puerto untrusted. Solo el Router conectado en `e0/0` (trusted) puede entregar configuración DHCP. La víctima recibe únicamente la configuración legítima con el gateway correcto `192.6.84.1`.

---

## 7. Conclusión

El ataque DHCP Spoofing es especialmente peligroso porque no requiere que el atacante interactúe directamente con la víctima — simplemente espera a que ella pida una IP y le responde primero. Al combinar este ataque con DHCP Starvation, el atacante se convierte en el único servidor DHCP disponible en la red.

La contramedida DHCP Snooping es altamente efectiva porque opera a nivel de switch, antes de que los paquetes lleguen a los clientes. Al definir explícitamente cuáles puertos son fuentes confiables de DHCP, se elimina la posibilidad de que cualquier host no autorizado actúe como servidor DHCP en la red.

---
*Reymond Marte — 2025-0684*
