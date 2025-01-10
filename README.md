# CVE-2024-38063 Exploit Checker and Denial-of-Service (Modified)

Este repositorio contiene un script de Python para verificar la vulnerabilidad CVE-2024-38063 en implementaciones de TCP/IP de Windows, y para llevar a cabo un ataque de denegación de servicio (DoS) si el sistema es vulnerable.

**Importante:** Este código se proporciona únicamente con fines educativos y de investigación en seguridad. La utilización de este script en sistemas sin la debida autorización es ilegal y puede causar daños significativos. El autor de este repositorio no se hace responsable del uso indebido de este código.

## Detalles de la Vulnerabilidad

La vulnerabilidad CVE-2024-38063 reside en la forma en que ciertas versiones de Windows gestionan paquetes IPv6 específicamente manipulados. Un atacante puede enviar una serie de paquetes con fragmentación y opciones corruptas que pueden llevar a una denegación de servicio (BSOD) en el sistema afectado.

## Cómo Funciona

El script realiza las siguientes acciones:

1. **Selección de Interfaz:** Permite al usuario seleccionar la interfaz de red que se utilizará para enviar los paquetes.
2. **Detección del Objetivo (Opcional):** Intenta determinar si el objetivo está activo utilizando peticiones ICMPv6 y un escaneo básico de puertos TCP.
3. **Obtención de la Dirección MAC:** Intenta obtener la dirección MAC del objetivo mediante Neighbor Discovery.
4. **Generación de Paquetes:** Crea una serie de paquetes IPv6 con opciones Destination Options malformadas y fragmentación incorrecta, diseñados para explotar la vulnerabilidad.
5. **Verificación de Vulnerabilidad:** Envía un pequeño número de paquetes para intentar verificar si el objetivo es vulnerable. Busca una respuesta ICMPv6 Parameter Problem.
6. **Ataque de Denegación de Servicio (Opcional):** Si el usuario lo confirma, envía una gran cantidad de paquetes maliciosos para provocar la denegación de servicio.

**Código Original:** Este script se basa en el trabajo original de **Photubias**, cuyo script de prueba de concepto se incluye en este repositorio con fines de referencia y para respetar la atribución del autor original.

**Modificaciones:** Este repositorio contiene modificaciones al script original de Photubias. Las principales modificaciones incluyen:

* **Mejoras en la detección del objetivo:** Se añadieron funciones para realizar un ping IPv6 y un escaneo básico de puertos TCP para verificar la accesibilidad del objetivo.
* **Opción de aleatorización de paquetes:** Se agregó la capacidad de aleatorizar ciertos campos de los paquetes para intentar evadir sistemas de detección.
* **Spoofing de la dirección de origen (opcional):** Se implementó la capacidad de falsificar la dirección IPv6 de origen de los paquetes.
* **Payloads personalizables:** Se introdujo la posibilidad de utilizar diferentes payloads en los paquetes fragmentados.
* **Logging básico:** Se añadió un sistema de logging para registrar la actividad del script.

## Cómo Utilizar

1. **Requisitos:**
    * Python 3 instalado.
    * La librería `scapy` instalada. Puedes instalarla con `pip install scapy`.
    * Ejecutar el script con privilegios de administrador (o `sudo` en Linux) para poder enviar paquetes raw.

2. **Ejecución:**
   ```bash
   python nombre_del_script.py <dirección_ipv6_del_objetivo>
