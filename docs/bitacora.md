
[P-09] Paso 4 - En progreso, pausado
Regla 1 (escaneo): CONFIRMADA en fast.log.
Regla 2 (FC5 Write Coil): CONFIRMADA en fast.log.
Regla 3 (FC1 Read Coils): CONFIRMADA en fast.log.
Regla 4 (FC3 bulk read): PENDIENTE.

Causa: el script apuntaba a device_id=1 pidiendo Holding Registers, pero
segun modbus.xml del template default de Conpot, el device_id=1 no tiene
bloque HOLDING_REGISTERS (solo COILS y DISCRETE_INPUTS). El unico bloque
HOLDING_REGISTERS existe en device_id=2, direccion protocolo 0, tamano 8
registros (mapea a la notacion clasica 40001-40008).

Hallazgo tecnico pendiente de resolver: con solo 8 registros disponibles,
la respuesta maxima posible de Conpot ronda ~25 bytes. La regla 4 pide
dsize:>50, umbral que este honeypot no puede alcanzar de forma legitima.
Proximo paso: bajar el umbral dsize de la regla 4 a un valor realista
(ej. >20) y volver a probar con device_id=2, address=0, count=8.
[P-09] Paso 1 - Instalación
Suricata 8.0.6 instalado vía apt en Kali Linux.
Servicio systemd deshabilitado por defecto (esperado, se controla manual).
Carpeta de trabajo: ~/Practicas_SOC/Semana3_4/P09-Suricata-Deteccion

[P-09] Paso 2 - Configuración (completo)
af-packet interface: docker0
vars.port-groups.MODBUS_PORTS: "[502,5020]"
app-layer.modbus.enabled: yes (estaba en "no" por defecto, corregido)
app-layer.modbus.detection-ports.dp: 502, 5020

[P-09] Paso 3 - Reglas Suricata (completo)
4 reglas custom en p09-modbus-custom.rules:
1. Reconocimiento/escaneo de puerto (TCP SYN repetido, sin capa modbus)
2. Write Single Coil (FC5) - modificacion de estado
3. Read Coils (FC1) - lectura basica
4. Bulk read Holding Registers (FC3) - deteccion por tamano de RESPUESTA

Archivo copiado a /var/lib/suricata/rules/, agregado a rule-files en
suricata.yaml. Validado con suricata -T -c /etc/suricata/suricata.yaml -v:
4/4 reglas cargadas, 0 errores, exit code 0.

Hallazgo tecnico: el keyword modbus (capa de aplicacion) no se puede
combinar con dsize (paquete crudo) en la misma firma, Suricata rechaza
la firma con error "Signature combines packet specific matches...with
stream/state matching". Regla 4 corregida: en vez de modbus: function 3,
se matchea el byte de function code (0x03) directo en offset 7 de la
trama TCP (offset fijo porque la cabecera MBAP de Modbus/TCP siempre
mide 7 bytes: Transaction ID 2 + Protocol ID 2 + Length 2 + Unit ID 1).

[P-09] Paso 4 - Completo
Las 4 reglas confirmadas disparando en fast.log:
1. Escaneo de puerto: 172.17.0.1:59944 -> 172.17.0.2:5020
2. FC5 Write Single Coil: confirmada
3. FC1 Read Coils: confirmada
4. FC3 Read Holding Registers (bulk): confirmada tras 2 correcciones

Correcciones aplicadas a la regla 4:
- dsize bajado de >50 a >15 (con 8 registros disponibles en el template,
  la respuesta real pesa 25 bytes; el umbral original nunca se hubiera
  alcanzado con este honeypot).
- Direccion de registro: Conpot NO aplica la conversion clasica Modbus
  (40001 -> address 0). Usa el valor literal del modbus.xml como
  direccion de protocolo. Pedido correcto: address=40001, device_id=2
  (unico slave con bloque HOLDING_REGISTERS en el template default).

Comando de trafico usado para validar:
read_holding_registers(address=40001, count=8, device_id=2)
