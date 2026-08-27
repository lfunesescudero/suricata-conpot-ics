# P-09 — Informe de Incidente: Detección de Actividad Anómala en Red Modbus (ICS/OT)

## Resumen ejecutivo

Se implementó una capa de detección activa (Suricata IDS) sobre un honeypot ICS
(Conpot, protocolo Modbus/TCP) para identificar patrones de reconocimiento y
manipulación no autorizada en un entorno OT. Se documentan 4 eventos
de seguridad detectados y validados, mapeados al NIST Cybersecurity Framework.

## Alcance y entorno

- Honeypot: Conpot 0.6.0, template default, protocolo Modbus/TCP en puerto no
  estandar 5020 (proceso no-root dentro de contenedor Docker)
- Sensor: Suricata 8.0.6, interfaz docker0, 4 reglas custom
- Referencia previa: P-08 documentó captura forense pasiva del mismo entorno;
  P-09 cierra la brecha de deteccion activa en tiempo real

## Mapeo NIST CSF

### IDENTIFY (ID)
Activo monitoreado: dispositivo ICS simulado (Siemens S7-200) expuesto en
puerto Modbus no estandar 5020. Superficie de ataque: escritura de coils
(control de salidas fisicas simuladas) y lectura de registros (exposicion
de datos operativos).

### DETECT (DE)
4 firmas Suricata desplegadas y validadas contra trafico real:

| # | Evento | Regla (SID) | Clasificacion | Evidencia (fast.log) |
|---|--------|-------------|----------------|----------------------|
| 1 | Escaneo de puerto Modbus no estandar | 9000001 | Attempted Information Leak | 172.17.0.1:59944 -> 172.17.0.2:5020 |
| 2 | Escritura Modbus (Write Single Coil, FC5) | 9000002 | Attempted Administrator Privilege Gain | 172.17.0.1:49750 -> 172.17.0.2:5020 |

| 3 | Lectura Modbus (Read Coils, FC1) | 9000003 | Attempted Information Leak | 172.17.0.1:49750 -> 172.17.0.2:5020 |
| 4 | Lectura masiva Holding Registers (FC3) | 9000004 | Attempted Information Leak | 172.17.0.2:5020 -> 172.17.0.1:37396 |

Detalle tecnico de deteccion:
- Evento 1: correlacion por umbral (3 conexiones TCP SYN en 60s), sin
  depender de parseo de capa de aplicacion, ya que un escaneo no completa
  sesion Modbus
- Eventos 2 y 3: matcheo directo sobre el keyword `modbus` (function code
  5 y 1 respectivamente), capa de aplicacion parseada por Suricata
- Evento 4: matcheo sobre el paquete de respuesta (direccion honeypot ->
  atacante), identificando el byte de function code (0x03) en offset fijo
  7 de la trama TCP, combinado con `dsize>15` para distinguir una lectura
  de multiples registros de una lectura puntual. Se opto por esta tecnica
  en lugar del keyword `modbus` porque Suricata no permite combinar un
  match de capa de aplicacion con un match de paquete crudo (dsize) en la
  misma firma

### RESPOND (RS)
Ante la deteccion de evento 2 (escritura de coil) en un entorno productivo,
la respuesta indicada seria: aislar el segmento de red del activo ICS,
validar el estado fisico real del dispositivo controlado, y revisar logs
de acceso para identificar el origen. En esta instancia, la respuesta se limitó a validación y documentación del evento.

### RECOVER (RC)
No aplica en el contexto de este trabajo de deteccion (no hubo impacto
real sobre un proceso fisico). En un escenario productivo, la recuperacion
implicaria restaurar el estado previo del registro/coil modificado y
confirmar integridad operativa antes de reconectar el segmento aislado.

## Hallazgos tecnicos relevantes


1. El template default de Conpot distribuye los tipos de datos Modbus entre
   distintos `device_id` (slaves): device_id=1 solo expone coils e inputs
   discretos, device_id=2 es el unico con holding registers (8 registros
   disponibles)
2. Conpot no aplica la conversion clasica de direccionamiento Modbus
   (40001 -> direccion de protocolo 0): usa el valor de `starting_address`
   del XML de configuracion de forma literal como direccion de protocolo
3. El umbral de deteccion de "lectura masiva" debe calibrarse contra la
   capacidad real del activo monitoreado, no contra un valor generico:
   con 8 registros disponibles, la respuesta maxima legitima es ~25 bytes

## Conclusion

Las 4 reglas quedaron validadas contra trafico Modbus real, cerrando la
brecha de deteccion activa identificada en P-08. El trabajo evidencio
la importancia de calibrar firmas de deteccion contra el comportamiento
real del protocolo y del activo especifico, en lugar de valores generico.
