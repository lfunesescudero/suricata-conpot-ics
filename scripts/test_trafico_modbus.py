from pymodbus.client import ModbusTcpClient
import time

HOST = "127.0.0.1"
PORT = 5020

client = ModbusTcpClient(HOST, port=PORT)
client.connect()

print("[FC5] Write Single Coil...")
client.write_coil(address=0, value=True, device_id=1)
time.sleep(1)

print("[FC1] Read Coils...")
client.read_coils(address=0, count=8, device_id=1)
time.sleep(1)

print("[FC3] Read Holding Registers (bulk, 25 registros)...")
client.read_holding_registers(address=40001, count=8, device_id=2)
time.sleep(1)

client.close()
print("Listo.")
