import time
import paho.mqtt.client as mqtt
import ssl
import json
from Crypto.Cipher import AES
import hashlib
import binascii
import RPi.GPIO as GPIO

GPIO.setmode(GPIO.BCM)
#set red,green and blue pins
redPin = 12
greenPin = 19
bluePin = 13
#set pins as outputs
GPIO.setup(redPin,GPIO.OUT)
GPIO.setup(greenPin,GPIO.OUT)
GPIO.setup(bluePin,GPIO.OUT)

AES_KEY = b"94cdbbbb3b11746cf232ec61c6de3bc0"
iv = b"1234567890123456"
decrypted_bytes = ""
SP = 0
oldHR = 0
HR_ctr = 0
HashTable = {}

def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

def decrypt_aes(encrypted_data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted

def systemError():
	turnOff()
	for i in range(0,5):
		GPIO.output(redPin,GPIO.HIGH)
		GPIO.output(greenPin,GPIO.LOW)
		GPIO.output(bluePin,GPIO.HIGH)
		time.sleep(1)
		turnOff()
		time.sleep(1)

def abnormalError():
	turnOff()
	for i in range(0,5):
		GPIO.output(redPin,GPIO.LOW)
		GPIO.output(greenPin,GPIO.HIGH)
		GPIO.output(bluePin,GPIO.HIGH)
		time.sleep(1)
		turnOff()
		time.sleep(1)

# Certificate files
CA_FILE = "/home/deya/Desktop/System/rootCA.pem"          #root CA
CERT_FILE = "/home/deya/Desktop/System/certificate.pem.crt"      # RPi5 certificate
PRIVATE_KEY_FILE = "/home/deya/Desktop/System/private.pem.key"  # RPi private key

# Define Variables
HR_TOPIC = "Sensor/readings"
ALERT_TOPIC = "RPi/alerts"
KEY_TOPIC = "Sensor/key"

#Time tracking
last_time_message = time.time()

def on_connect(client, userdata, flags, rc):
	print(f"Connected with result code {rc}")
	client.subscribe(HR_TOPIC)
	print(f"Subscribed to topic: {HR_TOPIC}")
	
	print(f"Connected with result code {rc}")
	client.subscribe(KEY_TOPIC)
	print(f"Subscribed to topic: {KEY_TOPIC}")
    

# Callback when a message is received
def on_message(client, userdata, msg):
    global SP
    global oldHR
    global HR_ctr
    global last_time_message
    last_time_message = time.time()

    try:
        # Decode JSON payload
        payload = json.loads(msg.payload.decode("utf-8"))

        # If the message is from KEY_TOPIC, extract the skinprint key
        if msg.topic == KEY_TOPIC:
            encrypted_hex = payload.get("KEY", "")
            if encrypted_hex:
                encrypted_bytes = hex_to_bytes(encrypted_hex)
                print(f"Encrypted Skinprint Key: {encrypted_bytes.hex()}")
                global decrypted_bytes 
                decrypted_bytes = decrypt_aes(encrypted_bytes)
                print(f"Decrypted Skinprint Key: {decrypted_bytes.hex()}")
                SP = 1
                hashTable_init()
            else:
               print("No KEY found in message.")
                
        elif SP == 0:
                client.publish(ALERT_TOPIC, payload="Alert(System): No SkinPrint!!" , qos=1, retain=False)
                print("Alert(System): No SkinPrint!!")
                systemError()
                client.loop_stop()
                client.disconnect()
                exit(0)
			
        elif msg.topic == HR_TOPIC:
            Hashed_HR = payload.get("HR", "No HR found")
            HR = hashTable_search(Hashed_HR)
            HR_Diff = int(HR) - oldHR
            if HR_Diff < -100 or HR_Diff > 100:
                if HR_ctr > 3:
                    client.publish(ALERT_TOPIC, payload="Alert(Abnormal): Abnormal Behaviour!!" , qos=1, retain=False)
                    print("Alert(Abnormal): Abnormal Behaviour!!")
                    abnormalError()
                else:
                    HR_ctr += 1
               
            print(f"HR: {HR}")
            oldHR = int(HR)
            					
            if int(HR) > 100 and int(HR) < 170:
                GPIO.output(redPin,GPIO.HIGH)
                GPIO.output(greenPin,GPIO.LOW)
                GPIO.output(bluePin,GPIO.HIGH)
                
            elif int(HR) < 100:
               GPIO.output(redPin,GPIO.LOW)
               GPIO.output(greenPin,GPIO.LOW)
               GPIO.output(bluePin,GPIO.LOW)
               
            elif int(HR) > 170:
               GPIO.output(redPin,GPIO.LOW)
               GPIO.output(greenPin,GPIO.HIGH)
               GPIO.output(bluePin,GPIO.HIGH)
				


    except json.JSONDecodeError:
        print(f"Error decoding JSON message: {msg.payload}")

    last_time_message = time.time()

def hashTable_init():
	global decrypted_bytes
	decrypted_str = str(decrypted_bytes).upper()
	decrypted_bytes_up = decrypted_str.encode()
	
	for HR in range(0, 251):
		hasher = hashlib.blake2s(key=decrypted_bytes, digest_size=32)
		hasher.update(str(HR).encode())
		Hashed_HR = hasher.hexdigest()
		HashTable[str(Hashed_HR).upper()] = str(HR)
	print(HashTable)

def hashTable_search(Hashed_HR):
	return HashTable[str(Hashed_HR)]

def turnOff():
    GPIO.output(redPin,GPIO.HIGH)
    GPIO.output(greenPin,GPIO.HIGH)
    GPIO.output(bluePin,GPIO.HIGH)

# MQTT Client Setup
client = mqtt.Client()
client.on_connect = on_connect

# SSL/TLS configuration
client.tls_set(ca_certs=CA_FILE,
               certfile=CERT_FILE,
               keyfile=PRIVATE_KEY_FILE,
               tls_version=ssl.PROTOCOL_TLSv1_2)
client.tls_insecure_set(True)

try:
    # Connect to VerneMQ Broker
	print("Connecting to the system...")
	client.connect("172.20.10.11", 8883, 60) 
	client.loop_start()
	while True:
		client.on_message = on_message
		current_time = time.time()
		if current_time - last_time_message > 20 and current_time - last_time_message < 25:
			   client.publish(ALERT_TOPIC, payload="Alert(System): No Readings!!" , qos=1, retain=False)
			   print("Alert(System): No Readings!!")
			   systemError()
		time.sleep(5)

except KeyboardInterrupt:
    print("Exiting HR System...")

finally:
    client.loop_stop()
    client.disconnect()
    turnOff()
