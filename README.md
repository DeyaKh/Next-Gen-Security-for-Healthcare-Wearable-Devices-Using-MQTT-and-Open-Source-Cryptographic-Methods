
# Next-Gen Security for Healthcare Wearable Devices Using MQTT and Open-Source Cryptographic Methods

This project proposes a **secure, open-source communication protocol** for healthcare wearable devices (HWDs), integrating MQTT and modern cryptographic techniques. The goal is to mitigate the vulnerabilities of existing systems that rely on proprietary protocols with weak or no encryption.

---

## Project Structure

```
├── Esp.ino               # ESP32 main firmware
├── certs.h               # TLS certificates and credentials
├── utils.h               # Networking, encryption, and hashing utilities
├── HR_System.py          # Python script for Raspberry Pi (Actuator Node)
```

---

## Hardware Requirements

- **ESP32 Dev Board**: Publishes sensor readings and encrypted key.
- **MAX30100 Pulse Oximeter Sensor**: Captures heart rate (HR).
- **R503 Capacitive Fingerprint Sensor**: Scans patient’s skin-print (SP).
- **Raspberry Pi 5**: Acts as the actuator.
- **LEDs**: Indicate HR status and errors.
- **Wi-Fi Access Point**: Required for device-to-cloud communication.
- **MQTT Broker (VerneMQ)**: Enforces secure communication (must be configured for TLS).

---

## Software & Libraries

### ESP32 (C/C++)

- `MAX30100_PulseOximeter`
- `Adafruit Fingerprint Sensor Library`
- `PubSubClient`
- `ArduinoJson`
- `WiFi.h`, `Wire.h`
- `mbedTLS` for AES-CBC
- Custom BLAKE2s hash implementation

### Raspberry Pi (Python)

Install via `pip`:

```bash
pip install paho-mqtt pycryptodome
```

- `paho-mqtt`: MQTT client
- `Crypto.Cipher.AES`: AES decryption
- `hashlib`: BLAKE2s hash
- `RPi.GPIO`: LED control

---

## Security Architecture

The system utilizes a layered security approach based on:

- **AES-256-CBC**: Encrypts patient skin-print using ESP32 serial number (SN) as the key.
- **Value-to-HMAC**: Applies BLAKE2s hash over HR using SP as the key.
- **TLS-encrypted MQTT**: Ensures end-to-end encrypted transmission using VerneMQ.

---

## Setup & Configuration

### ESP32

1. Configure `certs.h` with:
   - WiFi credentials
   - Broker address
   - TLS certificates

2. Flash `Esp.ino` with required libraries.

### Raspberry Pi

1. Configure `HR_System.py` with:
   - Paths to TLS certs
   - Broker details

2. Run:
```bash
python3 HR_System.py
```

---

## Functional Flow

### Sensor Node (ESP32)

1. Captures HR via MAX30100.
2. Captures SP via fingerprint sensor.
3. Encrypts SP using SN and AES.
4. Publishes encrypted SP and BLAKE2s hash of HR to VerneMQ broker.

### Actuator Node (Raspberry Pi)

1. Receives and decrypts SP using SN.
2. Builds hash table for HR values using SP.
3. Maps received HR hash to actual HR.
4. Indicates HR range using LEDs and sends alerts.

---

## MQTT Topics

| Topic           | Payload Format                      |
|-----------------|-------------------------------------|
| Sensor/key      | `{ "KEY": "<hex_encrypted_key>" }`  |
| Sensor/readings | `{ "HR": "<blake2s_hashed_HR>" }`   |
| RPi/alerts      | `"Alert(...): <message>"`           |

---

## Alerts & LED Indicators

| LED Pattern         | Meaning                        |
|---------------------|--------------------------------|
| Green LED           | Normal HR range                |
| Red LED             | High HR                        |
| White LED           | Low HR                         |
| Flashing Green      | System Error                   |
| Flashing Red        | Abnormal Error                 |

---

## Key Features

- **Confidentiality**: AES encryption of biometric SP data.
- **Integrity**: BLAKE2s hash validation.
- **Scalability**: Efficient MQTT protocol using VerneMQ.
- **Resilience**: Handles system malfunctions and alerts via LEDs and MQTT.

---

## Project Objectives

- Replace vulnerable proprietary protocols with open-source security.
- Enhance confidentiality and integrity using “Value-to-HMAC”.
- Demonstrate authentication via SN and SP-derived key.
- Provide a reusable, low-cost, secure framework for other HWDs.

---

## Contributors

Prepared by students at **Jordan University of Science and Technology (JUST)**:

- Karoleina Rezek  
- Deya Aldeen Alkhozaee  
- Abdulaziz Tbaishat  
- Hamza Alzoubi  

Supervised by: **Dr. Heba Alawneh**

---


