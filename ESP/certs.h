#include <pgmspace.h>

#ifndef CERTS_H
#define CERTS_H

// WiFi Credentials
#define WIFI_SSID "SSID"
#define WIFI_PASSWORD "Password"

// MQTT Broker Details
#define MQTT_BROKER "Broker domain/IP address"
#define MQTT_PORT 8883
#define MQTT_TOPIC "Sensor/readings"
#define KEY_TOPIC "Sensor/key"

// TLS Certificates
const char *CERT_CA = R"EOF(
-----BEGIN CERTIFICATE-----
---Your CA Cert goes here---
-----END CERTIFICATE-----
)EOF";

const char *ESP_CERT_CRT = R"EOF(
-----BEGIN CERTIFICATE-----
---Your CRT Cert goes here---
-----END CERTIFICATE-----
)EOF";

const char *ESP_CERT_PRIVATE = R"EOF(
-----BEGIN PRIVATE KEY-----
---Your Private Key goes here---
-----END PRIVATE KEY-----
)EOF";

#endif
