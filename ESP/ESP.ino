#include <Arduino_BuiltIn.h>
#include "utils.h"
#include <PubSubClient.h>
#include <Wire.h>
#include "MAX30100_PulseOximeter.h"
#include <Adafruit_Fingerprint.h>
#include "blake2s.h"
#include "certs.h"

#define REPORTING_PERIOD_MS     10000
PulseOximeter pox;
uint32_t tsLastReport = 0;
int BPM;

void setup() {
  Serial.begin(115200);
  connectWiFi();  // Connect to WiFi
  connectMQTT();  // Connect to MQTT Broker
  mySerial.begin(57600, SERIAL_8N1, 16, 17);
  skin.begin(57600);
  delay(100);

  if (skin.verifyPassword()) {
    Serial.println("Skinprint sensor detected!");
  } else {
    Serial.println("Skinprint sensor not found. Check wiring!");
    while (1) delay(1);
  }

    int p = skin.getImage();
  if (p == FINGERPRINT_OK) {
   Serial.println("Skinprint image taken!");

   p = skin.image2Tz(1);
    if (p == FINGERPRINT_OK) {
      Serial.println("Skinprint converted to template!");

      // Retrieve and print Skinprint template data
      publishSkinprintTemplate();
    }
  }
  else {
    Serial.println("Error capturing Skinprint.");
  }

  Serial.print("Initializing pulse oximeter..");

  if (!pox.begin()) {
    Serial.println("FAILED");
    for (;;);
  } else {
    Serial.println("SUCCESS");
  }

  pox.setIRLedCurrent(MAX30100_LED_CURR_50MA);
  pox.setOnBeatDetectedCallback(onBeatDetected);

}

void loop() {
 if (!client.connected()) {
    connectMQTT();
    }

  pox.update();
  BPM = pox.getHeartRate();

  if (millis() - tsLastReport > REPORTING_PERIOD_MS){
    Serial.print(F("HR: "));
    Serial.print(BPM);
    Serial.println();
    publishHR(BPM);
    tsLastReport = millis();

  
  }
}