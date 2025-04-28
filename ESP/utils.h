#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Wire.h>
#include "MAX30100_PulseOximeter.h"
#include <Adafruit_Fingerprint.h>
#include <mbedtls/aes.h>
#include "blake2s.h"
#include "certs.h"

#define BLOCK_SIZE 32
#ifndef ROTR32
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#endif
#define B2S_GET32(p)                            \
     (((uint32_t) ((uint8_t *) (p))[0]) ^        \
     (((uint32_t) ((uint8_t *) (p))[1]) << 8) ^  \
     (((uint32_t) ((uint8_t *) (p))[2]) << 16) ^ \
     (((uint32_t) ((uint8_t *) (p))[3]) << 24))
#define B2S_G(a, b, c, d, x, y) {   \
    v[a] = v[a] + v[b] + x;         \
    v[d] = ROTR32(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];             \
    v[b] = ROTR32(v[b] ^ v[c], 12); \
    v[a] = v[a] + v[b] + y;         \
    v[d] = ROTR32(v[d] ^ v[a], 8);  \
    v[c] = v[c] + v[d];             \
    v[b] = ROTR32(v[b] ^ v[c], 7); }

// You should enter your SN here (do not change the number of digits!!)
const unsigned char serialNum[BLOCK_SIZE] = {
    'Y', 'o', 'u', 'r', 'S', 'N', 'g', 'o', 
    'e', 's', 'h', 'e', 'r', 'e', '0', '0', 
    '0', '0', '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0', '0', '0'
};
unsigned char iv[BLOCK_SIZE/2] = {
    '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6'
};

static const uint32_t blake2s_iv[8] =
   {
       0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };

char skinPrint_pt[BLOCK_SIZE];

WiFiClientSecure net;
PubSubClient client(net);
HardwareSerial mySerial(2); 
Adafruit_Fingerprint skin = Adafruit_Fingerprint(&mySerial);


int blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen);
void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen);
void blake2s_final(blake2s_ctx *ctx, void *out);
int blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen);

// Connect to WiFi
void connectWiFi() {
    Serial.print("Connecting to WiFi...");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected!");
}

// Connect to MQTT Broker
void connectMQTT() {
    Serial.println("Connecting to MQTT Broker...");

    // Set up TLS certificates
    net.setCACert(CERT_CA);
    net.setCertificate(ESP_CERT_CRT);
    net.setPrivateKey(ESP_CERT_PRIVATE);
    net.setInsecure();

    client.setServer(MQTT_BROKER, MQTT_PORT);

    while (!client.connected()) {
        Serial.print("Attempting MQTT connection...");
        if (client.connect("ESP32_Client")) {
            Serial.println("Connected!");
            client.subscribe(MQTT_TOPIC);
        } else {
            Serial.print("Failed, rc=");
            Serial.print(client.state());
            Serial.println(" Retrying in 5 seconds...");
            delay(5000);
        }
    }
}

void publishMessage(char *HR_Readings) {
  StaticJsonDocument<200> doc;
  doc["HR"] = HR_Readings;

  char jsonBuffer[512];
  serializeJson(doc, jsonBuffer);
 
  client.publish(MQTT_TOPIC, jsonBuffer);
}

void onBeatDetected()
{
  Serial.println("Beat Detected!");
}

void aesEncrypt(unsigned char *input, size_t length, unsigned char *output, unsigned char *iv) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    // Set 256-bit key for encryption
    mbedtls_aes_setkey_enc(&aes, serialNum, 256);

    // Encrypt using CBC mode
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);

    mbedtls_aes_free(&aes);
}

void publishSkinprintTemplate() {
    uint8_t *buffer = (uint8_t*) malloc(512);  
    unsigned char skinPrint_ct[BLOCK_SIZE];  // 32-byte encrypted data
    StaticJsonDocument<300> doc;  // JSON document

    if (!buffer) {
        Serial.println("Memory allocation failed!");
        return;
    }

    Serial.println("Capturing Skinprint...");
    int p = skin.getModel(); 

    if (p == FINGERPRINT_OK) {
        // Convert first 32 bytes of skinprint data to HEX
        unsigned char skinPrint_pt_uns[BLOCK_SIZE];
        Serial.print("Plain Skinprint Data: ");
        for (int i = 0; i < BLOCK_SIZE; i++) {
            skinPrint_pt[i] = buffer[i];
            skinPrint_pt_uns[i] = buffer[i];
            Serial.printf("%02X", buffer[i]);  // Print plain skinprint data in HEX
        }
        Serial.println();

        // Encrypt only the first 32 bytes (256 bits)
        aesEncrypt(skinPrint_pt_uns, BLOCK_SIZE, skinPrint_ct, iv);

        // Convert encrypted bytes to HEX for transmission
        char skinPrint_ct_Hex[65];  // 32 bytes * 2 + null
        Serial.print("Encrypted Skinprint Data: ");
        for (int i = 0; i < BLOCK_SIZE; i++) {
            sprintf(&skinPrint_ct_Hex[i * 2], "%02X", skinPrint_ct[i]);
            Serial.printf("%02X", skinPrint_ct[i]);  // Print encrypted data in HEX
        }
        Serial.println();

        skinPrint_ct_Hex[64] = '\0';  // Ensure null termination
        doc["KEY"] = skinPrint_ct_Hex;

        char jsonBuffer[300];  
        serializeJson(doc, jsonBuffer);

        // Publish encrypted skinprint data
        client.publish(KEY_TOPIC, jsonBuffer);

        Serial.println("Published Encrypted skinprint");

    } else {
        Serial.println("Failed to retrieve skinprint data.");
    }

    free(buffer);
}

   
static void blake2s_compress(blake2s_ctx *ctx, int last) {
    const uint8_t sigma[10][16] = {
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
      { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
      { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
      { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
      { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
      { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
      { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
      { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
      { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
    };
    int i;
    uint32_t v[16], m[16];

    for (i = 0; i < 8; i++) {           // init work variables
      v[i] = ctx->h[i];
      v[i + 8] = blake2s_iv[i];
      }

      v[12] ^= ctx->t[0];                 // low 32 bits of offset
      v[13] ^= ctx->t[1];                 // high 32 bits
      if (last)                           // last block flag set ?
        v[14] = ~v[14];
        for (i = 0; i < 16; i++)            // get little-endian words
          m[i] = B2S_GET32(&ctx->b[4 * i]);

      for (i = 0; i < 10; i++) {          // ten rounds
           B2S_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
           B2S_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
           B2S_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
           B2S_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
           B2S_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
           B2S_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
           B2S_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
           B2S_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
       }

       for( i = 0; i < 8; ++i )
           ctx->h[i] ^= v[i] ^ v[i + 8];
   }

int blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen) {
    size_t i;

    if (outlen == 0 || outlen > 32 || keylen > 32)
      return -1;                      // illegal parameters

    for (i = 0; i < 8; i++)             // state, "param block"
        ctx->h[i] = blake2s_iv[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->t[0] = 0;                      // input count low word
    ctx->t[1] = 0;                      // input count high word
    ctx->c = 0;                         // pointer within buffer
    ctx->outlen = outlen;

    for (i = keylen; i < 64; i++)       // zero input block
      ctx->b[i] = 0;
      if (keylen > 0) {
        blake2s_update(ctx, key, keylen);
        ctx->c = 64;}
       return 0;}

void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen) {
       size_t i;

       for (i = 0; i < inlen; i++) {
           if (ctx->c == 64) {             // buffer full ?
               ctx->t[0] += ctx->c;        // add counters
               if (ctx->t[0] < ctx->c)     // carry overflow ?
                   ctx->t[1]++;            // high word
               blake2s_compress(ctx, 0);   // compress (not last)
               ctx->c = 0;                 // counter to zero
           }
           ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
       }
   }

void blake2s_final(blake2s_ctx *ctx, void *out) {
  size_t i;

  ctx->t[0] += ctx->c;                // mark last block offset
  if (ctx->t[0] < ctx->c)             // carry overflow
    ctx->t[1]++;                    // high word

  while (ctx->c < 64)                 // fill up with zeros
    ctx->b[ctx->c++] = 0;
    blake2s_compress(ctx, 1);           // final block flag = 1

// little endian convert and store
  for (i = 0; i < ctx->outlen; i++) {
    ((uint8_t *) out)[i] = (ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
    }
  }

int blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen) {
  blake2s_ctx ctx;
    if (blake2s_init(&ctx, outlen, key, keylen))
      return -1;
    blake2s_update(&ctx, in, inlen);
    blake2s_final(&ctx, out);

     return 0;
}

void calculateHRHash(int HR, char *outputHashHex) {
    blake2s_ctx ctx;
    unsigned char hashOutput[BLOCK_SIZE];  

    char hrString[10];  
    sprintf(hrString, "%d", HR);

    // Initialize BLAKE2s hashing 
    blake2s(hashOutput, BLOCK_SIZE, skinPrint_pt, BLOCK_SIZE, hrString, strlen(hrString));

    // Convert hashed bytes to HEX string
    for (int i = 0; i < BLOCK_SIZE; i++) {
        sprintf(&outputHashHex[i * 2], "%02X", hashOutput[i]);
    }
    outputHashHex[BLOCK_SIZE * 2] = '\0';
}

void publishHR(int HR) {
    char HRHash[BLOCK_SIZE * 2 + 1];

    calculateHRHash(HR, HRHash);

    Serial.print("Hashed HR: ");
    Serial.println(HRHash);
    publishMessage(HRHash);
}


#endif
