// ================================================================
//  ESTACAO COFRE - a estacao de sempre (DHT + LED), agora blindada
//
//  Camada 1  TLS de verdade ......... setCACert() em vez de setInsecure()
//  Camada 2  API key ................ cabecalho X-API-Key no Worker
//  Camada 3  Assinatura HMAC ........ cabecalho X-Assinatura (+ ts anti-replay)
//  Camada 4  Cofre AES-GCM .......... leitura cifrada de ponta a ponta no MQTT
//  Bonus     Comandos assinados ..... so obedece comando com assinatura valida
//
//  Arquivos desta pasta:
//    config.h        -> SEGREDOS (copie de config.example.h). Nao versionar!
//    certificados.h  -> CAs publicas (gerado por scripts/gerar_certificados.ps1)
//
//  Bibliotecas: "PubSubClient" (Nick O'Leary) e "DHT sensor library" (Adafruit).
//  A criptografia (mbedtls) ja vem dentro do core do ESP32 - nada a instalar.
// ================================================================
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <time.h>
#include "mbedtls/md.h"      // HMAC-SHA256
#include "mbedtls/gcm.h"     // AES-GCM
#include "mbedtls/base64.h"  // Base64
#include "config.h"
#include "certificados.h"

#define DHTPIN   4
#define DHTTYPE  DHT22       // Wokwi usa DHT22 (em placa fisica: DHT11)
#define LED      2

#define INTERVALO_MS   15000 // uma leitura a cada 15 s
#define JANELA_CMD_S   30    // comando com mais de 30 s e' considerado velho
#define RETRY_MQTT_MS  300000 // 5 min entre tentativas de reconectar no broker

DHT dht(DHTPIN, DHTTYPE);
WiFiClientSecure tlsMqtt;    // canal TLS que fica aberto com o broker
PubSubClient mqtt(tlsMqtt);

String T_COFRE  = String("sis1a/") + NOME + "/cofre";    // leituras CIFRADAS
String T_CMD    = String("sis1a/") + NOME + "/comando";  // comandos (assinados)
String T_STATUS = String("sis1a/") + NOME + "/status";   // respostas aos comandos

uint8_t  chaveAES[16];
uint32_t ultimoTsCmd = 0;    // anti-replay dos comandos
bool     ledOn = false;
unsigned long ultimo = 0;
unsigned long ultimaTentativaMqtt = 0;   // reconexao nao bloqueante do MQTT

// ---------------------------------------------------------------
//  Utilidades de criptografia
// ---------------------------------------------------------------

// HMAC-SHA256(CHAVE_HMAC, msg) em hexadecimal minusculo (64 caracteres)
String hmacHex(const String& msg) {
  uint8_t mac[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const uint8_t*)CHAVE_HMAC, strlen(CHAVE_HMAC),
                  (const uint8_t*)msg.c_str(), msg.length(), mac);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", mac[i]);
  hex[64] = '\0';
  return String(hex);
}

// Compara sem "vazar" pelo tempo em que posicao a diferenca aparece
bool iguais(const String& a, const String& b) {
  if (a.length() != b.length()) return false;
  uint8_t dif = 0;
  for (unsigned int i = 0; i < a.length(); i++) dif |= a[i] ^ b[i];
  return dif == 0;
}

String base64(const uint8_t* dados, size_t n) {
  size_t tam = 0;
  mbedtls_base64_encode(NULL, 0, &tam, dados, n);      // descobre o tamanho
  unsigned char* buf = (unsigned char*)malloc(tam);
  mbedtls_base64_encode(buf, tam, &tam, dados, n);
  String s = String((const char*)buf).substring(0, tam);
  free(buf);
  return s;
}

bool hexParaBytes(const char* hex, uint8_t* saida, size_t n) {
  if (strlen(hex) != 2 * n) return false;
  for (size_t i = 0; i < n; i++) {
    char par[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
    char* fim;
    saida[i] = (uint8_t)strtol(par, &fim, 16);
    if (*fim != '\0') return false;
  }
  return true;
}

// Cifra 'claro' com AES-128-GCM. Devolve {"iv":"...","dados":"..."}
// "dados" = texto cifrado + tag de 16 bytes (o "lacre" do GCM)
String cifrarCofre(const String& claro) {
  uint8_t iv[12];                                     // NUNCA repetir com a mesma chave
  for (int i = 0; i < 12; i++) iv[i] = (uint8_t)esp_random();

  size_t n = claro.length();
  uint8_t* saida = (uint8_t*)malloc(n + 16);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, chaveAES, 128);
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, n, iv, sizeof(iv),
                            NULL, 0,                         // sem dado adicional
                            (const uint8_t*)claro.c_str(), saida,
                            16, saida + n);                  // tag vai no fim
  mbedtls_gcm_free(&gcm);

  String json = "{\"iv\":\"" + base64(iv, sizeof(iv)) +
                "\",\"dados\":\"" + base64(saida, n + 16) + "\"}";
  free(saida);
  return json;
}

uint32_t agora() { return (uint32_t)time(nullptr); }  // segundos desde 1970 (UTC)

// ---------------------------------------------------------------
//  Camadas 1 + 2 + 3: HTTPS validado + API key + assinatura
// ---------------------------------------------------------------
int enviarLeitura(const char* sensor, float valor) {
  WiFiClientSecure tls;
  tls.setCACert(CA_WORKER);           // Camada 1 (antes: tls.setInsecure();)

  String corpo = String("{\"nome\":\"") + NOME + "\",\"sensor\":\"" + sensor +
                 "\",\"valor\":" + String(valor, 1) + ",\"ts\":" + String(agora()) + "}";
  String assinatura = hmacHex(corpo); // Camada 3: assina EXATAMENTE o corpo enviado

  HTTPClient http;
  http.begin(tls, String(WORKER_URL) + "/insert");
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", API_KEY);          // Camada 2
  http.addHeader("X-Assinatura", assinatura);    // Camada 3
  int codigo = http.POST(corpo);
  String resposta = http.getString();
  http.end();

  Serial.printf("[HTTPS] %s -> %d %s\n", corpo.c_str(), codigo, resposta.c_str());
  Serial.printf("        assinatura: %s\n", assinatura.c_str());
  if (codigo < 0) {
    char erro[120];
    tls.lastError(erro, sizeof(erro));
    Serial.printf("        erro TLS: %s\n", erro);
  }
  return codigo;
}

// ---------------------------------------------------------------
//  Bonus: comandos assinados.  Formato:  comando|ts|assinatura
//  ex.:  led:ON|1791300000|9f2c...   (assinatura = HMAC de "led:ON|1791300000")
// ---------------------------------------------------------------
void responder(const String& texto) {
  Serial.println("[CMD] " + texto);
  mqtt.publish(T_STATUS.c_str(), texto.c_str());
}

void aoReceber(char* topico, byte* payload, unsigned int len) {
  String msg;
  for (unsigned int i = 0; i < len; i++) msg += (char)payload[i];
  Serial.printf("[MQTT] recebido em %s: %s\n", topico, msg.c_str());

  int p1 = msg.indexOf('|');
  int p2 = msg.lastIndexOf('|');
  if (p1 < 0 || p2 <= p1) { responder("RECUSADO: sem assinatura -> " + msg); return; }

  String cmd   = msg.substring(0, p1);
  String tsTxt = msg.substring(p1 + 1, p2);
  String sig   = msg.substring(p2 + 1);
  sig.toLowerCase();

  if (!iguais(sig, hmacHex(cmd + "|" + tsTxt))) { responder("RECUSADO: assinatura invalida"); return; }

  uint32_t ts = strtoul(tsTxt.c_str(), NULL, 10);
  uint32_t t  = agora();
  if (ts + JANELA_CMD_S < t || ts > t + JANELA_CMD_S) { responder("RECUSADO: comando expirado"); return; }
  if (ts <= ultimoTsCmd) { responder("RECUSADO: replay (comando repetido)"); return; }
  ultimoTsCmd = ts;

  if (cmd == "led:ON" || cmd == "led:OFF") {
    ledOn = (cmd == "led:ON");
    digitalWrite(LED, ledOn ? HIGH : LOW);
    responder("OK: " + cmd);
  } else {
    responder("RECUSADO: comando desconhecido (" + cmd + ")");
  }
}

// ---------------------------------------------------------------
//  Conexoes
// ---------------------------------------------------------------
// Tenta conectar no broker ate 'tentativas' vezes. Devolve se conseguiu.
// NAO fica preso pra sempre: se o broker nao responder, a estacao continua
// mandando as leituras pelo HTTPS, que e' o que alimenta o Worker.
bool conectarMqtt(int tentativas) {
  for (int i = 0; i < tentativas && !mqtt.connected(); i++) {
    Serial.printf("[MQTT] conectando em %s:%d (TLS + login)...", MQTT_HOST, MQTT_PORTA);
    String id = String("esp32-") + NOME + "-" + String(esp_random() % 10000);
    if (mqtt.connect(id.c_str(), MQTT_USER, MQTT_PASS)) {
      Serial.println(" ok");
      mqtt.subscribe(T_CMD.c_str());
      return true;
    }
    char erro[120];
    tlsMqtt.lastError(erro, sizeof(erro));
    Serial.printf(" falhou rc=%d | TLS: %s\n", mqtt.state(), erro);
    delay(3000);
  }
  return mqtt.connected();
}

// TLS e assinatura dependem do relogio certo, mas esperar PARA SEMPRE pelo
// NTP deixa a estacao morta e muda. Espera limitada: se falhar, segue em
// frente - o Worker vai recusar com "expirada", e esse 401 na tabela
// 'tentativas' e' justamente o diagnostico de que o NTP nao subiu.
bool sincronizarRelogio() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");   // UTC
  Serial.print("[NTP] sincronizando relogio");
  unsigned long limite = millis() + 30000;             // 30 s, nao infinito
  while (agora() < 1700000000UL && millis() < limite) { delay(300); Serial.print("."); }
  bool ok = agora() >= 1700000000UL;
  Serial.printf(" %s (%lu)\n", ok ? "ok" : "FALHOU (seguindo assim mesmo)", (unsigned long)agora());
  return ok;
}

// ---------------------------------------------------------------
//  PROVA DA CAMADA 1 (Passo 4)
//  Faz um GET /resumo pelo HTTPS so para exercitar o handshake TLS:
//  com a CA certa o handshake fecha e o Worker responde; com a CA
//  errada o mbedtls recusa antes de mandar qualquer byte.
//  Usa rota de LEITURA de proposito: nao grava nada no banco.
// ---------------------------------------------------------------
void provaTLS(const char* rotulo, const char* ca) {
  WiFiClientSecure tls;
  tls.setCACert(ca);
  HTTPClient http;
  http.begin(tls, String(WORKER_URL) + "/resumo");
  int codigo = http.GET();
  Serial.printf("[TLS %s] GET /resumo -> %d
", rotulo, codigo);
  if (codigo < 0) {
    char erro[160];
    tls.lastError(erro, sizeof(erro));
    Serial.printf("                erro: %s
", erro);
  } else {
    String corpo = http.getString();
    Serial.printf("                corpo: %s
", corpo.substring(0, 90).c_str());
  }
  http.end();
}

void setup() {
  Serial.begin(115200);
  pinMode(LED, OUTPUT);
  dht.begin();

  if (!hexParaBytes(CHAVE_AES_HEX, chaveAES, sizeof(chaveAES))) {
    Serial.println("CHAVE_AES_HEX invalida: precisa ter 32 caracteres hexadecimais.");
    while (true) delay(1000);
  }

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[WiFi] conectando");
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
  Serial.printf(" ok | IP=%s | RSSI=%d dBm\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());

  sincronizarRelogio();

  // Prova da Camada 1: com a CA certa deve responder; com a errada deve falhar
  provaTLS("CA certa ", CA_WORKER);
  provaTLS("CA ERRADA", CA_MOSQUITTO);

  tlsMqtt.setCACert(CA_MOSQUITTO);   // Camada 1 no MQTT (antes: porta 1883, sem TLS)
  mqtt.setServer(MQTT_HOST, MQTT_PORTA);
  mqtt.setBufferSize(1024);          // mensagem cifrada e' maior que o padrao (256)
  mqtt.setCallback(aoReceber);
  conectarMqtt(1);                   // tenta uma vez; nao trava o setup se falhar
}

void loop() {
  // Reconexao do MQTT espacada: cada tentativa de TLS que falha bloqueia o
  // loop por mais de um minuto. Tentando de 20 em 20 s, a estacao passava
  // quase todo o tempo presa no handshake, e a leitura do DHT - que depende
  // de timing de microssegundo - falhava junto. Com 5 minutos, o ciclo normal
  // (ler o sensor e mandar pro Worker) roda sem ser atropelado.
  if (!mqtt.connected() && millis() - ultimaTentativaMqtt >= RETRY_MQTT_MS) {
    ultimaTentativaMqtt = millis();
    conectarMqtt(1);
  }
  if (mqtt.connected()) mqtt.loop();

  if (millis() - ultimo >= INTERVALO_MS) {
    ultimo = millis();
    float t = dht.readTemperature();
    float h = dht.readHumidity();
    if (isnan(t) || isnan(h)) { Serial.println("[DHT] falha na leitura"); return; }

    // Camadas 1-3: grava no Worker
    enviarLeitura("temp", t);
    enviarLeitura("umid", h);

    // Camada 4: publica no MQTT so a versao CIFRADA
    String claro = "{\"temp\":" + String(t, 1) + ",\"umid\":" + String(h, 1) +
                   ",\"led\":\"" + (ledOn ? "ON" : "OFF") + "\",\"ts\":" + String(agora()) + "}";
    String cifrado = cifrarCofre(claro);
    Serial.println("[COFRE] claro  : " + claro);
    Serial.println("[COFRE] cifrado: " + cifrado);
    if (mqtt.connected()) mqtt.publish(T_COFRE.c_str(), cifrado.c_str());
    else                  Serial.println("[COFRE] MQTT desconectado: nao publicado");
  }
}
