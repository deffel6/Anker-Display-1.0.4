/*
╔═════════════════════════════════════════════════════════════╗
║  Anker Solix Display – ESP32-C3 + GC9A01A 240x240 rund      ║
║  Version 1.0.3                                              ║
║  Änderungen ggü. 1.0.2:                                     ║
║   - GPIO9-Reset entfernt (nicht zugänglich im Gehäuse)      ║
║   - Bei falschem Anker-Login: Korrektur-Formular auf der    ║
║     Heimnetz-IP statt "neu flashen"                         ║
╚═════════════════════════════════════════════════════════════╝
*/

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include "time.h"
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#define LGFX_USE_V1
#include <LovyanGFX.hpp>

#define AP_SSID        "Anker-Display-Setup"
#define AP_IP          "192.168.4.1"
#define FETCH_INTERVAL  300000  // 5 Minuten

// Batteriekapazitaet ist fest im Code hinterlegt (kein Eingabefeld mehr
// im Setup-Formular). Bei Bedarf hier anpassen.
#define BATT_CAP_WH     2700

static const char* ANKER_HOST = "https://ankerpower-api-eu.anker.com";
static const char* SERVER_PUBKEY_HEX =
  "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a3"
  "868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076";

// ─────────────────────────────────────────────────────────────────────────────
// DISPLAY
// ─────────────────────────────────────────────────────────────────────────────
class LGFX : public lgfx::LGFX_Device {
  lgfx::Panel_GC9A01 _panel;
  lgfx::Bus_SPI      _bus;
  lgfx::Light_PWM    _light;
public:
  LGFX() {
    { auto c=_bus.config(); c.spi_host=SPI2_HOST; c.spi_mode=0;
      c.freq_write=40000000; c.freq_read=16000000;
      c.spi_3wire=true; c.use_lock=true; c.dma_channel=SPI_DMA_CH_AUTO;
      c.pin_sclk=6; c.pin_mosi=7; c.pin_miso=-1; c.pin_dc=2;
      _bus.config(c); _panel.setBus(&_bus); }
    { auto c=_panel.config(); c.pin_cs=10; c.pin_rst=1; c.pin_busy=-1;
      c.panel_width=240; c.panel_height=240; c.invert=true; c.rgb_order=false;
      _panel.config(c); }
    { auto c=_light.config(); c.pin_bl=3; c.invert=false;
      c.freq=44100; c.pwm_channel=7;
      _light.config(c); _panel.setLight(&_light); }
    setPanel(&_panel);
  }
};
static LGFX lcd;
static LGFX_Sprite spr(&lcd);

#define C_WHITE  lcd.color888(255,255,255)
#define C_GRAY   lcd.color888(120,120,120)
#define C_RED    lcd.color888(255, 60, 60)
#define C_GREEN  lcd.color888(  0,255,120)
#define C_YELLOW lcd.color888(255,210,  0)
#define C_BLUE   lcd.color888(  0,170,255)
#define C_BLACK  lcd.color888(  0,  0,  0)
#define C_ORANGE lcd.color888(255,140,  0)

// ─────────────────────────────────────────────────────────────────────────────
// GLOBALE OBJEKTE
// ─────────────────────────────────────────────────────────────────────────────
Preferences prefs;
WebServer   server(80);
DNSServer   dns;

struct Config {
  String wifiSsid, wifiPass, ankerEmail, ankerPass;
  String siteId, siteName;
};
static Config cfg;

struct AnkerData {
  float solar_w=0, battery_wh=0, battery_pct=0;
  float home_w=0, grid_w=0, batt_in_w=0, batt_out_w=0;
  bool  valid=false;
};
static AnkerData gData;

static String        gAuthToken   = "";
static String        gGtoken      = "";
static String        gSiteId      = "";
static unsigned long gTokenExpiry = 0;
static uint8_t gSharedSecret[32];
static uint8_t gClientPubKey[65];
static bool    gEcdhReady = false;

struct SiteEntry { String id; String name; };
static SiteEntry gSiteList[10];
static int       gSiteCount = 0;

// true = Fix-Portal (WLAN steht schon, nur Anker-Daten korrigieren)
static bool gFixMode = false;

// ─────────────────────────────────────────────────────────────────────────────
// HILFSFUNKTIONEN
// ─────────────────────────────────────────────────────────────────────────────
static String bytesToHex(const uint8_t* d, size_t n) {
  String s; s.reserve(n*2);
  for(size_t i=0;i<n;i++){char b[3];sprintf(b,"%02x",d[i]);s+=b;}
  return s;
}
static bool hexToBytes(const char* hex, uint8_t* out, size_t n) {
  if(strlen(hex)!=n*2) return false;
  for(size_t i=0;i<n;i++){char t[3]={hex[i*2],hex[i*2+1],0};out[i]=(uint8_t)strtol(t,nullptr,16);}
  return true;
}
static String md5Hex(const String& s) {
  uint8_t h[16];
  const mbedtls_md_info_t* info=mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
  mbedtls_md(info,(const uint8_t*)s.c_str(),s.length(),h);
  return bytesToHex(h,16);
}
static String b64Encode(const uint8_t* d, size_t n) {
  size_t len=0; mbedtls_base64_encode(nullptr,0,&len,d,n);
  uint8_t* buf=(uint8_t*)malloc(len+1); if(!buf) return "";
  mbedtls_base64_encode(buf,len,&len,d,n); buf[len]=0;
  String r=(char*)buf; free(buf); return r;
}
static float jF(JsonVariant v) {
  if(v.isNull()) return 0;
  if(v.is<float>()) return v.as<float>();
  if(v.is<int>())   return (float)v.as<int>();
  if(v.is<const char*>()) {
    String s=v.as<String>(); s.replace("W",""); s.trim();
    return s.length()?s.toFloat():0;
  }
  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDH
// ─────────────────────────────────────────────────────────────────────────────
bool ecdhInit() {
  mbedtls_entropy_context  entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_ecp_group        grp;
  mbedtls_mpi              privKey;
  mbedtls_ecp_point        pubKey,serverPt,sharedPt;
  mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&rng);
  mbedtls_ecp_group_init(&grp);   mbedtls_mpi_init(&privKey);
  mbedtls_ecp_point_init(&pubKey);mbedtls_ecp_point_init(&serverPt);
  mbedtls_ecp_point_init(&sharedPt);
  bool ok=false;
  do {
    if(mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,(const uint8_t*)"anker",5)!=0) break;
    if(mbedtls_ecp_group_load(&grp,MBEDTLS_ECP_DP_SECP256R1)!=0) break;
    if(mbedtls_ecp_gen_keypair(&grp,&privKey,&pubKey,mbedtls_ctr_drbg_random,&rng)!=0) break;
    size_t len=0;
    if(mbedtls_ecp_point_write_binary(&grp,&pubKey,MBEDTLS_ECP_PF_UNCOMPRESSED,&len,gClientPubKey,65)!=0||len!=65) break;
    uint8_t serverPub[65];
    if(!hexToBytes(SERVER_PUBKEY_HEX,serverPub,65)) break;
    if(mbedtls_ecp_point_read_binary(&grp,&serverPt,serverPub,65)!=0) break;
    if(mbedtls_ecp_mul(&grp,&sharedPt,&privKey,&serverPt,mbedtls_ctr_drbg_random,&rng)!=0) break;
    uint8_t buf[65]; size_t blen=0;
    if(mbedtls_ecp_point_write_binary(&grp,&sharedPt,MBEDTLS_ECP_PF_UNCOMPRESSED,&blen,buf,65)!=0||blen!=65) break;
    memcpy(gSharedSecret,buf+1,32);
    ok=true;
  } while(false);
  mbedtls_ecp_point_free(&sharedPt); mbedtls_ecp_point_free(&serverPt);
  mbedtls_ecp_point_free(&pubKey);   mbedtls_mpi_free(&privKey);
  mbedtls_ecp_group_free(&grp);      mbedtls_ctr_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
  gEcdhReady=ok;
  if(ok) Serial.printf("[ECDH] OK Secret[:8]=%s\n",bytesToHex(gSharedSecret,8).c_str());
  else   Serial.println("[ECDH] FAILED");
  return ok;
}

String encryptPassword(const String& pw) {
  if(!gEcdhReady) return "";
  size_t pwLen=pw.length(),padByte=16-(pwLen%16),total=pwLen+padByte;
  uint8_t* padded=(uint8_t*)malloc(total);
  uint8_t* enc   =(uint8_t*)malloc(total);
  if(!padded||!enc){free(padded);free(enc);return "";}
  memcpy(padded,pw.c_str(),pwLen);
  memset(padded+pwLen,(uint8_t)padByte,padByte);
  uint8_t iv[16]; memcpy(iv,gSharedSecret,16);
  mbedtls_aes_context aes; mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes,gSharedSecret,256);
  mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_ENCRYPT,total,iv,padded,enc);
  mbedtls_aes_free(&aes); free(padded);
  String r=b64Encode(enc,total); free(enc); return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// KONFIG
// ─────────────────────────────────────────────────────────────────────────────
void loadConfig() {
  prefs.begin("anker",true);
  cfg.wifiSsid  =prefs.getString("wssid",""); cfg.wifiPass  =prefs.getString("wpass","");
  cfg.ankerEmail=prefs.getString("email",""); cfg.ankerPass =prefs.getString("apass","");
  cfg.siteId    =prefs.getString("siteid","");
  cfg.siteName  =prefs.getString("sitename","");
  prefs.end();
  Serial.printf("[Prefs] SSID=%s Email=%s Site=%s BattCap(fest)=%dWh\n",
    cfg.wifiSsid.c_str(),cfg.ankerEmail.c_str(),cfg.siteName.c_str(),BATT_CAP_WH);
}
void saveConfig() {
  prefs.begin("anker",false);
  prefs.putString("wssid",cfg.wifiSsid); prefs.putString("wpass",cfg.wifiPass);
  prefs.putString("email",cfg.ankerEmail); prefs.putString("apass",cfg.ankerPass);
  prefs.putString("siteid",cfg.siteId); prefs.putString("sitename",cfg.siteName);
  prefs.end(); Serial.println("[Prefs] OK");
}
void clearConfig(){prefs.begin("anker",false);prefs.clear();prefs.end();}
bool configComplete(){return cfg.wifiSsid.length()>0&&cfg.ankerEmail.length()>0;}
bool siteSelected()  {return cfg.siteId.length()>0;}

// ─────────────────────────────────────────────────────────────────────────────
// DISPLAY HILFE
// ─────────────────────────────────────────────────────────────────────────────
void dispCenter(int y,const char* txt,uint32_t col,const lgfx::IFont* font){
  lcd.setFont(font);lcd.setTextColor(col,C_BLACK);
  lcd.setTextDatum(lgfx::TC_DATUM);lcd.drawString(txt,120,y);
}
void dispMsg(const char* l1,const char* l2="",uint32_t c1=0,uint32_t c2=0){
  lcd.fillScreen(C_BLACK); if(!c1)c1=C_WHITE; if(!c2)c2=C_GRAY;
  dispCenter(95,l1,c1,&fonts::FreeSansBold12pt7b);
  if(strlen(l2))dispCenter(130,l2,c2,&fonts::FreeSans9pt7b);
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG-PORTAL HTML
// ─────────────────────────────────────────────────────────────────────────────
String urlDecode(const String& s){
  String out; out.reserve(s.length());
  for(int i=0;i<(int)s.length();i++){
    char c=s[i];
    if(c=='+')out+=' ';
    else if(c=='%'&&i+2<(int)s.length()){
      auto h=[](char x)->int{if(x>='0'&&x<='9')return x-'0';if(x>='A'&&x<='F')return x-'A'+10;if(x>='a'&&x<='f')return x-'a'+10;return 0;};
      out+=(char)(h(s[i+1])*16+h(s[i+2]));i+=2;
    }else out+=c;
  }
  return out;
}

// Batteriekapazitaets-Eingabefeld entfernt - der Wert ist jetzt fest als
// BATT_CAP_WH oben im Code hinterlegt.
const char HTML_PAGE[] PROGMEM = R"HTML(
<!DOCTYPE html><html lang="de"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anker Display Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#eee;display:flex;justify-content:center;padding:20px}
.card{background:#1a1a1a;border-radius:16px;padding:28px;width:100%;max-width:420px;box-shadow:0 4px 24px #0008}
h1{font-size:1.4rem;margin-bottom:6px;color:#fff}.sub{color:#888;font-size:.85rem;margin-bottom:24px}
.section{background:#111;border-radius:10px;padding:16px;margin-bottom:16px}
.section h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:#f0a500;margin-bottom:12px}
label{display:block;font-size:.85rem;color:#aaa;margin-bottom:4px;margin-top:10px}label:first-of-type{margin-top:0}
input{width:100%;padding:10px 12px;background:#222;border:1px solid #333;border-radius:8px;color:#fff;font-size:.95rem;outline:none}
input:focus{border-color:#f0a500}.hint{font-size:.75rem;color:#666;margin-top:3px}
.pw{position:relative}.pw input{padding-right:44px}
.pw .eye{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:36px;height:36px;
background:none;border:none;color:#888;font-size:1.1rem;cursor:pointer;padding:0;margin:0;width:36px}
button{width:100%;padding:14px;background:#f0a500;border:none;border-radius:10px;color:#000;font-size:1rem;font-weight:700;cursor:pointer;margin-top:8px}
</style>
<script>
function tg(id,btn){var i=document.getElementById(id);
if(i.type==='password'){i.type='text';btn.textContent='\uD83D\uDE48';}
else{i.type='password';btn.textContent='\uD83D\uDC41';}}
</script></head><body><div class="card">
<h1>&#9889; Anker Display Setup</h1><p class="sub">Zugangsdaten konfigurieren</p>
<form method="POST" action="/save">
  <div class="section"><h2>&#128246; WLAN</h2>
    <label>SSID</label><input name="wssid" type="text" value="__WSSID__" required>
    <label>Passwort</label>
    <div class="pw"><input id="wp" name="wpass" type="password" value="">
    <button type="button" class="eye" onclick="tg('wp',this)">&#128065;</button></div></div>
  <div class="section"><h2>&#128267; Anker Cloud</h2>
    <label>E-Mail</label><input name="email" type="email" value="__EMAIL__" required>
    <label>Passwort</label>
    <div class="pw"><input id="ap" name="apass" type="password" value="" required>
    <button type="button" class="eye" onclick="tg('ap',this)">&#128065;</button></div></div>
  <button type="submit">&#128190; Speichern &amp; Neustart</button>
</form></div></body></html>
)HTML";

// Reduziertes Formular fuer den Fix-Modus: WLAN laeuft bereits,
// also nur die Anker-Zugangsdaten abfragen.
const char HTML_PAGE_FIX[] PROGMEM = R"HTML(
<!DOCTYPE html><html lang="de"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anker Login korrigieren</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#eee;display:flex;justify-content:center;padding:20px}
.card{background:#1a1a1a;border-radius:16px;padding:28px;width:100%;max-width:420px;box-shadow:0 4px 24px #0008}
h1{font-size:1.4rem;margin-bottom:6px;color:#fff}.sub{color:#f66;font-size:.85rem;margin-bottom:24px}
.section{background:#111;border-radius:10px;padding:16px;margin-bottom:16px}
.section h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:#f0a500;margin-bottom:12px}
label{display:block;font-size:.85rem;color:#aaa;margin-bottom:4px;margin-top:10px}label:first-of-type{margin-top:0}
input{width:100%;padding:10px 12px;background:#222;border:1px solid #333;border-radius:8px;color:#fff;font-size:.95rem;outline:none}
input:focus{border-color:#f0a500}
.pw{position:relative}.pw input{padding-right:44px}
.pw .eye{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:36px;height:36px;
background:none;border:none;color:#888;font-size:1.1rem;cursor:pointer;padding:0;margin:0}
button{width:100%;padding:14px;background:#f0a500;border:none;border-radius:10px;color:#000;font-size:1rem;font-weight:700;cursor:pointer;margin-top:8px}
</style>
<script>
function tg(id,btn){var i=document.getElementById(id);
if(i.type==='password'){i.type='text';btn.textContent='\uD83D\uDE48';}
else{i.type='password';btn.textContent='\uD83D\uDC41';}}
</script></head><body><div class="card">
<h1>&#9889; Anker Login korrigieren</h1>
<p class="sub">Login fehlgeschlagen &ndash; bitte Zugangsdaten pruefen</p>
<form method="POST" action="/save">
  <div class="section"><h2>&#128267; Anker Cloud</h2>
    <label>E-Mail</label><input name="email" type="email" value="__EMAIL__" required>
    <label>Passwort</label>
    <div class="pw"><input id="ap" name="apass" type="password" value="" required>
    <button type="button" class="eye" onclick="tg('ap',this)">&#128065;</button></div></div>
  <button type="submit">&#128190; Speichern &amp; Verbinden</button>
</form></div></body></html>
)HTML";

const char HTML_SAVED[] PROGMEM = R"HTML(
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#0a0a0a;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh}
.c{background:#1a3a1a;border:1px solid #2a6a2a;border-radius:16px;padding:40px;text-align:center;max-width:340px}
h1{color:#4caf50;font-size:2rem;margin-bottom:12px}p{color:#aaa}</style>
</head><body><div class="c"><h1>&#10004;</h1><h2>Gespeichert!</h2><p>ESP startet in 3s neu.</p></div></body></html>
)HTML";

// Site-Auswahl-Seite - erreichbar ueber die Heimnetz-IP, nachdem das
// Board sich erfolgreich mit dem Internet verbunden und bei Anker
// eingeloggt hat.
String buildSiteSelectPage() {
  String p = F("<!DOCTYPE html><html lang='de'><head>"
    "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Anlage waehlen</title><style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#eee;display:flex;justify-content:center;padding:20px}"
    ".card{background:#1a1a1a;border-radius:16px;padding:28px;width:100%;max-width:420px;box-shadow:0 4px 24px #0008}"
    "h1{font-size:1.4rem;margin-bottom:6px;color:#fff}.sub{color:#888;font-size:.85rem;margin-bottom:24px}"
    ".site-btn{display:block;width:100%;padding:16px;background:#111;border:1px solid #2a2a3a;"
    "border-radius:12px;color:#fff;text-decoration:none;margin-bottom:12px;text-align:left;"
    "cursor:pointer;transition:border-color .2s}"
    ".site-btn:hover{border-color:#f0a500}"
    ".site-name{font-size:1rem;font-weight:600;color:#fff}"
    ".site-id{font-size:.72rem;color:#555;margin-top:4px;word-break:break-all}"
    "</style></head><body><div class='card'>"
    "<h1>&#128267; Anlage waehlen</h1>"
    "<p class='sub'>Welche Anlage soll angezeigt werden?</p>");

  for(int i=0;i<gSiteCount;i++){
    p += "<a class='site-btn' href='/selectsite?id=";
    p += gSiteList[i].id;
    p += "'><div class='site-name'>&#9889; ";
    p += gSiteList[i].name;
    p += "</div><div class='site-id'>";
    p += gSiteList[i].id;
    p += "</div></a>";
  }
  if(gSiteCount==0){
    p += "<p style='color:#888'>Keine Anlagen gefunden. Pruefe die Zugangsdaten "
         "oder warte noch ein paar Sekunden und lade die Seite neu.</p>";
  }
  p += "</div></body></html>";
  return p;
}

void handleRoot(){
  if(gFixMode){
    // WLAN steht schon - nur Anker-Daten abfragen
    String p=FPSTR(HTML_PAGE_FIX);
    p.replace("__EMAIL__",cfg.ankerEmail);
    server.send(200,"text/html; charset=utf-8",p);
    return;
  }
  String p=FPSTR(HTML_PAGE);
  p.replace("__WSSID__",cfg.wifiSsid);p.replace("__EMAIL__",cfg.ankerEmail);
  server.send(200,"text/html; charset=utf-8",p);
}

void handleSites(){
  server.send(200,"text/html; charset=utf-8",buildSiteSelectPage());
}

void handleSelectSite(){
  String id=server.arg("id");
  String name="";
  for(int i=0;i<gSiteCount;i++){
    if(gSiteList[i].id==id){name=gSiteList[i].name;break;}
  }
  if(id.length()==0){server.sendHeader("Location","/sites");server.send(302);return;}

  cfg.siteId=id;
  cfg.siteName=name;
  saveConfig();

  server.send(200,"text/html; charset=utf-8",FPSTR(HTML_SAVED));
  delay(2500);
  ESP.restart();
}

// Vorwaertsdeklarationen, da diese Funktionen erst weiter unten im Code
// definiert sind, aber bereits in handleSave() benutzt werden.
String httpsPost(const String& path,const String& body,
                 const String& token="",const String& gtoken="");
bool ankerLogin();
bool ecdhInit();

void handleSave(){
  if(server.method()==HTTP_POST){
    // Im Fix-Modus schickt das Formular keine WLAN-Felder mit -
    // bestehende WLAN-Daten dann NICHT ueberschreiben.
    if(server.hasArg("wssid")&&server.arg("wssid").length()>0){
      cfg.wifiSsid=urlDecode(server.arg("wssid"));
      cfg.wifiPass=urlDecode(server.arg("wpass"));
    }
    cfg.ankerEmail=urlDecode(server.arg("email")); cfg.ankerPass=urlDecode(server.arg("apass"));
    saveConfig();

    // Sofort eine Antwort senden, BEVOR wir versuchen uns mit dem Heimnetz
    // zu verbinden - sonst haengt der Browser, waehrend der ESP-Hotspot
    // (vom Handy aus gesehen) "kein Internet" zu haben scheint und das
    // Handy von sich aus die WLAN-Verbindung wechselt.
    if(gFixMode){
      // Wir sind schon im Heimnetz - direkt auf die Anlagen-Auswahl verweisen.
      server.send(200,"text/html; charset=utf-8",
        F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
          "<style>body{font-family:sans-serif;background:#0a0a0a;color:#eee;"
          "display:flex;justify-content:center;align-items:center;height:100vh;padding:20px}"
          ".c{text-align:center;max-width:360px}"
          "h2{color:#f0a500}p{color:#aaa;margin-top:12px;line-height:1.5}"
          "a{color:#4caf50;font-size:1.1rem;font-weight:700}"
          "</style></head><body><div class='c'>"
          "<h2>&#8987; Pruefe Anker-Login...</h2>"
          "<p>Warte ca. 10 Sekunden, dann hier weiter:</p>"
          "<p><a href='/sites'>Anlage auswaehlen</a></p>"
          "<p>Falls das Display wieder &quot;Login falsch&quot; zeigt, "
          "lade diese Seite neu und pruefe die Daten nochmal.</p>"
          "</div></body></html>"));
    }
    else server.send(200,"text/html; charset=utf-8",
      F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<style>body{font-family:sans-serif;background:#0a0a0a;color:#eee;"
        "display:flex;justify-content:center;align-items:center;height:100vh;padding:20px}"
        ".c{text-align:center;max-width:360px}"
        "h2{color:#f0a500}p{color:#aaa;margin-top:12px;line-height:1.5}"
        ".ip{color:#4caf50;font-size:1.3rem;font-weight:700;margin-top:16px}"
        "</style></head><body><div class='c'>"
        "<h2>&#8987; Verbinde mit Internet...</h2>"
        "<p>Das Display verbindet sich jetzt mit deinem Heimnetz und loggt sich bei Anker ein.</p>"
        "<p>Schau auf das runde Display - dort erscheint gleich eine IP-Adresse mit Pfad.</p>"
        "<p>Ruf diese Adresse danach im Browser <strong>in deinem normalen WLAN</strong> auf, "
        "um die Anlage auszuwaehlen.</p>"
        "</div></body></html>"));
    delay(300);

    // Im Fix-Modus sind wir bereits im Heimnetz - Verbindungsaufbau
    // nur, wenn wir aus dem Setup-Hotspot kommen.
    if(WiFi.status()!=WL_CONNECTED){
      // AP bleibt aktiv (AP_STA), zusaetzlich mit dem Heimnetz verbinden,
      // damit der Anker-Login (braucht echtes Internet) funktioniert.
      WiFi.mode(WIFI_AP_STA);
      delay(200);
      WiFi.begin(cfg.wifiSsid.c_str(),cfg.wifiPass.c_str());
      Serial.printf("[Save] Verbinde mit Heimnetz '%s'...\n", cfg.wifiSsid.c_str());
      int tries=0;
      while(WiFi.status()!=WL_CONNECTED&&tries<40){delay(500);Serial.print(".");tries++;}
      Serial.println();
    }

    if(WiFi.status()!=WL_CONNECTED){
      Serial.println("[Save] Heimnetz-Verbindung fehlgeschlagen!");
      dispMsg("WLAN-Fehler!","Neu starten & Setup wiederholen",C_RED,C_YELLOW);
      return;
    }

    String myIp = WiFi.localIP().toString();
    Serial.printf("[Save] Verbunden! IP=%s\n", myIp.c_str());
    Serial.printf("[Save] Im Browser oeffnen: http://%s/sites\n", myIp.c_str());

    // Komplette URL inkl. /sites direkt aufs Display, damit man nicht
    // selbst draufkommen muss, den Pfad anzuhaengen.
    lcd.fillScreen(C_BLACK);
    dispCenter(70, "Im Browser oeffnen:", C_GREEN, &fonts::FreeSansBold12pt7b);
    dispCenter(105, myIp.c_str(),         C_YELLOW,&fonts::FreeSans9pt7b);
    dispCenter(130, "/sites",             C_YELLOW,&fonts::FreeSans9pt7b);
    dispCenter(165, "(im Heimnetz, nicht", C_GRAY,  &fonts::FreeSans9pt7b);
    dispCenter(185, "im Setup-Hotspot!)",  C_GRAY,  &fonts::FreeSans9pt7b);

    configTzTime("CET-1CEST,M3.5.0,M10.5.0/3","pool.ntp.org","1.de.pool.ntp.org");
    delay(1000);

    ecdhInit();
    if(ankerLogin()){
      String resp=httpsPost("power_service/v1/site/get_site_list",
                            "{\"page\":1,\"size\":10}",gAuthToken,gGtoken);
      DynamicJsonDocument doc(4096);
      if(resp.length()&&deserializeJson(doc,resp)==DeserializationError::Ok){
        auto sites=doc["data"]["site_list"];
        gSiteCount=0;
        for(auto s:sites.as<JsonArray>()){
          if(gSiteCount>=10) break;
          gSiteList[gSiteCount].id  =s["site_id"].as<String>();
          gSiteList[gSiteCount].name=s["site_name"].as<String>();
          gSiteCount++;
        }
        Serial.printf("[Save] %d Sites gefunden\n", gSiteCount);
      }
    } else {
      // Login falsch: Hinweis aufs Display - das Formular laeuft ja noch
      // (AP + Heimnetz-IP), also kann man die Daten direkt neu eingeben.
      Serial.println("[Save] Anker-Login fehlgeschlagen!");
      lcd.fillScreen(C_BLACK);
      dispCenter( 55,"Anker-Login",           C_RED,   &fonts::FreeSansBold12pt7b);
      dispCenter( 82,"falsch!",               C_RED,   &fonts::FreeSansBold12pt7b);
      dispCenter(118,"Im Browser oeffnen:",   C_GRAY,  &fonts::FreeSans9pt7b);
      dispCenter(140,myIp.c_str(),            C_YELLOW,&fonts::FreeSansBold12pt7b);
      dispCenter(172,"und Daten neu eingeben",C_GRAY,  &fonts::FreeSans9pt7b);
    }
  }else{server.sendHeader("Location","/");server.send(302);}
}
void handleNotFound(){server.sendHeader("Location","http://192.168.4.1/");server.send(302);}

void startConfigPortal(){
  Serial.println("[AP] Start...");
  lcd.fillScreen(C_BLACK);
  dispCenter(50,"Setup-Modus",    C_ORANGE,&fonts::FreeSansBold12pt7b);
  dispCenter(80,"WLAN verbinden:",C_GRAY,  &fonts::FreeSans9pt7b);
  dispCenter(100,AP_SSID,         C_WHITE, &fonts::FreeSans9pt7b);
  dispCenter(125,"Dann Browser:", C_GRAY,  &fonts::FreeSans9pt7b);
  dispCenter(145,AP_IP,           C_YELLOW,&fonts::FreeSans9pt7b);
  WiFi.mode(WIFI_AP); WiFi.softAP(AP_SSID);
  IPAddress ip(192,168,4,1),gw(192,168,4,1),sn(255,255,255,0);
  WiFi.softAPConfig(ip,gw,sn); dns.start(53,"*",ip);
  server.on("/",          HTTP_GET,  handleRoot);
  server.on("/save",      HTTP_POST, handleSave);
  server.on("/sites",     HTTP_GET,  handleSites);
  server.on("/selectsite",HTTP_GET,  handleSelectSite);
  server.onNotFound(handleNotFound); server.begin();
  while(true){dns.processNextRequest();server.handleClient();delay(5);}
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX-PORTAL
// Anker-Login fehlgeschlagen, aber WLAN steht: Konfig-Formular auf der
// Heimnetz-IP anbieten, damit man die Anker-Daten korrigieren kann,
// ohne neu zu flashen oder an den Setup-Hotspot zu muessen.
// ─────────────────────────────────────────────────────────────────────────────
void startFixPortal(){
  gFixMode = true;
  String myIp = WiFi.localIP().toString();
  Serial.printf("[Fix] Anker-Login falsch. Formular auf http://%s/\n", myIp.c_str());
  lcd.fillScreen(C_BLACK);
  dispCenter( 55,"Anker-Login",           C_RED,   &fonts::FreeSansBold12pt7b);
  dispCenter( 82,"falsch!",               C_RED,   &fonts::FreeSansBold12pt7b);
  dispCenter(118,"Im Browser oeffnen:",   C_GRAY,  &fonts::FreeSans9pt7b);
  dispCenter(140,myIp.c_str(),            C_YELLOW,&fonts::FreeSansBold12pt7b);
  dispCenter(172,"und Daten neu eingeben",C_GRAY,  &fonts::FreeSans9pt7b);
  server.on("/",          HTTP_GET,  handleRoot);
  server.on("/save",      HTTP_POST, handleSave);
  server.on("/sites",     HTTP_GET,  handleSites);
  server.on("/selectsite",HTTP_GET,  handleSelectSite);
  server.onNotFound([](){server.sendHeader("Location","/");server.send(302);});
  server.begin();
  while(true){server.handleClient();delay(5);}
}

// ─────────────────────────────────────────────────────────────────────────────
// ANKER HTTP
// ─────────────────────────────────────────────────────────────────────────────
String httpsPost(const String& path,const String& body,
                 const String& token,const String& gtoken){
  WiFiClientSecure client; client.setInsecure();
  HTTPClient http;
  http.begin(client,String(ANKER_HOST)+"/"+path);
  http.addHeader("content-type",  "application/json");
  http.addHeader("model-type",    "DESKTOP");
  http.addHeader("app-name",      "anker_power");
  http.addHeader("os-type",       "android");
  http.addHeader("country",       "DE");
  http.addHeader("timezone",      "GMT+02:00");
  if(token.length()){
    http.addHeader("x-auth-token",token);
    http.addHeader("gtoken",gtoken.length()?gtoken:token);
  }
  http.setTimeout(15000);
  int code=http.POST(body);
  String resp=http.getString();
  Serial.printf("[API] %d /%s\n",code,path.c_str());
  if(code!=200) Serial.printf("[API] Resp: %.200s\n",resp.c_str());
  http.end();
  return (code==200)?resp:"";
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────────────────────────────────────
bool ankerLogin(){
  Serial.println("[Auth] Login...");
  if(!gEcdhReady){Serial.println("[Auth] ECDH not ready");return false;}
  String encPw=encryptPassword(cfg.ankerPass);
  if(encPw.isEmpty()){Serial.println("[Auth] Encrypt failed");return false;}
  char tsMs[21];
  snprintf(tsMs,sizeof(tsMs),"%llu",(unsigned long long)time(nullptr)*1000ULL);
  time_t now=time(nullptr); struct tm tiL,tiU;
  localtime_r(&now,&tiL); gmtime_r(&now,&tiU);
  long tzMs=(long)(difftime(mktime(&tiL),mktime(&tiU))*1000.0);
  DynamicJsonDocument doc(512);
  doc["ab"]="DE"; doc["enc"]=0;
  doc["email"]=cfg.ankerEmail; doc["password"]=encPw;
  doc["time_zone"]=tzMs; doc["transaction"]=String(tsMs);
  doc.createNestedObject("client_secret_info")["public_key"]=bytesToHex(gClientPubKey,65);
  String body; serializeJson(doc,body);
  String resp=httpsPost("passport/login",body);
  if(resp.isEmpty()){Serial.println("[Auth] No response");return false;}
  DynamicJsonDocument rd(2048);
  if(deserializeJson(rd,resp)!=DeserializationError::Ok){Serial.println("[Auth] JSON error");return false;}
  int code=rd["code"]|-1;
  if(code!=0){Serial.printf("[Auth] Error %d: %s\n",code,rd["msg"].as<const char*>());return false;}
  gAuthToken=rd["data"]["auth_token"].as<String>();
  gGtoken=md5Hex(rd["data"]["user_id"].as<String>());
  gTokenExpiry=millis()+23UL*3600*1000;
  Serial.println("[Auth] OK");
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// SITE + DATEN
// ─────────────────────────────────────────────────────────────────────────────
bool fetchSiteId(){
  String resp=httpsPost("power_service/v1/site/get_site_list",
                        "{\"page\":1,\"size\":10}",gAuthToken,gGtoken);
  if(resp.isEmpty()) return false;
  DynamicJsonDocument doc(4096);
  if(deserializeJson(doc,resp)!=DeserializationError::Ok) return false;
  auto sites=doc["data"]["site_list"];
  if(!sites||sites.size()==0){Serial.println("[API] No sites");return false;}
  for(auto s:sites.as<JsonArray>())
    Serial.printf("[API] Site: %s  %s\n",s["site_id"].as<const char*>(),s["site_name"].as<const char*>());
  gSiteId=sites[0]["site_id"].as<String>();
  Serial.printf("[API] SiteID: %s\n",gSiteId.c_str());
  return true;
}

bool fetchData(){
  if(gAuthToken.isEmpty()) return false;
  if(millis()>gTokenExpiry){Serial.println("[Auth] Re-Login...");if(!ankerLogin())return false;}
  if(gSiteId.isEmpty()){
    // Im Normalbetrieb nutzen wir die im Setup ausgewaehlte Site.
    if(cfg.siteId.length()>0) gSiteId=cfg.siteId;
    else if(!fetchSiteId()) return false;
  }
  String resp=httpsPost("power_service/v1/site/get_scen_info",
    "{\"site_id\":\""+gSiteId+"\"}",gAuthToken,gGtoken);
  if(resp.isEmpty()) return false;
  DynamicJsonDocument doc(24576);
  if(deserializeJson(doc,resp)!=DeserializationError::Ok) return false;
  int apiCode=doc["code"]|-1;
  if(apiCode!=0){if(apiCode==401||apiCode==9999)gAuthToken="";return false;}
  auto sb=doc["data"]["solarbank_info"];
  auto gi=doc["data"]["grid_info"];
  float pv=jF(sb["total_photovoltaic_power"]);
  if(pv==0) pv=jF(sb["solar_power"]);
  float batt_pct=0;
  if(sb["solarbank_list"].is<JsonArray>()&&sb["solarbank_list"].size()>0)
    batt_pct=jF(sb["solarbank_list"][0]["battery_power"]);
  if(batt_pct==0) batt_pct=jF(sb["total_battery_power"]);
  float batt_in=jF(sb["total_charging_power"]);
  float batt_out=jF(sb["battery_discharge_power"]);
  if(batt_in<0){batt_out=-batt_in;batt_in=0;}
  float home=jF(sb["to_home_load"]);
  float grid=jF(gi["grid_to_home_power"])-jF(gi["photovoltaic_to_grid_power"]);
  gData={pv,(batt_pct/100.f)*BATT_CAP_WH,batt_pct,home,
         fabsf(grid)<0.5f?0.f:grid,
         batt_in<0.5f?0.f:batt_in,
         batt_out<0.5f?0.f:batt_out,true};
  Serial.printf("[Data] PV=%.0fW SOC=%.0f%% Grid=%.0fW\n",
    gData.solar_w,gData.battery_pct,gData.grid_w);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// DISPLAY ZEICHNEN
// ─────────────────────────────────────────────────────────────────────────────
void drawDisplay(){
  bool useSprite = spr.getBuffer() != nullptr;
  lgfx::LovyanGFX* g = useSprite ? (lgfx::LovyanGFX*)&spr : (lgfx::LovyanGFX*)&lcd;

  g->fillScreen(C_BLACK);
  g->setTextDatum(lgfx::TC_DATUM);
  char buf[16];

  struct tm ti;
  if(getLocalTime(&ti)){
    char t[6],d[11];
    strftime(t,sizeof(t),"%H:%M",&ti);
    strftime(d,sizeof(d),"%d.%m.%Y",&ti);
    g->setFont(&fonts::FreeSansBold18pt7b);
    g->setTextColor(C_WHITE,C_BLACK);
    g->drawString(t,120,10);
    g->setFont(&fonts::FreeSans9pt7b);
    g->setTextColor(C_GRAY,C_BLACK);
    g->drawString(d,120,56);
  }

  if(!gData.valid){
    g->setFont(&fonts::FreeSansBold12pt7b);
    g->setTextColor(C_RED,C_BLACK);
    g->drawString("KEIN SIGNAL",120,120);
    g->setFont(&fonts::FreeSans9pt7b);
    g->setTextColor(C_GRAY,C_BLACK);
    g->drawString("Verbinde Anker.",120,150);
    if(useSprite) spr.pushSprite(0,0);
    return;
  }

  uint32_t battCol = gData.battery_pct<20?C_RED:gData.battery_pct<50?C_YELLOW:C_GREEN;
  uint32_t gridCol = C_BLUE; const char* gridLabel="NETZ";
  if     (gData.grid_w> 0.5f){gridCol=C_RED;  gridLabel="BEZUG";}
  else if(gData.grid_w<-0.5f){gridCol=C_GREEN;gridLabel="EINSP";}
  uint32_t flowCol=C_GRAY; const char* flowLabel="--";
  float flowVal=0; bool hasFlow=false;
  if     (gData.batt_in_w >0.5f){flowCol=C_GREEN;flowLabel="EINGANG";flowVal=gData.batt_in_w; hasFlow=true;}
  else if(gData.batt_out_w>0.5f){flowCol=C_RED;  flowLabel="AUSGANG";flowVal=gData.batt_out_w;hasFlow=true;}

  g->setFont(&fonts::FreeSans9pt7b);
  g->setTextColor(C_YELLOW,C_BLACK); g->drawString("PV",      38, 76);
  g->setTextColor(C_GRAY,  C_BLACK); g->drawString("AKKU",   120, 76);
  g->setTextColor(gridCol, C_BLACK); g->drawString(gridLabel, 202, 76);

  snprintf(buf,sizeof(buf),"%.0f",gData.solar_w);
  g->setFont(&fonts::FreeSansBold12pt7b); g->setTextColor(C_WHITE,C_BLACK);
  g->drawString(buf,38,92);
  g->setFont(&fonts::FreeSans9pt7b); g->setTextColor(C_YELLOW,C_BLACK);
  g->drawString("W",38,114);

  snprintf(buf,sizeof(buf),"%d%%",(int)gData.battery_pct);
  g->setFont(&fonts::FreeSansBold18pt7b); g->setTextColor(battCol,C_BLACK);
  g->drawString(buf,120,100);

  snprintf(buf,sizeof(buf),"%.0f",fabsf(gData.grid_w));
  g->setFont(&fonts::FreeSansBold12pt7b); g->setTextColor(C_WHITE,C_BLACK);
  g->drawString(buf,202,92);
  g->setFont(&fonts::FreeSans9pt7b); g->setTextColor(gridCol,C_BLACK);
  g->drawString("W",202,114);

  const int bx=120,by=150;
  g->drawRect(bx-18,by-8,36,16,flowCol);
  g->fillRect(bx+18,by-4,5,8,flowCol);
  if(gData.batt_in_w>0.5f){
    g->fillTriangle(bx,by-20,bx-7,by-10,bx+7,by-10,flowCol);
  }else if(gData.batt_out_w>0.5f){
    g->fillTriangle(bx,by+20,bx-7,by+10,bx+7,by+10,flowCol);
  }else{
    g->drawLine(bx-6,by,bx+6,by,C_GRAY);
  }

  g->setFont(&fonts::FreeSans9pt7b); g->setTextColor(flowCol,C_BLACK);
  g->drawString(flowLabel,120,174);
  g->setFont(&fonts::FreeSansBold12pt7b);
  g->setTextColor(hasFlow?C_WHITE:C_GRAY,C_BLACK);
  snprintf(buf,sizeof(buf),"%.0fW",flowVal);
  g->drawString(buf,120,192);

  if(useSprite) spr.pushSprite(0,0);
}

// ─────────────────────────────────────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────────────────────────────────────
void setup(){
  Serial.begin(115200); delay(300);
  lcd.init(); lcd.setRotation(0); lcd.setBrightness(200); lcd.fillScreen(C_BLACK);
  spr.setColorDepth(8);
  if(!spr.createSprite(240,240)){
    Serial.println("[SPR] RAM zu wenig – kein Sprite");
  } else {
    Serial.println("[SPR] Sprite OK (8bit, 57KB)");
  }

  loadConfig();
  if(!configComplete()||!siteSelected()){startConfigPortal();return;}

  lcd.fillScreen(C_BLACK);
  dispCenter(100,"Verbinde WLAN...",   C_WHITE, &fonts::FreeSans9pt7b);
  dispCenter(125,cfg.wifiSsid.c_str(),C_YELLOW,&fonts::FreeSans9pt7b);
  WiFi.mode(WIFI_STA); WiFi.begin(cfg.wifiSsid.c_str(),cfg.wifiPass.c_str());
  int tries=0;
  while(WiFi.status()!=WL_CONNECTED&&tries<40){delay(500);Serial.print(".");tries++;}
  if(WiFi.status()!=WL_CONNECTED){
    dispMsg("WLAN-Fehler","Konfig pruefen...",C_RED,0);
    delay(3000);startConfigPortal();return;
  }
  Serial.printf("\n[WiFi] %s\n",WiFi.localIP().toString().c_str());
  lcd.fillScreen(C_BLACK);
  dispCenter(90,"WLAN verbunden",                  C_GREEN,&fonts::FreeSansBold12pt7b);
  dispCenter(120,WiFi.localIP().toString().c_str(),C_GRAY, &fonts::FreeSans9pt7b);
  delay(1200);

  configTzTime("CET-1CEST,M3.5.0,M10.5.0/3","pool.ntp.org","1.de.pool.ntp.org");
  Serial.print("[NTP] Warte...");
  struct tm ti; int ntpTries=0;
  while(!getLocalTime(&ti)&&ntpTries<20){delay(500);Serial.print(".");ntpTries++;}
  Serial.println(ntpTries<20?" OK":" Timeout");

  dispCenter(110,"ECDH Init...",C_GRAY,&fonts::FreeSans9pt7b);
  if(!ecdhInit()){dispMsg("ECDH Fehler","Neustart...",C_RED,0);delay(3000);ESP.restart();return;}

  dispMsg("Anker Login...",cfg.siteName.length()>0?cfg.siteName.c_str():cfg.ankerEmail.c_str(),C_WHITE,C_GRAY);
  if(!ankerLogin()){
    // Login falsch: Formular auf der Heimnetz-IP anbieten statt
    // zurueck in den Setup-Hotspot zu zwingen.
    startFixPortal();
    return;
  }
  gSiteId=cfg.siteId;
  fetchData();
  lcd.fillScreen(C_BLACK);
  drawDisplay();
}

// ─────────────────────────────────────────────────────────────────────────────
// LOOP
// ─────────────────────────────────────────────────────────────────────────────
static unsigned long lastFetch=0,lastClock=0;
void loop(){
  unsigned long now=millis();
  if(now-lastFetch>=FETCH_INTERVAL||lastFetch==0){
    if(WiFi.status()!=WL_CONNECTED){WiFi.reconnect();delay(3000);}
    if(!fetchData())gData.valid=false;
    drawDisplay(); lastFetch=now;
  }
  if(now-lastClock>=60000){
    if(gData.valid)drawDisplay();
    lastClock=now;
  }
  delay(100);
}
