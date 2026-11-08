#include "meshcore_link.h"
#include "network.h"
#include "hardware.h"
#include <Preferences.h>
#include <string.h>

extern Preferences prefs;

bool g_meshcoreTransport = false;
static bool s_handshakeSent = false;

static const uint8_t MC_APP2RADIO = 0x3C;
static const uint8_t MC_RADIO2APP = 0x3E;
static const uint8_t MC_CMD_APP_START = 0x01;
static const uint8_t MC_CMD_SEND_CHANNEL_TXT = 0x03;
static const uint8_t MC_CMD_SYNC_NEXT = 0x0A;
static const uint8_t MC_PUSH_MSG_WAITING = 0x83;
static const uint8_t MC_RESP_CHANNEL_MSG = 0x08;
static const uint8_t MC_RESP_CHANNEL_MSG_V3 = 0x11;
static const uint16_t MC_MAX_PAYLOAD = 176;
static const uint16_t MC_MAX_TEXT = 133;

static void mcWriteFrame(const uint8_t *payload, uint16_t len) {
    if (len == 0 || len > MC_MAX_PAYLOAD) return;
    uint8_t hdr[3] = {MC_APP2RADIO, (uint8_t)(len & 0xFF), (uint8_t)(len >> 8)};
    Serial1.write(hdr, 3);
    Serial1.write(payload, len);
    Serial1.flush();
}

static void mcSendAppStart() {
    const char *app = "AntiHunter";
    uint16_t al = (uint16_t)strlen(app);
    uint8_t buf[8 + 16];
    uint16_t n = 0;
    buf[n++] = MC_CMD_APP_START;
    for (int i = 0; i < 7; i++) buf[n++] = 0x00;
    memcpy(buf + n, app, al);
    n += al;
    mcWriteFrame(buf, n);
}

static uint32_t mcEpoch() {
    uint32_t e = (uint32_t)rtc.now().unixtime();
    return (e > 1600000000UL) ? e : 0;
}

void meshcoreWriteText(const String &msg) {
    if (!s_handshakeSent) { mcSendAppStart(); s_handshakeSent = true; }
    uint16_t tlen = msg.length();
    if (tlen > MC_MAX_TEXT) tlen = MC_MAX_TEXT;
    uint32_t ts = mcEpoch();
    uint8_t buf[7 + MC_MAX_TEXT];
    uint16_t n = 0;
    buf[n++] = MC_CMD_SEND_CHANNEL_TXT;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = (uint8_t)(ts);
    buf[n++] = (uint8_t)(ts >> 8);
    buf[n++] = (uint8_t)(ts >> 16);
    buf[n++] = (uint8_t)(ts >> 24);
    memcpy(buf + n, msg.c_str(), tlen);
    n += tlen;
    mcWriteFrame(buf, n);
}

static void mcSendCmd1(uint8_t code) {
    if (serial1Mutex && xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        mcWriteFrame(&code, 1);
        xSemaphoreGive(serial1Mutex);
    }
}

void meshcoreLoadPref() {
    g_meshcoreTransport = prefs.getBool("meshcoreTx", false);
    s_handshakeSent = false;
}

void meshcoreSetTransport(bool on) {
    g_meshcoreTransport = on;
    prefs.putBool("meshcoreTx", on);
    s_handshakeSent = false;
    if (!on) return;
    if (serial1Mutex && xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        mcSendAppStart();
        s_handshakeSent = true;
        xSemaphoreGive(serial1Mutex);
    }
}

bool meshcoreFeedByte(uint8_t c, String &outText) {
    static bool inFrame = false;
    static uint8_t hdrN = 0;
    static uint16_t len = 0;
    static uint16_t payN = 0;
    static uint8_t pay[MC_MAX_PAYLOAD + 4];

    if (!inFrame) {
        if (c == MC_RADIO2APP) { inFrame = true; hdrN = 0; len = 0; payN = 0; }
        return false;
    }
    if (hdrN < 2) {
        if (hdrN == 0) len = c; else len |= ((uint16_t)c) << 8;
        hdrN++;
        if (hdrN == 2 && (len == 0 || len > (uint16_t)sizeof(pay))) inFrame = false;
        return false;
    }
    pay[payN++] = c;
    if (payN < len) return false;
    inFrame = false;
    uint8_t code = pay[0];
    if (code == MC_PUSH_MSG_WAITING) { mcSendCmd1(MC_CMD_SYNC_NEXT); return false; }
    if (code == MC_RESP_CHANNEL_MSG && len > 8) {
        outText = "";
        for (uint16_t i = 8; i < len; i++) outText += (char)pay[i];
        mcSendCmd1(MC_CMD_SYNC_NEXT);
        return outText.length() > 0;
    }
    if (code == MC_RESP_CHANNEL_MSG_V3 && len > 11) {
        outText = "";
        for (uint16_t i = 11; i < len; i++) outText += (char)pay[i];
        mcSendCmd1(MC_CMD_SYNC_NEXT);
        return outText.length() > 0;
    }
    return false;
}
