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
static const uint8_t MC_CMD_GET_DEVICE_TIME = 0x05;
static const uint8_t MC_CMD_SYNC_NEXT = 0x0A;
static const uint8_t MC_RESP_OK = 0x00;
static const uint8_t MC_RESP_ERR = 0x01;
static const uint8_t MC_RESP_SELF_INFO = 0x05;
static const uint8_t MC_RESP_CONTACT_MSG = 0x07;
static const uint8_t MC_RESP_CHANNEL_MSG = 0x08;
static const uint8_t MC_RESP_CURR_TIME = 0x09;
static const uint8_t MC_RESP_CONTACT_MSG_V3 = 0x10;
static const uint8_t MC_RESP_CHANNEL_MSG_V3 = 0x11;
static const uint8_t MC_RESP_CHANNEL_DATA = 0x1B;
static const uint8_t MC_PUSH_MSG_WAITING = 0x83;
static const uint8_t MC_CHANNEL = 0;
static const uint16_t MC_MAX_PAYLOAD = 176;
static const uint16_t MC_MAX_TEXT = MC_MAX_PAYLOAD - 7;
static const uint16_t MC_RADIO_TEXT_LEN = 160;
static const uint16_t MC_DEFAULT_TEXT_CAP = 127;
static const uint16_t MC_SELF_INFO_NAME_OFS = 58;
static const uint32_t MC_REPLY_TIMEOUT_MS = 1000;
static const uint8_t MC_PEND_SLOTS = 8;
static const uint8_t MC_RETRY_SLOTS = 8;
static const uint32_t MC_RETRY_HOLD_MS = 600000;
static const uint32_t MC_BRIDGE_IDLE_MS = 10000;

static volatile uint16_t s_textCap = MC_DEFAULT_TEXT_CAP;
static volatile bool s_syncPending = false;
static bool s_linkUp = false;
static bool s_resync = true;

static bool s_inFrame = false;
static uint8_t s_hdrN = 0;
static uint16_t s_rxLen = 0;
static uint16_t s_rxN = 0;
static uint8_t s_rx[MC_MAX_PAYLOAD];

struct McPending {
    uint16_t len;
    uint8_t data[MC_MAX_PAYLOAD];
};
static McPending s_pend[MC_PEND_SLOTS];
static uint8_t s_pendHead = 0;
static uint8_t s_pendCount = 0;

struct McRetry {
    uint32_t hash;
    uint32_t ms;
};
static McRetry s_retry[MC_RETRY_SLOTS];

static void mcWriteFrame(const uint8_t *payload, uint16_t len) {
    if (len == 0 || len > MC_MAX_PAYLOAD) return;
    uint8_t hdr[3] = {MC_APP2RADIO, (uint8_t)(len & 0xFF), (uint8_t)(len >> 8)};
    Serial1.write(hdr, 3);
    Serial1.write(payload, len);
    Serial1.flush();
}

static bool mcAssemble(uint8_t c) {
    if (!s_inFrame) {
        if (c == MC_RADIO2APP) { s_inFrame = true; s_hdrN = 0; s_rxLen = 0; s_rxN = 0; }
        return false;
    }
    if (s_hdrN < 2) {
        if (s_hdrN == 0) s_rxLen = c; else s_rxLen |= ((uint16_t)c) << 8;
        s_hdrN++;
        if (s_hdrN == 2 && (s_rxLen == 0 || s_rxLen > MC_MAX_PAYLOAD)) s_inFrame = false;
        return false;
    }
    s_rx[s_rxN++] = c;
    if (s_rxN < s_rxLen) return false;
    s_inFrame = false;
    if (!s_linkUp) { s_linkUp = true; s_resync = true; }
    return true;
}

static void mcPendClear() {
    s_pendHead = 0;
    s_pendCount = 0;
    s_inFrame = false;
    s_linkUp = false;
    s_resync = true;
}

static void mcPendPush(const uint8_t *data, uint16_t len) {
    if (s_pendCount == MC_PEND_SLOTS) {
        s_pendHead = (s_pendHead + 1) % MC_PEND_SLOTS;
        s_pendCount--;
    }
    McPending &f = s_pend[(s_pendHead + s_pendCount) % MC_PEND_SLOTS];
    f.len = len;
    memcpy(f.data, data, len);
    s_pendCount++;
}

static bool mcPendPop(McPending &out) {
    if (s_pendCount == 0) return false;
    out = s_pend[s_pendHead];
    s_pendHead = (s_pendHead + 1) % MC_PEND_SLOTS;
    s_pendCount--;
    return true;
}

static bool mcWanted(uint8_t code) {
    return code == MC_RESP_SELF_INFO || code == MC_RESP_CONTACT_MSG || code == MC_RESP_CHANNEL_MSG ||
           code == MC_RESP_CONTACT_MSG_V3 || code == MC_RESP_CHANNEL_MSG_V3 || code == MC_RESP_CHANNEL_DATA ||
           code == MC_PUSH_MSG_WAITING;
}

static uint32_t mcHash(const char *text, uint16_t len) {
    uint32_t h = 2166136261u;
    for (uint16_t i = 0; i < len; i++) {
        h ^= (uint8_t)text[i];
        h *= 16777619u;
    }
    return h;
}

static int mcAwait(uint8_t want, uint8_t &err) {
    const uint32_t start = millis();
    while (millis() - start < MC_REPLY_TIMEOUT_MS) {
        while (Serial1.available()) {
            if (!mcAssemble((uint8_t)Serial1.read())) continue;
            const uint8_t code = s_rx[0];
            if (want == MC_RESP_OK && (code == MC_RESP_OK || code == MC_RESP_ERR)) {
                err = (s_rxLen > 1) ? s_rx[1] : 0;
                return code;
            }
            if (code == want) return code;
            if (mcWanted(code)) mcPendPush(s_rx, s_rxLen);
        }
        vTaskDelay(1);
    }
    return -1;
}

static void mcResync() {
    const uint8_t query = MC_CMD_GET_DEVICE_TIME;
    mcWriteFrame(&query, 1);
    uint8_t err = 0;
    if (mcAwait(MC_RESP_CURR_TIME, err) == MC_RESP_CURR_TIME) s_resync = false;
    else s_linkUp = false;
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
    const uint8_t sync = MC_CMD_SYNC_NEXT;
    mcWriteFrame(&sync, 1);
}

static uint32_t mcEpoch() {
    return getEventTimestamp();
}

static int mcRetryFind(uint32_t h, uint32_t now) {
    for (int i = 0; i < MC_RETRY_SLOTS; i++) {
        if (s_retry[i].hash == h && now - s_retry[i].ms < MC_RETRY_HOLD_MS) return i;
    }
    return -1;
}

static void mcHandleSendReply(int code, uint8_t err, const char *text, uint16_t len) {
    if (code < 0) {
        s_linkUp = false;
        s_resync = true;
        return;
    }
    const uint32_t now = millis();
    const uint32_t h = mcHash(text, len);
    int slot = mcRetryFind(h, now);
    if (code == MC_RESP_OK) {
        if (slot >= 0) s_retry[slot].hash = 0;
        return;
    }
    String part;
    part.reserve(len);
    for (uint16_t i = 0; i < len; i++) part += text[i];
    if (slot >= 0) {
        s_retry[slot].hash = 0;
        Serial.printf("[MC] Radio rejected send again (err=%u), dropped: %.40s\n", (unsigned)err, part.c_str());
        return;
    }
    for (slot = 0; slot < MC_RETRY_SLOTS; slot++) {
        if (s_retry[slot].hash == 0 || now - s_retry[slot].ms >= MC_RETRY_HOLD_MS) break;
    }
    if (slot == MC_RETRY_SLOTS) {
        Serial.printf("[MC] Radio rejected send (err=%u), no retry slot, dropped: %.40s\n", (unsigned)err, part.c_str());
        return;
    }
    s_retry[slot].hash = h;
    s_retry[slot].ms = now;
    Serial.printf("[MC] Radio rejected send (err=%u), queued again: %.40s\n", (unsigned)err, part.c_str());
    meshEnqueue(part);
}

static void mcSendChannelText(const char *text, uint16_t tlen) {
    if (tlen > MC_MAX_TEXT) tlen = MC_MAX_TEXT;
    if (s_linkUp && s_resync) mcResync();
    const uint32_t ts = mcEpoch();
    uint8_t buf[7 + MC_MAX_TEXT];
    uint16_t n = 0;
    buf[n++] = MC_CMD_SEND_CHANNEL_TXT;
    buf[n++] = 0x00;
    buf[n++] = MC_CHANNEL;
    buf[n++] = (uint8_t)(ts);
    buf[n++] = (uint8_t)(ts >> 8);
    buf[n++] = (uint8_t)(ts >> 16);
    buf[n++] = (uint8_t)(ts >> 24);
    memcpy(buf + n, text, tlen);
    n += tlen;
    mcWriteFrame(buf, n);
    if (!s_linkUp) return;
    uint8_t err = 0;
    const int code = mcAwait(MC_RESP_OK, err);
    mcHandleSendReply(code, err, text, tlen);
}

void meshcoreWriteText(const String &msg) {
    if (!s_handshakeSent) { mcSendAppStart(); s_handshakeSent = true; }
    const uint16_t cap = s_textCap;
    const uint16_t len = msg.length();
    const char *p = msg.c_str();
    const String id = getNodeId() + ": ";
    const bool hasId = msg.startsWith(id);
    uint16_t start = 0;
    bool first = true;
    while (start < len) {
        const uint16_t pre = (!first && hasId) ? id.length() : 0;
        const uint16_t room = (cap > pre) ? cap - pre : 1;
        uint16_t end = (len - start > room) ? start + room : len;
        if (end < len) {
            const uint16_t minCut = start + ((first && hasId) ? id.length() : 0);
            uint16_t cut = end;
            while (cut > minCut && p[cut] != '\n') cut--;
            if (cut == minCut) {
                cut = end;
                while (cut > minCut && p[cut] != ' ') cut--;
            }
            if (cut > minCut) end = cut;
        }
        String part = pre ? id : String();
        part += msg.substring(start, end);
        mcSendChannelText(part.c_str(), part.length());
        start = end;
        while (start < len && (p[start] == '\n' || p[start] == ' ')) start++;
        first = false;
    }
}

uint16_t meshcoreTextCap() {
    return s_textCap;
}

static bool mcSendCmd1(uint8_t code) {
    if (serial1Mutex && xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        mcWriteFrame(&code, 1);
        xSemaphoreGive(serial1Mutex);
        return true;
    }
    return false;
}

static void mcRequestNext() {
    s_syncPending = !mcSendCmd1(MC_CMD_SYNC_NEXT);
}

void meshcorePoll() {
    if (s_syncPending) mcRequestNext();
}

static void mcSetCapFromSelfInfo(uint16_t len) {
    if (len < MC_SELF_INFO_NAME_OFS) return;
    const uint16_t nameLen = len - MC_SELF_INFO_NAME_OFS;
    uint16_t cap = (nameLen + 2 < MC_RADIO_TEXT_LEN) ? MC_RADIO_TEXT_LEN - (nameLen + 2) : 1;
    if (cap > MC_MAX_TEXT) cap = MC_MAX_TEXT;
    s_textCap = cap;
    Serial.printf("[MC] Radio answered, text limit %u bytes\n", (unsigned)cap);
}

void meshcoreLoadPref() {
    g_meshcoreTransport = prefs.getBool("meshcoreTx", false);
    s_handshakeSent = false;
}

void meshcoreSetTransport(bool on) {
    g_meshcoreTransport = on;
    prefs.putBool("meshcoreTx", on);
    lastSaveTime = 0;
    saveConfiguration();
    s_handshakeSent = false;
    if (serial1Mutex && xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        mcPendClear();
        if (on) {
            mcSendAppStart();
            s_handshakeSent = true;
        }
        xSemaphoreGive(serial1Mutex);
    }
}

void meshcoreFeedByte(uint8_t c) {
    if (mcAssemble(c) && mcWanted(s_rx[0])) mcPendPush(s_rx, s_rxLen);
}

void meshcoreBridge(uint8_t first) {
    if (!serial1Mutex || xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(2000)) != pdTRUE) return;
    Serial1.write(&first, 1);
    uint8_t buf[64];
    uint32_t last = millis();
    while (millis() - last < MC_BRIDGE_IDLE_MS) {
        int n = Serial.available();
        if (n > 0) {
            n = Serial.readBytes(buf, n < (int)sizeof(buf) ? n : (int)sizeof(buf));
            Serial1.write(buf, n);
            last = millis();
        }
        n = Serial1.available();
        if (n > 0) {
            n = Serial1.readBytes(buf, n < (int)sizeof(buf) ? n : (int)sizeof(buf));
            Serial.write(buf, n);
        }
        vTaskDelay(1);
    }
    mcPendClear();
    s_handshakeSent = false;
    xSemaphoreGive(serial1Mutex);
}

static bool mcHandleFrame(const McPending &f, String &outText) {
    const uint8_t code = f.data[0];
    if (code == MC_RESP_SELF_INFO) {
        mcSetCapFromSelfInfo(f.len);
        return false;
    }
    if (code == MC_PUSH_MSG_WAITING || code == MC_RESP_CONTACT_MSG || code == MC_RESP_CONTACT_MSG_V3 ||
        code == MC_RESP_CHANNEL_DATA) {
        mcRequestNext();
        return false;
    }
    if (code == MC_RESP_CHANNEL_MSG || code == MC_RESP_CHANNEL_MSG_V3) {
        const uint16_t chOfs = (code == MC_RESP_CHANNEL_MSG) ? 1 : 4;
        const uint16_t txtOfs = (code == MC_RESP_CHANNEL_MSG) ? 8 : 11;
        mcRequestNext();
        if (f.len <= txtOfs || f.data[chOfs] != MC_CHANNEL) return false;
        outText = "";
        for (uint16_t i = txtOfs; i < f.len; i++) outText += (char)f.data[i];
        const int sep = outText.indexOf(": ");
        if (sep >= 0) outText.remove(0, sep + 2);
        return outText.length() > 0;
    }
    return false;
}

bool meshcoreNextText(String &outText) {
    McPending f;
    for (;;) {
        bool got = false;
        if (serial1Mutex && xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            got = mcPendPop(f);
            xSemaphoreGive(serial1Mutex);
        }
        if (!got) return false;
        if (mcHandleFrame(f, outText)) return true;
    }
}
