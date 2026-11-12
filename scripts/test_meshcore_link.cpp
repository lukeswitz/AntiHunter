#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "hardware.h"
#include "meshcore_link.h"
#include "network.h"
#include <Preferences.h>

uint32_t g_fakeMillis = 1000;
HostSerial Serial;
HostRadioSerial Serial1;
Preferences prefs;
SemaphoreHandle_t serial1Mutex = (void *)1;
unsigned long lastSaveTime = 1;
static int g_saves = 0;
static std::vector<std::string> g_enqueued;
static const uint32_t kEpoch = 1794000000u;

void saveConfiguration() { g_saves++; }
uint32_t getEventTimestamp() { return kEpoch; }
String getNodeId() { return String("AH01"); }
bool meshEnqueue(const String &msg, bool) {
    g_enqueued.push_back(msg.s);
    return true;
}

enum SendReply { REPLY_OK, REPLY_ERR, REPLY_NONE };
static SendReply g_sendReply = REPLY_OK;

static void radio(const std::vector<uint8_t> &f) {
    switch (f[0]) {
    case 0x01: {
        std::vector<uint8_t> self(58, 0);
        self[0] = 0x05;
        const char *name = "8CF27974";
        self.insert(self.end(), name, name + strlen(name));
        Serial1.reply(self);
        break;
    }
    case 0x05:
        Serial1.reply({0x09, 1, 2, 3, 4});
        break;
    case 0x0A:
        Serial1.reply({0x0A});
        break;
    case 0x03:
        if (g_sendReply == REPLY_OK) Serial1.reply({0x00});
        else if (g_sendReply == REPLY_ERR) Serial1.reply({0x01, 0x02});
        break;
    }
}

static std::vector<std::string> pump() {
    while (Serial1.available()) meshcoreFeedByte((uint8_t)Serial1.read());
    std::vector<std::string> out;
    String t;
    while (meshcoreNextText(t)) out.push_back(t.s);
    return out;
}

static std::vector<std::string> sentTexts() {
    std::vector<std::string> out;
    for (auto &f : Serial1.frames)
        if (f[0] == 0x03) out.push_back(std::string(f.begin() + 7, f.end()));
    return out;
}

static bool wroteSyncNext() {
    for (auto &f : Serial1.frames)
        if (f.size() == 1 && f[0] == 0x0A) return true;
    return false;
}

static std::vector<uint8_t> channelMsg(uint8_t code, uint8_t ch, const char *text) {
    std::vector<uint8_t> f;
    if (code == 0x08) f = {0x08, ch, 0xFF, 0, 1, 2, 3, 4};
    else f = {0x11, 0, 0, 0, ch, 0xFF, 0, 1, 2, 3, 4};
    f.insert(f.end(), text, text + strlen(text));
    return f;
}

int main() {
    Serial1.onFrame = radio;

    meshcoreSetTransport(true);
    assert(g_meshcoreTransport && prefs.bools["meshcoreTx"] && g_saves == 1);
    assert(Serial1.frames.size() == 2);
    assert(Serial1.frames[0][0] == 0x01 && Serial1.frames[0].size() == 18);
    assert(memcmp(Serial1.frames[0].data() + 8, "AntiHunter", 10) == 0);
    assert(Serial1.frames[1] == std::vector<uint8_t>({0x0A}));
    assert(pump().empty());
    assert(meshcoreTextCap() == 150);
    printf("handshake + SELF_INFO cap 150: ok\n");

    Serial1.frames.clear();
    g_sendReply = REPLY_OK;
    meshcoreWriteText(String("AH01: STATUS: Mode:WiFi"));
    assert(Serial1.frames.size() == 2 && Serial1.frames[0] == std::vector<uint8_t>({0x05}));
    const std::vector<uint8_t> &s = Serial1.frames[1];
    assert(s[0] == 0x03 && s[1] == 0 && s[2] == 0);
    uint32_t ts = s[3] | (s[4] << 8) | (s[5] << 16) | ((uint32_t)s[6] << 24);
    assert(ts == kEpoch);
    assert(sentTexts() == std::vector<std::string>({"AH01: STATUS: Mode:WiFi"}));
    assert(g_enqueued.empty());
    printf("resync then channel-0 send, OK: ok\n");

    g_sendReply = REPLY_ERR;
    meshcoreWriteText(String("AH01: ALERT one"));
    assert(g_enqueued == std::vector<std::string>({"AH01: ALERT one"}));
    meshcoreWriteText(String(g_enqueued[0].c_str()));
    assert(g_enqueued.size() == 1);
    printf("ERR re-queues once, second ERR drops: ok\n");

    meshcoreWriteText(String("AH01: ALERT two"));
    assert(g_enqueued.size() == 2 && g_enqueued[1] == "AH01: ALERT two");
    g_sendReply = REPLY_OK;
    meshcoreWriteText(String("AH01: ALERT two"));
    g_sendReply = REPLY_ERR;
    meshcoreWriteText(String("AH01: ALERT two"));
    assert(g_enqueued.size() == 3);
    printf("OK clears the retry slot: ok\n");

    meshcoreWriteText(String("AH01: ALERT three"));
    assert(g_enqueued.size() == 4);
    g_fakeMillis += 600001;
    meshcoreWriteText(String("AH01: ALERT three"));
    assert(g_enqueued.size() == 5);
    printf("retry hold expires after 600 s: ok\n");

    g_sendReply = REPLY_NONE;
    uint32_t t0 = g_fakeMillis;
    meshcoreWriteText(String("AH01: lost"));
    assert(g_fakeMillis - t0 >= 1000 && g_enqueued.size() == 5);
    Serial1.frames.clear();
    t0 = g_fakeMillis;
    meshcoreWriteText(String("AH01: next"));
    assert(g_fakeMillis == t0);
    assert(sentTexts() == std::vector<std::string>({"AH01: next"}));
    printf("reply timeout -> fire-and-forget: ok\n");

    Serial1.reply({0x0A});
    pump();
    g_sendReply = REPLY_OK;
    std::string body;
    for (int i = 0; i < 40; i++) body += "word" + std::to_string(i) + " ";
    body.pop_back();
    std::string msg = "AH01: " + body;
    Serial1.frames.clear();
    meshcoreWriteText(String(msg.c_str()));
    std::vector<std::string> parts = sentTexts();
    assert(parts.size() >= 2);
    std::string joined;
    for (size_t i = 0; i < parts.size(); i++) {
        const bool last = i + 1 == parts.size();
        assert(parts[i].size() <= 150);
        assert(parts[i].compare(0, 6, "AH01: ") == 0);
        const bool marked = parts[i].size() >= 2 && parts[i].compare(parts[i].size() - 2, 2, " +") == 0;
        assert(marked == !last);
        joined += (i ? " " : "") + parts[i].substr(6, parts[i].size() - 6 - (marked ? 2 : 0));
    }
    assert(joined == body);
    printf("split at 150 on spaces, continuation re-prefixed and marked \" +\": ok (%zu parts)\n", parts.size());

    Serial1.frames.clear();
    meshcoreWriteText(String("AH01: line one\nline two"));
    assert(sentTexts() == std::vector<std::string>({"AH01: line one\nline two"}));
    std::string lines = "AH01: ";
    for (int i = 0; i < 12; i++) lines += "row" + std::to_string(i) + " abcdefghij\n";
    lines.pop_back();
    Serial1.frames.clear();
    meshcoreWriteText(String(lines.c_str()));
    parts = sentTexts();
    assert(parts.size() >= 2);
    for (const auto &pt : parts) {
        assert(pt.size() <= 150);
        assert(pt.compare(pt.size() - 2, 2, " +") != 0);
    }
    printf("newline cuts carry no marker: ok (%zu parts)\n", parts.size());

    Serial1.frames.clear();
    Serial1.reply(channelMsg(0x08, 0, "8CF27974: @AH01 STATUS"));
    assert(pump() == std::vector<std::string>({"@AH01 STATUS"}));
    assert(wroteSyncNext());
    Serial1.frames.clear();
    Serial1.reply(channelMsg(0x08, 1, "8CF27974: @AH01 STATUS"));
    assert(pump().empty() && wroteSyncNext());
    Serial1.frames.clear();
    Serial1.reply(channelMsg(0x11, 0, "radio: @ALL STOP"));
    assert(pump() == std::vector<std::string>({"@ALL STOP"}));
    Serial1.frames.clear();
    Serial1.reply({0x83});
    assert(pump().empty() && wroteSyncNext());
    Serial1.frames.clear();
    Serial1.reply({0x88, 1, 2, 3});
    assert(pump().empty() && !wroteSyncNext());
    printf("inbound ch0 v1/v3 decode, other channel ignored, 0x83 sync, 0x88 skipped: ok\n");

    Serial1.frames.clear();
    Serial.tx.clear();
    const uint8_t appStart[] = {0x0B, 0x00, 0x01, 3, 0, 0, 0, 0, 0, 0, 'c', 'l', 'i'};
    Serial.rx.insert(Serial.rx.end(), appStart, appStart + sizeof(appStart));
    t0 = g_fakeMillis;
    meshcoreBridge(0x3C);
    assert(g_fakeMillis - t0 >= 10000 && Serial.rx.empty());
    assert(Serial1.frames.size() == 1 && Serial1.frames[0].size() == 11 && Serial1.frames[0][0] == 0x01);
    assert(Serial.tx.size() == 3 + 66 && Serial.tx[0] == 0x3E && Serial.tx[1] == 66 && Serial.tx[3] == 0x05);
    assert(pump().empty());
    Serial1.frames.clear();
    meshcoreWriteText(String("AH01: after bridge"));
    assert(Serial1.frames.size() >= 3 && Serial1.frames[0][0] == 0x01 && Serial1.frames[1][0] == 0x0A);
    assert(sentTexts() == std::vector<std::string>({"AH01: after bridge"}));
    printf("USB bridge forwards both ways, exits after 10 s idle, link re-handshakes: ok\n");

    printf("meshcore_link: all tests passed\n");
    return 0;
}
