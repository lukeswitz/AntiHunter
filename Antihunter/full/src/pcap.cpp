#include "pcap.h"
#include "network.h"
#include "scanner.h"
#include "hardware.h"
#include "detect.h"
#include "main.h"

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_heap_caps.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include <mutex>
#include <vector>

extern std::atomic<bool> scanning;
extern std::atomic<bool> stopRequested;
extern TaskHandle_t workerTaskHandle;
extern std::vector<uint8_t> CHANNELS;

#define PCAP_LT_WIFI       127u
#define PCAP_LT_BLE        256u
#define PCAP_RADIOTAP_LEN  16u
#define PCAP_SNAPLEN       2324u
#define PCAP_BUF_PSRAM     (16u * 1024u)
#define PCAP_BUF_INTERNAL  (8u * 1024u)
#define PCAP_DIR           "/pcap"
#define BLE_ADV_ACCESS_ADDR 0x8E89BED6u

std::atomic<bool> pcapBleEnabled{false};

static uint8_t g_radio = PCAP_RADIO_WIFI;
static uint8_t g_band = PCAP_BAND_24;
static uint16_t g_dwellMs = 250;
static bool g_mgmtOnly = false;
static std::vector<uint8_t> g_reqChannels;

static uint8_t g_hopList[48];
static uint8_t g_hopLen = 0;
static uint8_t g_hopIdx = 0;

static volatile bool g_active = false;
static uint8_t *g_bufA = nullptr;
static uint8_t *g_bufB = nullptr;
static uint32_t g_bufCap = 0;
static volatile uint32_t g_sizeA = 0;
static volatile uint32_t g_sizeB = 0;
static volatile bool g_useA = true;
static portMUX_TYPE g_bufMux = portMUX_INITIALIZER_UNLOCKED;

static const uint32_t PCAP_MAX_FILE_MB_MIN = 8;
static const uint32_t PCAP_MAX_FILE_MB_MAX = 300;
static const uint32_t PCAP_MAX_FILE_MB_DEF = 100;
static const uint32_t PCAP_MIN_FREE_BYTES = 32u * 1024u * 1024u;
static const uint8_t PCAP_MAX_WRITE_FAILS = 3;
static std::atomic<uint32_t> g_maxFileMB{PCAP_MAX_FILE_MB_DEF};
static std::atomic<uint32_t> g_writeFails{0};
static std::atomic<bool> g_stopReasonSize{false};
static std::atomic<bool> g_stopReasonWrite{false};

static std::atomic<uint32_t> g_frames{0};
static std::atomic<uint32_t> g_bytes{0};
static std::atomic<uint32_t> g_dropped{0};
static std::atomic<uint8_t> g_curChan{0};
static uint32_t g_startMs = 0;
static uint32_t g_endMs = 0;
static uint32_t g_baseEpoch = 0;
static uint32_t g_baseMicros = 0;
static String g_path;
static std::mutex g_pathMutex;
static bool g_autoTriggered = false;
static std::atomic<uint32_t> g_autoBudgetMB{512};
static std::atomic<uint32_t> g_freeFloorMB{256};

void setPcapAutoTriggered(bool autoTriggered) { g_autoTriggered = autoTriggered; }
// cppcheck-suppress unusedFunction // pcap.h API, called from network.cpp in the full tree
uint32_t getPcapAutoBudgetMB() { return g_autoBudgetMB.load(); }
// cppcheck-suppress unusedFunction // pcap.h API, called from network.cpp in the full tree
uint32_t getPcapFreeFloorMB() { return g_freeFloorMB.load(); }

// cppcheck-suppress unusedFunction // pcap.h API, called from network.cpp in the full tree
void setPcapAutoLimits(uint32_t budgetMB, uint32_t freeFloorMB) {
    if (budgetMB < 16) budgetMB = 16;
    if (budgetMB > 262144) budgetMB = 262144;
    if (freeFloorMB > 262144) freeFloorMB = 262144;
    g_autoBudgetMB.store(budgetMB);
    g_freeFloorMB.store(freeFloorMB);
    Preferences p;
    if (p.begin("ahpcap", false)) {
        p.putUInt("budMB", budgetMB);
        p.putUInt("floorMB", freeFloorMB);
        p.end();
    }
}

void loadPcapPrefs() {
    Preferences p;
    if (!p.begin("ahpcap", true)) return;
    g_autoBudgetMB.store(p.getUInt("budMB", 512));
    g_freeFloorMB.store(p.getUInt("floorMB", 256));
    p.end();
}

bool pcapDualBandCapable() {
#ifdef ARDUINO_XIAO_ESP32C5
    return true;
#else
    return false;
#endif
}

void setPcapConfig(uint8_t radio, uint8_t band, const String &channelsCsv,
                   uint16_t dwellMs, bool mgmtOnly) {
    g_radio = (radio == PCAP_RADIO_BLE) ? PCAP_RADIO_BLE : PCAP_RADIO_WIFI;
    g_band = (band <= PCAP_BAND_BOTH) ? band : PCAP_BAND_24;
    // cppcheck-suppress knownConditionTrueFalse // constant per target, true on C5
    if (!pcapDualBandCapable()) g_band = PCAP_BAND_24;
    g_dwellMs = (dwellMs >= 50 && dwellMs <= 5000) ? dwellMs : 250;
    g_mgmtOnly = mgmtOnly;

    g_reqChannels.clear();
    int start = 0;
    while (start < (int)channelsCsv.length()) {
        int comma = channelsCsv.indexOf(',', start);
        if (comma < 0) comma = channelsCsv.length();
        int ch = channelsCsv.substring(start, comma).toInt();
        if (ch >= 1 && ch <= 177 && g_reqChannels.size() < sizeof(g_hopList)) {
            g_reqChannels.push_back((uint8_t)ch);
        }
        start = comma + 1;
    }
}

static bool IRAM_ATTR pcapAppend(const uint8_t *a, uint32_t alen,
                                 const uint8_t *b, uint32_t blen) {
    if (!g_active) return false;

    uint32_t us = (uint32_t)(micros() - g_baseMicros);
    uint32_t tsSec = g_baseEpoch + us / 1000000u;
    uint32_t tsUsec = us % 1000000u;
    uint32_t total = alen + blen;

    uint8_t rec[16];
    memcpy(rec + 0, &tsSec, 4);
    memcpy(rec + 4, &tsUsec, 4);
    memcpy(rec + 8, &total, 4);
    memcpy(rec + 12, &total, 4);

    const uint32_t need = sizeof(rec) + total;

    portENTER_CRITICAL_ISR(&g_bufMux);
    if (g_bufA == nullptr || g_bufB == nullptr) {
        portEXIT_CRITICAL_ISR(&g_bufMux);
        return false;
    }
    uint8_t *dst = g_useA ? g_bufA : g_bufB;
    volatile uint32_t *used = g_useA ? &g_sizeA : &g_sizeB;
    if (*used + need > g_bufCap) {
        volatile uint32_t *other = g_useA ? &g_sizeB : &g_sizeA;
        if (*other != 0) {
            portEXIT_CRITICAL_ISR(&g_bufMux);
            g_dropped.fetch_add(1);
            return false;
        }
        g_useA = !g_useA;
        dst = g_useA ? g_bufA : g_bufB;
        used = other;
    }
    memcpy(dst + *used, rec, sizeof(rec));
    *used += sizeof(rec);
    if (alen) { memcpy(dst + *used, a, alen); *used += alen; }
    if (blen) { memcpy(dst + *used, b, blen); *used += blen; }
    portEXIT_CRITICAL_ISR(&g_bufMux);

    g_frames.fetch_add(1);
    return true;
}

static IRAM_ATTR uint16_t pcapChanToFreq(uint8_t ch) {
    if (ch >= 1 && ch <= 13) return (uint16_t)(2407 + ch * 5);
    if (ch == 14) return 2484u;
    if (ch >= 32 && ch <= 177) return (uint16_t)(5000 + ch * 5);
    return 0u;
}

static void IRAM_ATTR pcapWifiCb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_active) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) return;

    const wifi_promiscuous_pkt_t *pkt = static_cast<wifi_promiscuous_pkt_t *>(buf);
    int len = pkt->rx_ctrl.sig_len;
    if (len > 4) len -= 4;
    if (len < 10) return;
    if (len > (int)(PCAP_SNAPLEN - PCAP_RADIOTAP_LEN)) len = PCAP_SNAPLEN - PCAP_RADIOTAP_LEN;

    uint16_t freq = pcapChanToFreq(pkt->rx_ctrl.channel);
    uint16_t cflags = 0x0080u;
    if (freq >= 2412u && freq <= 2484u) cflags |= 0x0040u;
    else if (freq >= 5000u) cflags |= 0x0100u;

    uint8_t rt[PCAP_RADIOTAP_LEN];
    rt[0] = 0;
    rt[1] = 0;
    rt[2] = (uint8_t)(PCAP_RADIOTAP_LEN & 0xFF);
    rt[3] = (uint8_t)(PCAP_RADIOTAP_LEN >> 8);
    rt[4] = 0x6E; rt[5] = 0; rt[6] = 0; rt[7] = 0;
    rt[8] = 0;
    rt[9] = (uint8_t)(pkt->rx_ctrl.rate & 0x1F);
    rt[10] = (uint8_t)(freq & 0xFF);
    rt[11] = (uint8_t)(freq >> 8);
    rt[12] = (uint8_t)(cflags & 0xFF);
    rt[13] = (uint8_t)(cflags >> 8);
    rt[14] = (uint8_t)pkt->rx_ctrl.rssi;
    rt[15] = (uint8_t)-128;

    pcapAppend(rt, PCAP_RADIOTAP_LEN, pkt->payload, (uint32_t)len);
}

static uint8_t pcapMapPduType(uint8_t advType) {
    switch (advType) {
        case 0: return 0;
        case 1: return 1;
        case 2: return 6;
        case 3: return 2;
        case 4: return 4;
        default: return 0;
    }
}

static uint32_t pcapBleCrc24(const uint8_t *data, size_t len) {
    uint32_t crc = 0x555555u;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        for (int j = 0; j < 8; j++) {
            uint32_t fb = ((b >> j) & 1u) ^ (crc & 1u);
            crc >>= 1;
            if (fb) crc ^= 0xDA6000u;
        }
    }
    return crc & 0xFFFFFFu;
}

static void pcapEmitBle(uint8_t pduType, uint8_t addrType, const uint8_t *advA,
                        const uint8_t *targetA, const uint8_t *advData,
                        uint8_t advDataLen, int8_t rssi) {
    if (advDataLen > 31) advDataLen = 31;
    const uint8_t targetLen = targetA ? 6 : 0;
    const uint8_t payloadLen = 6 + targetLen + advDataLen;

    uint8_t body[64];
    size_t off = 0;
    body[off++] = 0;
    body[off++] = (uint8_t)rssi;
    body[off++] = (uint8_t)-128;
    body[off++] = 0;
    uint32_t aa = BLE_ADV_ACCESS_ADDR;
    memcpy(body + off, &aa, 4); off += 4;
    uint16_t flags = 0x0001 | 0x0002 | 0x0010 | 0x0400 | 0x0800;
    memcpy(body + off, &flags, 2); off += 2;
    memcpy(body + off, &aa, 4); off += 4;
    size_t pduStart = off;
    uint8_t txAdd = (addrType == 1 || addrType == 3) ? 1 : 0;
    body[off++] = (pduType & 0x0F) | (txAdd << 6);
    body[off++] = payloadLen;
    memcpy(body + off, advA, 6); off += 6;
    if (targetLen) { memcpy(body + off, targetA, 6); off += 6; }
    if (advDataLen) { memcpy(body + off, advData, advDataLen); off += advDataLen; }
    uint32_t crc = pcapBleCrc24(body + pduStart, 2u + (size_t)payloadLen);
    body[off++] = (uint8_t)(crc & 0xFF);
    body[off++] = (uint8_t)((crc >> 8) & 0xFF);
    body[off++] = (uint8_t)((crc >> 16) & 0xFF);

    pcapAppend(body, (uint32_t)off, nullptr, 0);
}

void pcapOnBleAdv(const uint8_t *addr, uint8_t addrType, uint8_t advType,
                  const uint8_t *payload, uint16_t payloadLen, uint16_t advLen,
                  const uint8_t *targetAddr, int8_t rssi) {
    if (!g_active || g_radio != PCAP_RADIO_BLE) return;

    if (advLen > payloadLen) advLen = payloadLen;
    uint8_t scanLen = (uint8_t)((payloadLen > advLen) ? (payloadLen - advLen) : 0);
    const bool directed = (advType == 1) && targetAddr != nullptr;

    pcapEmitBle(pcapMapPduType(advType), addrType, addr,
                directed ? targetAddr : nullptr,
                payload, (uint8_t)advLen, rssi);

    if (scanLen > 0 && advType != 4) {
        pcapEmitBle(4, addrType, addr, nullptr, payload + advLen, scanLen, rssi);
    }
}

static bool pcapAllocBuffers() {
    g_bufCap = PCAP_BUF_PSRAM;
    g_bufA = static_cast<uint8_t *>(heap_caps_malloc(g_bufCap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    g_bufB = static_cast<uint8_t *>(heap_caps_malloc(g_bufCap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!g_bufA || !g_bufB) {
        if (g_bufA) { free(g_bufA); g_bufA = nullptr; }
        if (g_bufB) { free(g_bufB); g_bufB = nullptr; }
        g_bufCap = PCAP_BUF_INTERNAL;
        g_bufA = static_cast<uint8_t *>(heap_caps_malloc(g_bufCap, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        g_bufB = static_cast<uint8_t *>(heap_caps_malloc(g_bufCap, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }
    if (!g_bufA || !g_bufB) {
        if (g_bufA) { free(g_bufA); g_bufA = nullptr; }
        if (g_bufB) { free(g_bufB); g_bufB = nullptr; }
        g_bufCap = 0;
        return false;
    }
    g_sizeA = g_sizeB = 0;
    g_useA = true;
    return true;
}

static void pcapFreeBuffers() {
    uint8_t *a, *b;
    portENTER_CRITICAL(&g_bufMux);
    a = g_bufA; g_bufA = nullptr;
    b = g_bufB; g_bufB = nullptr;
    g_sizeA = g_sizeB = 0;
    g_useA = true;
    portEXIT_CRITICAL(&g_bufMux);
    if (a) free(a);
    if (b) free(b);
    g_bufCap = 0;
}

static void pcapDrain(fs::File &f) {
    const uint8_t *src = nullptr;
    uint32_t len = 0;

    portENTER_CRITICAL(&g_bufMux);
    if (g_useA && g_sizeB > 0) {
        src = g_bufB; len = g_sizeB; g_sizeB = 0;
    } else if (!g_useA && g_sizeA > 0) {
        src = g_bufA; len = g_sizeA; g_sizeA = 0;
    } else if (g_useA && g_sizeA > 0) {
        src = g_bufA; len = g_sizeA; g_sizeA = 0; g_useA = false;
    } else if (!g_useA && g_sizeB > 0) {
        src = g_bufB; len = g_sizeB; g_sizeB = 0; g_useA = true;
    }
    portEXIT_CRITICAL(&g_bufMux);

    if (!src || !len) return;
    size_t wrote = SafeSD::write(f, src, len);
    g_bytes.fetch_add((uint32_t)wrote);
    if (wrote == len) {
        g_writeFails.store(0);
        // sync now: a reset between appends is what leaves the filesystem inconsistent
        f.flush();
        return;
    }

    const uint32_t fails = g_writeFails.fetch_add(1) + 1;
    Serial.printf("[PCAP] short write %u/%u (%u consecutive)\n",
                  (unsigned)wrote, (unsigned)len, (unsigned)fails);
    if (fails >= PCAP_MAX_WRITE_FAILS) {
        g_stopReasonWrite.store(true);
        stopRequested = true;
        Serial.println("[PCAP] stopping: the card is not accepting writes - further writes would damage the filesystem");
    }
}

static void pcapBuildHopList() {
    g_hopLen = 0;
    g_hopIdx = 0;

    const std::vector<uint8_t> &src = g_reqChannels.empty() ? CHANNELS : g_reqChannels;
    for (size_t i = 0; i < src.size() && g_hopLen < sizeof(g_hopList); i++) {
        const uint8_t ch = src[i];
        const bool is24 = (ch >= 1 && ch <= 14);
        if (g_band == PCAP_BAND_24 && !is24) continue;
        if (g_band == PCAP_BAND_5 && is24) continue;
        g_hopList[g_hopLen++] = ch;
    }
    if (g_hopLen == 0) g_hopList[g_hopLen++] = 1;
}

static bool pcapRadioStartWifi() {
    WiFi.mode(WIFI_AP_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
#ifdef ARDUINO_XIAO_ESP32C5
    esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
#endif

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = g_mgmtOnly
        ? WIFI_PROMIS_FILTER_MASK_MGMT
        : (WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&pcapWifiCb);

    esp_err_t rp = esp_wifi_set_promiscuous(true);
    if (rp != ESP_OK) {
        Serial.printf("[PCAP] promiscuous enable failed: %s\n", esp_err_to_name(rp));
        return false;
    }

    esp_wifi_set_channel(g_hopList[0], WIFI_SECOND_CHAN_NONE);
    g_curChan.store(g_hopList[0]);
    vTaskDelay(pdMS_TO_TICKS(50));
    return true;
}

static uint64_t pcapSdFreeBytes() {
    const uint64_t total = SD.totalBytes();
    const uint64_t used = SD.usedBytes();
    return (total > used) ? (total - used) : 0ULL;
}

static uint32_t pcapPruneAuto() {
    if (!SafeSD::isAvailable()) return 0;

    std::vector<String> names;
    std::vector<uint32_t> sizes;
    uint64_t autoTotal = 0;

    fs::File dir = SafeSD::open(PCAP_DIR);
    if (!dir || !dir.isDirectory()) {
        if (dir) dir.close();
        return 0;
    }
    for (fs::File f = dir.openNextFile(); f; f = dir.openNextFile()) {
        if (!f.isDirectory()) {
            String name = f.name();
            const int slash = name.lastIndexOf('/');
            if (slash >= 0) name = name.substring(slash + 1);
            if (name.indexOf("_auto_") >= 0 && name.endsWith(".pcap")) {
                names.push_back(name);
                sizes.push_back((uint32_t)f.size());
                autoTotal += (uint64_t)f.size();
            }
        }
        f.close();
    }
    dir.close();

    for (size_t i = 1; i < names.size(); i++) {
        String kn = names[i];
        uint32_t ks = sizes[i];
        size_t j = i;
        while (j > 0 && names[j - 1] > kn) {
            names[j] = names[j - 1];
            sizes[j] = sizes[j - 1];
            j--;
        }
        names[j] = kn;
        sizes[j] = ks;
    }

    const uint64_t budget = (uint64_t)g_autoBudgetMB.load() * 1024ULL * 1024ULL;
    const uint64_t floor = (uint64_t)g_freeFloorMB.load() * 1024ULL * 1024ULL;
    uint64_t freeNow = pcapSdFreeBytes();

    uint32_t removed = 0;
    for (size_t i = 0; i < names.size(); i++) {
        if (autoTotal <= budget && freeNow >= floor) break;
        if (!pcapDeleteFile(names[i])) continue;
        autoTotal = (autoTotal > sizes[i]) ? (autoTotal - sizes[i]) : 0ULL;
        freeNow += sizes[i];
        removed++;
    }
    if (removed) {
        Serial.printf("[PCAP] Pruned %u auto capture%s (budget %uMB, free floor %uMB)\n",
                      removed, removed == 1 ? "" : "s",
                      (unsigned)g_autoBudgetMB.load(), (unsigned)g_freeFloorMB.load());
    }
    return removed;
}

static String pcapMakePath() {
    String stamp = getFormattedTimestamp();
    String safe;
    for (size_t i = 0; i < stamp.length(); i++) {
        char c = stamp[i];
        if (c == ' ') safe += '_';
        else if (c == ':' || c == '-') continue;
        else safe += c;
    }
    if (safe.length() == 0) safe = String(millis());
    return String(PCAP_DIR) + "/" + (g_radio == PCAP_RADIO_BLE ? "ble_" : "wifi_") +
           (g_autoTriggered ? "auto_" : "") + safe + ".pcap";
}

static bool pcapWriteGlobalHeader(fs::File &f) {
    uint8_t hdr[24];
    uint32_t magic = 0xA1B2C3D4u;
    uint16_t major = 2, minor = 4;
    uint32_t zone = 0, sigfigs = 0;
    uint32_t snaplen = PCAP_SNAPLEN;
    uint32_t network = (g_radio == PCAP_RADIO_BLE) ? PCAP_LT_BLE : PCAP_LT_WIFI;
    memcpy(hdr + 0, &magic, 4);
    memcpy(hdr + 4, &major, 2);
    memcpy(hdr + 6, &minor, 2);
    memcpy(hdr + 8, &zone, 4);
    memcpy(hdr + 12, &sigfigs, 4);
    memcpy(hdr + 16, &snaplen, 4);
    memcpy(hdr + 20, &network, 4);
    return SafeSD::write(f, hdr, sizeof(hdr)) == sizeof(hdr);
}

String getPcapFilePath() {
    std::lock_guard<std::mutex> lock(g_pathMutex);
    return g_path;
}

bool pcapNameIsValid(const String &name) {
    if (name.length() < 6 || name.length() > 64) return false;
    if (!name.endsWith(".pcap")) return false;
    for (size_t i = 0; i < name.length(); i++) {
        const char c = name[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return name.indexOf("..") < 0;
}

// cppcheck-suppress unusedFunction // pcap.h API, called from network.cpp in the full tree
String getPcapListJson() {
    String j = "[";
    if (!SafeSD::isAvailable()) return j + "]";

    fs::File dir = SafeSD::open(PCAP_DIR);
    if (!dir || !dir.isDirectory()) {
        if (dir) dir.close();
        return j + "]";
    }

    const String activePath = g_active ? getPcapFilePath() : String("");
    bool first = true;
    for (fs::File f = dir.openNextFile(); f; f = dir.openNextFile()) {
        if (f.isDirectory()) { f.close(); continue; }
        String name = f.name();
        const int slash = name.lastIndexOf('/');
        if (slash >= 0) name = name.substring(slash + 1);
        if (!name.endsWith(".pcap")) { f.close(); continue; }
        if (!first) j += ",";
        first = false;
        j += "{\"name\":\"" + jsonEscape(name) + "\",\"size\":" + String((uint32_t)f.size());
        j += ",\"active\":" + String(activePath.endsWith(name) ? "true" : "false") + "}";
        f.close();
    }
    dir.close();
    return j + "]";
}

bool pcapDeleteFile(const String &name) {
    if (!pcapNameIsValid(name) || !SafeSD::isAvailable()) return false;
    const String path = String(PCAP_DIR) + "/" + name;
    if (g_active && getPcapFilePath() == path) return false;
    if (!SafeSD::exists(path.c_str())) return false;
    return SafeSD::remove(path.c_str());
}

// cppcheck-suppress unusedFunction // pcap.h API, called from network.cpp in the full tree
uint32_t pcapDeleteAll() {
    if (!SafeSD::isAvailable()) return 0;

    std::vector<String> names;
    fs::File dir = SafeSD::open(PCAP_DIR);
    if (!dir || !dir.isDirectory()) {
        if (dir) dir.close();
        return 0;
    }
    for (fs::File f = dir.openNextFile(); f; f = dir.openNextFile()) {
        if (!f.isDirectory()) {
            String name = f.name();
            const int slash = name.lastIndexOf('/');
            if (slash >= 0) name = name.substring(slash + 1);
            if (name.endsWith(".pcap")) names.push_back(name);
        }
        f.close();
    }
    dir.close();

    uint32_t removed = 0;
    for (const String &n : names) {
        if (pcapDeleteFile(n)) removed++;
    }
    return removed;
}

static String pcapSummary(bool inProgress) {
    String s = "Packet Capture - ";
    s += (g_radio == PCAP_RADIO_BLE) ? "BLE" : "WiFi";
    if (g_radio == PCAP_RADIO_WIFI) {
        s += " ch" + String(g_curChan.load());
    }
    s += inProgress ? " (IN PROGRESS)\n" : "\n";
    s += "File: " + getPcapFilePath() + "\n";
    s += "Frames: " + String(g_frames.load()) + "\n";
    s += "Bytes: " + String(g_bytes.load()) + "\n";
    s += "Dropped: " + String(g_dropped.load()) + "\n";
    uint32_t span = ((inProgress ? millis() : g_endMs) - g_startMs) / 1000;
    s += "Elapsed: " + String(span) + "s\n";
    return s;
}

// cppcheck-suppress unusedFunction // pcap.h API, called from network.cpp in the full tree
String getPcapStatusJson() {
    String j = "{";
    j += "\"active\":" + String(g_active ? "true" : "false");
    // cppcheck-suppress knownConditionTrueFalse // constant per target, true on C5
    j += ",\"dualBand\":" + String(pcapDualBandCapable() ? "true" : "false");
    j += ",\"radio\":" + String(g_radio);
    j += ",\"band\":" + String(g_band);
    j += ",\"channel\":" + String(g_curChan.load());
    j += ",\"frames\":" + String(g_frames.load());
    j += ",\"bytes\":" + String(g_bytes.load());
    j += ",\"dropped\":" + String(g_dropped.load());
    j += ",\"elapsed\":" + String((((g_active ? millis() : g_endMs) - g_startMs) / 1000));
    j += ",\"file\":\"" + jsonEscape(getPcapFilePath()) + "\"";
    j += ",\"sd\":" + String(SafeSD::isAvailable() ? "true" : "false");
    j += ",\"budgetMB\":" + String(g_autoBudgetMB.load());
    j += ",\"floorMB\":" + String(g_freeFloorMB.load());
    j += ",\"freeMB\":" + String(SafeSD::isAvailable() ? (uint32_t)(pcapSdFreeBytes() / (1024ULL * 1024ULL)) : 0);
    j += "}";
    return j;
}

static void pcapAbort(const char *why) {
    Serial.printf("[PCAP] %s\n", why);
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = std::string("Packet Capture\n\n") + why + "\n";
    }
    pcapBleEnabled.store(false);
    pcapFreeBuffers();
    g_autoTriggered = false;
    scanning = false;
    scanSetCountdown(0, false);
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void pcapCaptureTask(void *pv) {
    sentinel_yieldAndWait(1500);

    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int *>(pv)));
    bool forever = (duration <= 0);

    if (!SafeSD::isAvailable()) {
        pcapAbort("No SD card - packet capture needs SD storage");
        return;
    }
    if (!SafeSD::exists(PCAP_DIR) && !SafeSD::mkdir(PCAP_DIR)) {
        pcapAbort("Could not create /pcap on SD");
        return;
    }
    if (g_autoTriggered) {
        pcapPruneAuto();
    }
    {
        const uint64_t freeNow = pcapSdFreeBytes();
        const uint64_t floorB = (uint64_t)g_freeFloorMB.load() * 1024ULL * 1024ULL;
        const uint64_t needB = floorB > PCAP_MIN_FREE_BYTES ? floorB : (uint64_t)PCAP_MIN_FREE_BYTES;
        if (freeNow < needB) {
            String msg = "SD below the free-space floor - capture refused (" +
                         String((unsigned long)(freeNow / (1024ULL * 1024ULL))) + "MB free, need " +
                         String((unsigned long)(needB / (1024ULL * 1024ULL))) + "MB)";
            pcapAbort(msg.c_str());
            return;
        }
    }
    if (!pcapAllocBuffers()) {
        pcapAbort("Capture buffer allocation failed");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_pathMutex);
        g_path = pcapMakePath();
    }

    fs::File f = SafeSD::open(getPcapFilePath().c_str(), FILE_WRITE);
    if (!f) {
        pcapAbort("Could not open capture file on SD");
        return;
    }
    if (!pcapWriteGlobalHeader(f)) {
        f.close();
        pcapAbort("Could not write pcap header");
        return;
    }

    g_frames.store(0);
    g_bytes.store(0);
    g_writeFails.store(0);
    g_stopReasonSize.store(false);
    g_stopReasonWrite.store(false);
    g_dropped.store(0);
    g_startMs = millis();
    g_endMs = 0;
    g_baseEpoch = (uint32_t)getRTCEpoch();
    g_baseMicros = micros();

    pcapBuildHopList();

    if (g_radio == PCAP_RADIO_WIFI) {
        if (!pcapRadioStartWifi()) {
            f.close();
            pcapAbort("WiFi promiscuous mode failed to start");
            return;
        }
    } else {
        pcapBleEnabled.store(true);
        if (!radioStartBLEChecked()) {
            pcapBleEnabled.store(false);
            f.close();
            pcapAbort("BLE radio unavailable");
            return;
        }
    }

    scanning = true;
    stopRequested = false;
    scanStopPending.store(false);
    scanSetCountdown(duration, forever);
    g_active = true;

    Serial.println("[PCAP] Warning: resetting or losing power while a capture is running can "
                   "corrupt the SD filesystem. FAT has no power-fail protection. Stop the capture "
                   "before power-cycling.");
    Serial.printf("[PCAP] Started %s -> %s %s\n",
                  g_radio == PCAP_RADIO_BLE ? "BLE" : "WiFi",
                  getPcapFilePath().c_str(),
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    if (meshEnabled) {
        meshEnqueue(getNodeId() + ": PCAP_START: " +
                    String(g_radio == PCAP_RADIO_BLE ? "BLE" : "WIFI") +
                    " D=" + String(forever ? 0 : duration));
    }

    uint32_t lastHop = millis();
    uint32_t lastFlush = millis();
    uint32_t lastResults = 0;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - g_startMs) < duration * 1000 && !stopRequested)) {

        pcapDrain(f);

        const uint32_t now = millis();

        if (g_radio == PCAP_RADIO_WIFI && g_hopLen > 1 && now - lastHop >= g_dwellMs) {
            g_hopIdx = (uint8_t)((g_hopIdx + 1) % g_hopLen);
            esp_wifi_set_channel(g_hopList[g_hopIdx], WIFI_SECOND_CHAN_NONE);
            g_curChan.store(g_hopList[g_hopIdx]);
            lastHop = now;
        }

        if (now - lastFlush >= 2000) {
            lastFlush = now;
            const uint64_t capB = (uint64_t)g_maxFileMB.load() * 1024ULL * 1024ULL;
            if ((uint64_t)f.size() >= capB) {
                g_stopReasonSize.store(true);
                stopRequested = true;
                Serial.printf("[PCAP] stopping: file reached the %u MB cap\n",
                              (unsigned)g_maxFileMB.load());
            }
        }

        if (now - lastResults >= 1000) {
            lastResults = now;
            String s = pcapSummary(true);
            std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
            antihunter::lastResults = std::string(s.c_str());
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }

    g_active = false;

    if (g_radio == PCAP_RADIO_WIFI) {
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        vTaskDelay(pdMS_TO_TICKS(50));
        radioStopSTA();
    } else {
        pcapBleEnabled.store(false);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    pcapDrain(f);
    pcapDrain(f);
    SafeSD::flush(f);
    uint32_t fileSize = (uint32_t)f.size();
    f.close();

    g_endMs = millis();
    pcapFreeBuffers();

    const char *why = g_stopReasonWrite.load() ? " (stopped: card refused writes)"
                    : g_stopReasonSize.load()  ? " (stopped: size cap)"
                                               : "";
    Serial.printf("[PCAP] Stopped: %u frames, %u bytes, %u dropped, file %u bytes%s\n",
                  g_frames.load(), g_bytes.load(), g_dropped.load(), fileSize, why);

    {
        String s = pcapSummary(false);
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = std::string(s.c_str());
    }

    if (meshEnabled) {
        meshEnqueue(getNodeId() + ": PCAP_DONE: F=" + String(g_frames.load()) +
                    " B=" + String(g_bytes.load()) + " D=" + String(g_dropped.load()) +
                    (g_stopReasonWrite.load() ? " R=WRITEFAIL"
                     : g_stopReasonSize.load() ? " R=SIZECAP" : ""));
    }

    logToSD("PCAP: " + getPcapFilePath() + " frames=" + String(g_frames.load()) +
            " bytes=" + String(g_bytes.load()) + " dropped=" + String(g_dropped.load()));

    g_autoTriggered = false;
    scanning = false;
    scanSetCountdown(0, false);
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}
