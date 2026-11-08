#include "main.h"
#include "triangulation.h"
#include "campaign.h"
#include <SPI.h>
#include <algorithm>
#include <Arduino.h>
#include <Preferences.h>
#include "network.h"
#include "scanner.h"
#include "hardware.h"
#include "detect.h"
#include "meshcore_link.h"
#include <SD.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_cpu.h"
#include "soc/soc_caps.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "bootloader_random.h"

#ifdef ARDUINO_XIAO_ESP32C5
#include "esp_private/startup_internal.h"
#endif
#if defined(ARDUINO_XIAO_ESP32C5) && !defined(AH_NO_MAC_BOOT_RESET)
#include "hal/modem_syscon_ll.h"

ESP_SYSTEM_INIT_FN(ah_mac_boot_reset, CORE, BIT(0), 2)
{
    modem_syscon_ll_reset_wifimac(&MODEM_SYSCON);
    return ESP_OK;
}
#endif
#if defined(ARDUINO_XIAO_ESP32C5) && AH_HEAP_TRACE
static uint32_t g_macBeforeHeap[5], g_macAfterHeap[5];

static void macRegsRead(uint32_t *out) {
    for (int i = 0; i < 5; i++) out[i] = *(volatile uint32_t *)(0x600A4080u + 4u * i);
}

ESP_SYSTEM_INIT_FN(ah_mac_before_heap, CORE, BIT(0), 99)
{
    macRegsRead(g_macBeforeHeap);
    return ESP_OK;
}

ESP_SYSTEM_INIT_FN(ah_mac_after_heap, CORE, BIT(0), 104)
{
    macRegsRead(g_macAfterHeap);
    return ESP_OK;
}

void macRegsPrint(const char *tag) {
    uint32_t now[5];
    macRegsRead(now);
    Serial.printf("[MACREG] %s rst=%d before_heap: %08x %08x %08x %08x %08x after_heap: %08x %08x %08x %08x %08x now: %08x %08x %08x %08x %08x\n",
                  tag, (int)esp_reset_reason(),
                  (unsigned)g_macBeforeHeap[0], (unsigned)g_macBeforeHeap[1], (unsigned)g_macBeforeHeap[2], (unsigned)g_macBeforeHeap[3], (unsigned)g_macBeforeHeap[4],
                  (unsigned)g_macAfterHeap[0], (unsigned)g_macAfterHeap[1], (unsigned)g_macAfterHeap[2], (unsigned)g_macAfterHeap[3], (unsigned)g_macAfterHeap[4],
                  (unsigned)now[0], (unsigned)now[1], (unsigned)now[2], (unsigned)now[3], (unsigned)now[4]);
    Serial.flush();
}
#endif

#ifndef AH_EXTMEM_THRESHOLD
#define AH_EXTMEM_THRESHOLD 16
#endif


#ifdef ARDUINO_XIAO_ESP32C5
#include "freertos/idf_additions.h"
// C5: CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y, so long-lived task stacks belong in PSRAM
#define AH_TASK_CREATE(fn, nm, st, arg, pr, hd, co) \
    xTaskCreatePinnedToCoreWithCaps(fn, nm, st, arg, pr, hd, co, MALLOC_CAP_SPIRAM)
#else
#define AH_TASK_CREATE(fn, nm, st, arg, pr, hd, co) \
    xTaskCreatePinnedToCore(fn, nm, st, arg, pr, hd, co)
#endif

SET_LOOP_TASK_STACK_SIZE(5120);

Preferences prefs;
ScanMode currentScanMode = SCAN_WIFI;
std::vector<uint8_t> CHANNELS = DEFAULT_CHANNELS;
std::atomic<bool> stopRequested(false);

unsigned long lastRTCUpdate = 0;

TaskHandle_t workerTaskHandle = nullptr;
TaskHandle_t blueTeamTaskHandle = nullptr;
extern std::atomic<bool> scanning;

std::string antihunter::lastResults = "No scan data yet.";
std::mutex antihunter::lastResultsMutex;

static void meshRxProcessLine(const String &line, uint32_t lastRxMicros) {
  if (line.length() == 0) return;
  if (!line.startsWith("[")) Serial.printf("[MESH RX] %s\n", meshRedactSecrets(line).c_str());

  String toProcess, senderId;
  meshSplitSender(line, senderId, toProcess);

  mesh_observeInbound(senderId, toProcess);
  meshFleetObserve(senderId, toProcess);
  detect_fleetObserve(senderId, line);

  if (toProcess.startsWith("TIME_SYNC_REQ:")) {
    processMeshTimeSyncWithDelay(senderId, toProcess, lastRxMicros);
  } else if (toProcess.startsWith("PMKID_HARVEST:") ||
             toProcess.startsWith("EVILTWIN:") ||
             toProcess.startsWith("SAE_DOS:") ||
             toProcess.startsWith("DEAUTH_FLOOD:") ||
             toProcess.startsWith("BEACON_FORGE:") ||
             toProcess.startsWith("PMKID_FORGE:") ||
             toProcess.startsWith("EAPOL_BAIT:") ||
             toProcess.startsWith("PROBE_FLOOD:") ||
             toProcess.startsWith("PROBE_FLOOD_BEHAVE:") ||
             toProcess.startsWith("ASSOC_SLEEP:") ||
             toProcess.startsWith("RECON:") ||
             toProcess.startsWith("RID_CLAIM:") ||
             toProcess.startsWith("RID_RX:") ||
             toProcess.startsWith("BLOOM:") ||
             toProcess.startsWith("CHAN_ASSIGN:") ||
             toProcess.startsWith("FRAG:") ||
             toProcess.startsWith("IDHASH:") ||
             toProcess.startsWith("HSHK:") ||
             toProcess.startsWith("KRACK:") ||
             toProcess.startsWith("ATTACKER_HUNT:") ||
             toProcess.startsWith("PWNAGOTCHI:") ||
             toProcess.startsWith("RADIO_DETECTED:") ||
             toProcess.startsWith("JAMMING:") ||
             toProcess.startsWith("BEACON_FLOOD:") ||
             toProcess.startsWith("AUTH_FLOOD:") ||
             toProcess.startsWith("DEAUTH_FORGE:") ||
             toProcess.startsWith("DEAUTH_AP_TARGETED:") ||
             toProcess.startsWith("OWE_ABUSE:") ||
             toProcess.startsWith("PROBE_FLOOD_AP:") ||
             toProcess.startsWith("SSID_CONFUSION:") ||
             toProcess.startsWith("CSA_SPOOF:") ||
             toProcess.startsWith("QUIET_ABUSE:") ||
             toProcess.startsWith("MESH_FLOOD:") ||
             toProcess.startsWith("MESH_SPOOF_SELF:") ||
             toProcess.startsWith("JAMMING_BASELINE:") ||
             toProcess.startsWith("KARMA_CAND:") ||
             toProcess.startsWith("KARMA_CONFIRMED:") ||
             toProcess.startsWith("TOF_PING:") ||
             toProcess.startsWith("TOF_PONG:") ||
             toProcess.startsWith("FLEET_AP:") ||
             toProcess.startsWith("FLEET_RADIO:")) {
    detect_processMesh(senderId, toProcess);
  } else {
    processMeshMessage(line);
  }
}

void uartForwardTask(void *parameter) {
  static String meshBuffer = "";

  for (;;) {
    String rxChunk = "";
    uint32_t lastRxMicros = 0;
    if (serial1Mutex != nullptr && xSemaphoreTake(serial1Mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
      const size_t MAX_DRAIN_BYTES = 256;
      size_t drained = 0;
      while (Serial1.available() && drained < MAX_DRAIN_BYTES) {
        rxChunk += (char)Serial1.read();
        lastRxMicros = micros();
        drained++;
      }
      xSemaphoreGive(serial1Mutex);
    }

    for (size_t i = 0; i < rxChunk.length(); i++) {
      char c = rxChunk[i];
#if defined(AH_USB_ECHO) && (AH_USB_ECHO)
      Serial.write(c);
#endif

      if (g_meshcoreTransport) {
        String mcLine;
        if (meshcoreFeedByte((uint8_t)c, mcLine)) meshRxProcessLine(mcLine, lastRxMicros);
        continue;
      }

      if (c == '\n' || c == '\r') {
        meshRxProcessLine(meshBuffer, lastRxMicros);
        meshBuffer = "";
      } else {
        meshBuffer += c;
        if (meshBuffer.length() > 1024) {
          meshBuffer = "";
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}

String macFmt6(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", 
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
}

bool parseMac6(const String &in, uint8_t out[6]) {
    String t;
    for (size_t i = 0; i < in.length(); ++i) {
        char c = in[i];
        if (isxdigit((int)c)) t += (char)toupper(c);
    }
    if (t.length() != 12) return false;
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    return true;
}

inline uint16_t u16(const uint8_t *p) { 
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8); 
}

bool isZeroOrBroadcast(const uint8_t *mac) {
    bool all0 = true, allF = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) all0 = false;
        if (mac[i] != 0xFF) allF = false;
    }
    return all0 || allF;
}

static bool isValidChannel(int ch) {
    if (ch >= 1 && ch <= 14) return true;
#ifdef ARDUINO_XIAO_ESP32C5
    switch (ch) {
        case 36: case 40: case 44: case 48:
        case 149: case 153: case 157: case 161: case 165:
            return true;
    }
#endif
    return false;
}

void parseChannelsCSV(const String &csv) {
    CHANNELS.clear();
    if (csv.indexOf("..") >= 0) {
        int a = csv.substring(0, csv.indexOf("..")).toInt();
        int b = csv.substring(csv.indexOf("..") + 2).toInt();
        if (a < 1) a = 1;
        if (b > 255) b = 255;
        for (int ch = a; ch <= b; ch++) {
            if (isValidChannel(ch)) CHANNELS.push_back((uint8_t)ch);
        }
    } else {
        int start = 0;
        while (start < csv.length()) {
            int comma = csv.indexOf(',', start);
            if (comma < 0) comma = csv.length();
            int ch = csv.substring(start, comma).toInt();
            if (isValidChannel(ch)) CHANNELS.push_back((uint8_t)ch);
            start = comma + 1;
        }
    }
    if (CHANNELS.empty()) CHANNELS = DEFAULT_CHANNELS;
    const bool hasAp = std::any_of(CHANNELS.begin(), CHANNELS.end(),
        [](uint8_t ch) { return ch == (uint8_t)AP_CHANNEL; });
    if (!hasAp) CHANNELS.push_back((uint8_t)AP_CHANNEL);
    rebuildActiveChannels();
}

void sendNodeIdUpdate() {
    float esp_temp = temperatureRead();
    String timestamp = getFormattedTimestamp();
    timestamp.replace(" ", "_");

    String nodeMsg = getNodeId() + ": Time:" + timestamp + " Temp:" + String(esp_temp, 1) + "C";

    if (gpsValid) {
        nodeMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }

    if (!triangulationActive && hbEnabled) {
        Serial.println(nodeMsg);
        sendToSerial1(nodeMsg, true);
    }
}

void randomizeMacAddress() {
    uint8_t newMACAddress[6];
    newMACAddress[0] = (random(0, 256) & 0xFE) | 0x02;
    for (int i = 1; i < 6; i++) {
        newMACAddress[i] = random(0, 256);
    }
    esp_err_t err = esp_wifi_set_mac(WIFI_IF_AP, newMACAddress);
    Serial.printf("[MAC] Randomized MAC: %02x:%02x:%02x:%02x:%02x:%02x (status: %d)\n",
                  newMACAddress[0], newMACAddress[1], newMACAddress[2],
                  newMACAddress[3], newMACAddress[4], newMACAddress[5], err);
}


#ifndef AH_HEAP_TRACE
#define AH_HEAP_TRACE 0
#endif
#if AH_HEAP_TRACE
struct HeapScanCtx {
    uintptr_t prevPtr, prevSize, hStart, hEnd, blk, size, dumpAt, dataAt;
    uint32_t w0, w1;
    int kind;
    uint8_t dump[256];
    uint8_t data[32];
};

static void heapScanCopy(uint8_t *dst, size_t n, uintptr_t at, uintptr_t lo, uintptr_t hi) {
    for (size_t i = 0; i < n; i++) {
        uintptr_t a = at + i;
        dst[i] = (a >= lo && a < hi) ? *(volatile uint8_t *)a : 0;
    }
}

static bool heapScanWalker(walker_heap_into_t hi, walker_block_info_t bi, void *u) {
    HeapScanCtx *c = (HeapScanCtx *)u;
    const uintptr_t lo = (uintptr_t)hi.start, top = (uintptr_t)hi.end, p = (uintptr_t)bi.ptr;
    int kind = 0;
    uint32_t w0 = 0, w1 = 0;
    uintptr_t failAt = p;
    if (p < lo || p >= top || bi.size > (size_t)(top - p)) {
        kind = 1;
    } else if (bi.used && bi.size >= 12) {
        memcpy(&w0, (const void *)p, 4);
        memcpy(&w1, (const void *)(p + 4), 4);
        if (w0 != 0xABBA1234u) {
            kind = 2;
        } else if (w1 > bi.size - 12) {
            kind = 3;
        } else {
            uint32_t t;
            failAt = p + 8 + w1;
            memcpy(&t, (const void *)failAt, 4);
            if (t != 0xBAAD5678u) kind = 4;
        }
    }
    if (!kind) {
        c->prevPtr = p;
        c->prevSize = bi.size;
        return true;
    }
    c->kind = kind;
    c->blk = p;
    c->size = bi.size;
    c->w0 = w0;
    c->w1 = w1;
    c->hStart = lo;
    c->hEnd = top;
    c->dumpAt = failAt - 128;
    c->dataAt = p + 8;
    heapScanCopy(c->dump, sizeof(c->dump), c->dumpAt, lo, top);
    heapScanCopy(c->data, sizeof(c->data), c->dataAt, lo, top);
    return false;
}

static void heapScanHex(const char *label, uintptr_t at, const uint8_t *b, size_t n) {
    for (size_t off = 0; off < n; off += 16) {
        Serial.printf("[HEAPSCAN] %s %08x:", label, (unsigned)(at + off));
        for (size_t i = 0; i < 16 && off + i < n; i++) Serial.printf(" %02x", b[off + i]);
        Serial.print("  |");
        for (size_t i = 0; i < 16 && off + i < n; i++) Serial.print(isprint(b[off + i]) ? (char)b[off + i] : '.');
        Serial.println("|");
    }
}

void allocDump();

void heapScan(const char *tag) {
    static bool reported = false;
    if (reported) return;
    static HeapScanCtx c;
    memset(&c, 0, sizeof(c));
    heap_caps_walk(MALLOC_CAP_INTERNAL, heapScanWalker, &c);
    if (!c.kind) return;
    reported = true;
    static const char *const kKind[] = {"", "block-size-out-of-heap", "bad-head-canary", "bad-alloc-size", "bad-tail-canary"};
    Serial.printf("\n[HEAPSCAN] CORRUPT at=%s ms=%lu kind=%s blk=%08x size=%u head=%08x alloc=%u heap=%08x-%08x prev=%08x prevsize=%u\n",
                  tag, (unsigned long)millis(), kKind[c.kind], (unsigned)c.blk, (unsigned)c.size,
                  (unsigned)c.w0, (unsigned)c.w1, (unsigned)c.hStart, (unsigned)c.hEnd,
                  (unsigned)c.prevPtr, (unsigned)c.prevSize);
    heapScanHex("fail", c.dumpAt, c.dump, sizeof(c.dump));
    heapScanHex("data", c.dataAt, c.data, sizeof(c.data));
    allocDump();
    Serial.flush();
}

struct AllocRec {
    uintptr_t ra, ptr;
    uint32_t size, caps;
};
static AllocRec g_allocRec[32];
static volatile uint32_t g_allocRecN = 0;

static void *volatile g_wpPtr[SOC_CPU_WATCHPOINTS_NUM];
static volatile uint32_t g_wpN = 0;
static volatile uint32_t g_wpSet = 0;
static volatile uint32_t g_wpCleared = 0;

void wpSelfTest() {
#ifdef AH_WP_TEST
    for (int i = SOC_CPU_WATCHPOINTS_NUM - 1; i >= 0; i--) {
        if (!g_wpPtr[i]) continue;
        volatile uint32_t *t = (volatile uint32_t *)(((uintptr_t)g_wpPtr[i] + 796) & ~(uintptr_t)3);
        Serial.printf("[WPTEST] storing to tail %08x\n", (unsigned)(uintptr_t)t);
        Serial.flush();
        *t = 0xBAAD5678u;
        Serial.println("[WPTEST] store returned, watchpoint did not fire");
        return;
    }
    Serial.println("[WPTEST] no watched block");
#endif
}

void allocDump() {
    const uint32_t nrec = g_allocRecN < 32 ? g_allocRecN : 32;
    Serial.printf("[ALLOCREC] n=%u wpset=%u wpcleared=%u\n", (unsigned)nrec, (unsigned)g_wpSet, (unsigned)g_wpCleared);
    for (uint32_t i = 0; i < nrec; i++)
        Serial.printf("[ALLOCREC] ra=%08x ptr=%08x size=%u caps=%08x\n", (unsigned)g_allocRec[i].ra,
                      (unsigned)g_allocRec[i].ptr, (unsigned)g_allocRec[i].size, (unsigned)g_allocRec[i].caps);
}

static void allocNote(void *p, size_t size, uint32_t caps, void *ra) {
    if (size != 796 && (size < 2200 || size > 2232)) return;
    uint32_t i = __atomic_fetch_add(&g_allocRecN, 1, __ATOMIC_RELAXED);
    if (i < 32) g_allocRec[i] = {(uintptr_t)ra, (uintptr_t)p, (uint32_t)size, caps};
    if (size == 796 && p) {
        uint32_t slot = g_wpN++ % SOC_CPU_WATCHPOINTS_NUM;
        g_wpPtr[slot] = p;
        const uintptr_t tail = ((uintptr_t)p + size) & ~(uintptr_t)3;
        if (esp_cpu_set_watchpoint(slot, (const void *)tail, 4, ESP_CPU_WATCHPOINT_STORE) == ESP_OK) g_wpSet = g_wpSet + 1;
    }
}

extern "C" {
void *__real_heap_caps_malloc(size_t size, uint32_t caps);
void *__real_heap_caps_calloc(size_t n, size_t size, uint32_t caps);
void *__real_heap_caps_malloc_prefer(size_t size, size_t num, ...);
void *__real_heap_caps_aligned_alloc(size_t alignment, size_t size, uint32_t caps);
void *__real_heap_caps_malloc_default(size_t size);
void __real_heap_caps_free(void *p);

void *__wrap_heap_caps_malloc_default(size_t size) {
    void *p = __real_heap_caps_malloc_default(size);
    allocNote(p, size, 0, __builtin_return_address(0));
    return p;
}
void __wrap_heap_caps_free(void *p) {
    if (p) {
        for (int i = 0; i < SOC_CPU_WATCHPOINTS_NUM; i++) {
            if (g_wpPtr[i] == p) {
                esp_cpu_clear_watchpoint(i);
                g_wpPtr[i] = nullptr;
                g_wpCleared = g_wpCleared + 1;
            }
        }
    }
    __real_heap_caps_free(p);
}

void *IRAM_ATTR __wrap_heap_caps_malloc(size_t size, uint32_t caps) {
    void *p = __real_heap_caps_malloc(size, caps);
    allocNote(p, size, caps, __builtin_return_address(0));
    return p;
}
void *IRAM_ATTR __wrap_heap_caps_calloc(size_t n, size_t size, uint32_t caps) {
    void *p = __real_heap_caps_calloc(n, size, caps);
    allocNote(p, n * size, caps, __builtin_return_address(0));
    return p;
}
void *IRAM_ATTR __wrap_heap_caps_malloc_prefer(size_t size, size_t num, uint32_t c1, uint32_t c2, uint32_t c3) {
    void *p = __real_heap_caps_malloc_prefer(size, num, c1, c2, c3);
    allocNote(p, size, c1, __builtin_return_address(0));
    return p;
}
void *IRAM_ATTR __wrap_heap_caps_aligned_alloc(size_t alignment, size_t size, uint32_t caps) {
    void *p = __real_heap_caps_aligned_alloc(alignment, size, caps);
    allocNote(p, size, caps, __builtin_return_address(0));
    return p;
}
}

struct HeapMapEntry {
    uint32_t off, size, w0, w1, w2, w3;
    uintptr_t region;
    bool used;
};
struct HeapMapCtx {
    HeapMapEntry e[96];
    int n;
    uint32_t lo, hi;
};

static bool heapMapWalker(walker_heap_into_t hi, walker_block_info_t bi, void *u) {
    HeapMapCtx *c = (HeapMapCtx *)u;
    const uintptr_t p = (uintptr_t)bi.ptr;
    if (p < (uintptr_t)hi.start || p >= (uintptr_t)hi.end || bi.size > (size_t)(hi.end - p)) return false;
    const uint32_t off = (uint32_t)(p - (uintptr_t)hi.start);
    if (off < c->lo || off > c->hi || c->n >= 96) return true;
    HeapMapEntry &e = c->e[c->n++];
    e.off = off;
    e.size = bi.size;
    e.used = bi.used;
    e.region = (uintptr_t)hi.start;
    uint32_t w[4] = {0, 0, 0, 0};
    memcpy(w, (const void *)p, bi.size >= 16 ? 16 : (bi.size & ~3u));
    e.w0 = w[0]; e.w1 = w[1]; e.w2 = w[2]; e.w3 = w[3];
    return true;
}

static void heapMapDump(const char *tag) {
    static HeapMapCtx c;
    memset(&c, 0, sizeof(c));
    c.lo = 40 * 1024;
    c.hi = 80 * 1024;
    heap_caps_walk(MALLOC_CAP_INTERNAL, heapMapWalker, &c);
    Serial.printf("[HEAPMAP] %s blocks=%d (offset 40-80 KB)\n", tag, c.n);
    const uint32_t nrec = g_allocRecN < 32 ? g_allocRecN : 32;
    for (uint32_t i = 0; i < nrec; i++)
        Serial.printf("[ALLOCREC] %s ra=%08x ptr=%08x off=%d size=%u caps=%08x\n", tag, (unsigned)g_allocRec[i].ra,
                      (unsigned)g_allocRec[i].ptr,
                      c.n ? (int)(g_allocRec[i].ptr - c.e[0].region) : -1, (unsigned)g_allocRec[i].size,
                      (unsigned)g_allocRec[i].caps);
    for (int i = 0; i < c.n; i++) {
        const HeapMapEntry &e = c.e[i];
        Serial.printf("[HEAPMAP] %s reg=%08x off=%6u size=%5u %s %08x %08x %08x %08x\n", tag, (unsigned)e.region,
                      (unsigned)e.off, (unsigned)e.size, e.used ? "U" : "F", (unsigned)e.w0, (unsigned)e.w1,
                      (unsigned)e.w2, (unsigned)e.w3);
    }
    Serial.flush();
}

static void heapMark(const char *tag) {
    heapScan(tag);
    if (strcmp(tag, "after network+AP+web") == 0 || strcmp(tag, "after DetectTask") == 0) heapMapDump(tag);
    Serial.printf("[HEAPTRACE] %-22s internal=%6u largest=%6u psram=%u\n", tag,
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}
static void dumpTaskStacks(const char *tag) {
    UBaseType_t n = uxTaskGetNumberOfTasks();
    TaskStatus_t *ts = (TaskStatus_t *)heap_caps_malloc(sizeof(TaskStatus_t) * n, MALLOC_CAP_SPIRAM);
    if (!ts) ts = (TaskStatus_t *)malloc(sizeof(TaskStatus_t) * n);
    if (!ts) { Serial.println("[STACKS] alloc failed"); return; }
    n = uxTaskGetSystemState(ts, n, nullptr);
    Serial.printf("[STACKS] %s (%u tasks) name / unused-stack-bytes / prio\n", tag, (unsigned)n);
    for (UBaseType_t i = 0; i < n; i++)
        Serial.printf("[STACKS]   %-18s %6u  p%u\n", ts[i].pcTaskName,
                      (unsigned)ts[i].usStackHighWaterMark, (unsigned)ts[i].uxCurrentPriority);
    free(ts);
}
#else
static void heapMark(const char *) {}
static void dumpTaskStacks(const char *) {}
#endif

static void randomizeRadioIdentity() {
    static const esp_mac_type_t kTypes[] = {ESP_MAC_BASE, ESP_MAC_WIFI_STA, ESP_MAC_WIFI_SOFTAP, ESP_MAC_BT};
    bootloader_random_enable();
    for (esp_mac_type_t t : kTypes) {
        uint8_t mac[6];
        esp_fill_random(mac, sizeof(mac));
        mac[0] = (uint8_t)((mac[0] & 0xFE) | 0x02);
        esp_err_t err = esp_iface_mac_addr_set(mac, t);
        Serial.printf("[MAC] type=%d %02x:%02x:%02x:%02x:%02x:%02x (status: %d)\n", (int)t,
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], err);
    }
    bootloader_random_disable();
}

void memMark(const char *what) {
    Serial.printf("[MEM] %-16s internal=%u largest=%u psram=%u tasks=%u\n", what,
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                  (unsigned)uxTaskGetNumberOfTasks());
}

#ifdef ARDUINO_XIAO_ESP32C5
void ahPsramBarrierInit(void);
#endif

// cppcheck-suppress unusedFunction // Arduino entry point, called by the framework
void setup() {
    delay(1000);
    Serial.begin(115200);
    delay(300);

    Serial.println("\n=== AntiHunter v1.0.5-c5exp1 C5 [FULL] Boot ===");
    Serial.printf("[BUILD] sha=%s epoch=%lu\n", AH_GIT_SHA, (unsigned long)AH_BUILD_EPOCH);
    randomizeRadioIdentity();
    recordBootReason();


#ifdef ARDUINO_XIAO_ESP32C5
    // C5 has 320KB HP SRAM and the image eats 180KB; without this the 4096B ALWAYSINTERNAL default starves WiFi
    if (psramFound()) heap_caps_malloc_extmem_enable(AH_EXTMEM_THRESHOLD);
    ahPsramBarrierInit();
    Serial.printf("[MEM] C5: PSRAM heap routing on (>=%uB -> PSRAM; WiFi/LWIP + ISR queues internal). psram_free=%u internal_free=%u\n",
                  (unsigned)AH_EXTMEM_THRESHOLD,
                  (unsigned)ESP.getFreePsram(), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
#else
    if (psramFound()) {
        heap_caps_malloc_extmem_enable(64);
        Serial.printf("[MEM] PSRAM heap routing on (>=64B -> PSRAM). psram_free=%u internal_free=%u\n",
                      (unsigned)ESP.getFreePsram(), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    }
#endif

    delay(400);
    initializeHardware();
    heapMark("after hardware");
    delay(10);
    initializeDroneDetector();
    heapMark("after drone");
    delay(20);
    initializeSD();
    heapMark("after SD");
    logBootRecord();
    if (!wasCleanBoot()) loadResultsSnapshot();


    if (waitForInitialConfig()) {
        delay(1000);
    }

    delay(500);
    loadConfiguration();
    meshcoreLoadPref();
    calibrationLoad();
    campaignInit();
    heapMark("after config");

    Serial.println("Waiting for mesh device stability...");
    delay(10000);

    initializeNetwork();
    ensureErasePSK();
    heapMark("after network+AP+web");
    delay(500);
    initializeGPS();
    heapMark("after GPS");
    delay(1000);
    initializeRTC();
    heapMark("after RTC");
    delay(500);
    
    initializeVibrationSensor();
    delay(50);
    initializeScanner();
    heapMark("after scanner");
    delay(50);
    initializeDetect();
    heapMark("after detect");
    delay(50);
#ifdef ARDUINO_XIAO_ESP32C5
    initializeGpsPps(4);
#else
    initializeGpsPps(21);
#endif
    if (AH_TASK_CREATE(detectTask, "DetectTask", 8192, NULL, 3, NULL, SCAN_CORE) != pdPASS)
        Serial.println("[BOOT] ERROR: DetectTask create failed - detection/sentinel inactive");
    heapMark("after DetectTask");
    dumpTaskStacks("boot");
    {
        uint8_t selfMac[6];
        esp_wifi_get_mac(WIFI_IF_AP, selfMac);
        String ssid = prefsGetString("apSsid", AP_SSID);
        if (ssid.length() == 0) ssid = AP_SSID;
        detect_setSelfApIdentity(selfMac, ssid.c_str());
        Serial.printf("[SENTINEL] self-filter mac=%02X:%02X:%02X:%02X:%02X:%02X ssid=%s\n",
                      selfMac[0],selfMac[1],selfMac[2],selfMac[3],selfMac[4],selfMac[5], ssid.c_str());
    }
    if (prefs.getBool("sentBoot", false)) {
        sentinel_setUserEnabled(true);
        Serial.println("[SENTINEL] Boot-enable ON (persisted) — starting sentinel");
    } else {
        sentinel_setUserEnabled(false);
        Serial.println("[SENTINEL] OFF on boot (enable manually)");
    }

    if (ahCreateTask(uartForwardTask, "UARTForwardTask", 4096, NULL, 2, NULL, SCAN_CORE) != pdPASS)
        Serial.println("[BOOT] ERROR: UARTForwardTask create failed - mesh RX bridge down");
    delay(120);

    Serial.println("===== ANTIHUNTER DIGINODE C5 v1.0.5-c5exp1 BOOT COMPLETE =====");

    String currentSsid = prefsGetString("apSsid", AP_SSID);
    String currentPass = prefsGetString("apPass", AP_PASS);
    String currentNodeId = getNodeId();

    if (currentSsid.length() == 0) currentSsid = AP_SSID;
    if (currentPass.length() == 0) currentPass = AP_PASS;

    Serial.printf("NODE ID: %s\n", currentNodeId.c_str());
    Serial.printf("WEB UI: http://192.168.4.1/ (SSID: %s, PASS: %s)\n", 
                  currentSsid.c_str(), currentPass.c_str());
    Serial.printf("RANDOMIZED MAC: %s\n", WiFi.softAPmacAddress().c_str());

    delay(2000);
}

// cppcheck-suppress unusedFunction // Arduino entry point, called by the framework
void loop() {
    static unsigned long lastSaveSend = 0;
    static unsigned long lastHbSend = 0;
    static unsigned long lastHeapCheck = 0;

    markUptimeAlive();

#if AH_HEAP_TRACE
    {
        static unsigned long lastScan = 0;
        static bool mapped = false;
        if (!mapped) {
            mapped = true;
            heapScan("loop-first");
            heapMapDump("loop-first");
        }
        if (millis() - lastScan >= (millis() < 90000 ? 100UL : 1000UL)) {
            heapScan("loop");
            lastScan = millis();
        }
    }
#endif

    if (g_channelsAmended.exchange(false)) saveConfiguration();

    processUSBToMesh();

    // Battery saver mode - minimal operations
    if (batterySaverEnabled) {

        sendBatterySaverHeartbeat();

        updateGPSLocation();
        
        checkAndSendVibrationAlert();

        // Tamper detection still active
        if (tamperEraseActive) {
            checkTamperTimeout();
        }

        vTaskDelay(pdMS_TO_TICKS(500));
        return;
    }

    // Normal operation mode
    static bool s_bleUserWasBusy = false;
    bool bleUserNow = scanning.load() || workerTaskHandle || triangulationActive.load();
    if (s_bleUserWasBusy && !bleUserNow) {
        radioReleaseBLE();
    }
    s_bleUserWasBusy = bleUserNow;

    static bool s_scanWasBusy = false;
    bool scanBusyNow = scanning.load() || workerTaskHandle || blueTeamTaskHandle || triangulationActive.load();
    if (s_scanWasBusy && !scanBusyNow) {
        sentinel_resumeAfterScan();
    }
    s_scanWasBusy = scanBusyNow;
    scheduleTick();
    attack_responsePump();

    if (millis() - lastSaveSend > 600000 && !triangulationActive) {
        saveConfiguration();
        lastSaveSend = millis();
    }
    if (!triangulationActive) serviceDeferredSave();

    if (millis() - lastHbSend > hbInterval && !triangulationActive) {
        sendNodeIdUpdate();
        lastHbSend = millis();
    }

    if (millis() - lastRTCUpdate > 1000) {
        if (!triangulationActive) {
            updateRTCTime();
            disciplineRTCFromGPS();
        }
        updateGPSLocation();
        lastRTCUpdate = millis();
    }

    if (tamperEraseActive) {
        checkTamperTimeout();
    }

    checkAndSendVibrationAlert();
    serviceVibrationAutoScan();
    serviceSdRepair();
    saveResultsSnapshot();

    if (millis() - lastHeapCheck > 30000) {
        uint32_t freeHeap = ESP.getFreeHeap();
        Serial.printf("[HEAP] int=%u largest=%u minever=%u psram=%u tasks=%u\n",
                      (unsigned)freeHeap,
                      (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                      (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                      (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                      (unsigned)uxTaskGetNumberOfTasks());
        if (freeHeap < 25000) {
            Serial.printf("[HEAP] LOW: %u bytes free\n", freeHeap);
            dumpTaskStacks("heap-low");
        }
        lastHeapCheck = millis();
    }

    vTaskDelay(pdMS_TO_TICKS(100));
}