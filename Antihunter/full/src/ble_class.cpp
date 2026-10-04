#include "ble_class.h"
#include "ble_id_class.h"
#include <stdio.h>
#include <string.h>

static const char *idClassLabel(const uint16_t *keys, const uint8_t *labels, size_t n, uint16_t key) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (keys[mid] < key) lo = mid + 1; else hi = mid;
    }
    return (lo < n && keys[lo] == key) ? BLE_ID_LABELS[labels[lo]] : nullptr;
}

static const char *uuid16Class(uint16_t uuid) {
    return idClassLabel(BLE_UUID16_KEYS, BLE_UUID16_LABEL, sizeof(BLE_UUID16_KEYS) / sizeof(BLE_UUID16_KEYS[0]), uuid);
}

static const char *companyClass(uint16_t company) {
    return idClassLabel(BLE_COMPANY_KEYS, BLE_COMPANY_LABEL, sizeof(BLE_COMPANY_KEYS) / sizeof(BLE_COMPANY_KEYS[0]), company);
}

static const char *appearanceCategory(uint16_t a) {
    switch (a >> 6) {
        case 0x001: return "Phone";
        case 0x002: return "Computer";
        case 0x003: return "Watch";
        case 0x004: return "Clock";
        case 0x005: return "Display";
        case 0x006: return "Remote";
        case 0x007: return "EyeGlasses";
        case 0x008: return "Tag";
        case 0x009: return "Keyring";
        case 0x00A: return "MediaPlayer";
        case 0x00B: return "Barcode";
        case 0x00F: return "HID";
        case 0x011: return "Sensor";
        case 0x015: return "HeartRate";
        case 0x016: return "BP";
        case 0x019: return "Cycling";
        case 0x024: return "Audio";
        case 0x025: return "Wearable";
        case 0x026: return "Toy";
        case 0x027: return "Robotic";
        case 0x031: return "Auto";
        default:    return nullptr;
    }
}

static void appleContinuity(const uint8_t *m, size_t n, char *out, size_t outLen) {
    if (n < 4) { snprintf(out, outLen, "Apple"); return; }
    const char *s = nullptr;
    switch (m[2]) {
        case 0x02: s = "iBeacon"; break;
        case 0x03: s = "AirPrint"; break;
        case 0x05: s = "AirDrop"; break;
        case 0x06: s = "HomeKit"; break;
        case 0x07: s = "AirPods"; break;
        case 0x08: s = "Hey-Siri"; break;
        case 0x09: s = "Nearby-Action"; break;
        case 0x0A: s = "Apple-TV"; break;
        case 0x0B: s = "Watch-C"; break;
        case 0x0C: s = "Handoff"; break;
        case 0x0D: s = "WiFi-Settings"; break;
        case 0x0E: s = "Tethering-T"; break;
        case 0x0F: s = "Tethering-S"; break;
        case 0x10:
            if (n >= 6) {
                uint8_t act = (m[4] >> 4) & 0x0F;
                uint8_t flg = m[4] & 0x0F;
                bool wifi = (m[5] & 0x10) != 0;
                switch (act) {
                    case 0x00: s = wifi ? "iPhone-Inactive-WiFi" : "iPhone-Inactive"; break;
                    case 0x01: s = "iPhone-Idle"; break;
                    case 0x03: s = "iPhone-Audio"; break;
                    case 0x05: s = "iPhone-AirDrop-RX"; break;
                    case 0x07: s = "iPhone-HomeScreen"; break;
                    case 0x09: s = "iPhone-LockScreen"; break;
                    case 0x0A: s = "iPhone-Locked"; break;
                    case 0x0B: s = "iPhone-Call-Ringing"; break;
                    case 0x0D: s = "iPhone-Recently-Used"; break;
                    case 0x0E: s = "iPhone-Call-Active"; break;
                    default: snprintf(out, outLen, "iPhone-Act%X-%X", act, flg); return;
                }
            } else {
                s = "iPhone-Nearby";
            }
            break;
        case 0x12: s = "FindMy"; break;
        default: snprintf(out, outLen, "Apple-%02X", m[2]); return;
    }
    snprintf(out, outLen, "%s", s);
}

static void microsoftSubtype(const uint8_t *m, size_t n, char *out, size_t outLen) {
    if (n < 3) { snprintf(out, outLen, "Microsoft"); return; }
    const char *s = nullptr;
    uint8_t sub = m[2] & 0x3F;
    switch (sub) {
        case 0x01: s = "MS-XboxOne"; break;
        case 0x03: s = "SwiftPair-T1"; break;
        case 0x05: s = "SwiftPair-T2"; break;
        case 0x06: s = "SwiftPair-T3"; break;
        case 0x07: s = "SwiftPair-T4"; break;
        case 0x08: s = "Beacon"; break;
        case 0x09: s = "CDP"; break;
        case 0x0A: s = "Continuum"; break;
        case 0x0C: s = "MS-Account"; break;
        default: snprintf(out, outLen, "Microsoft-%02X", sub); return;
    }
    snprintf(out, outLen, "%s", s);
}

static const char *googleSubtype(const uint8_t *m, size_t n) {
    if (n >= 4 && m[2] == 0x00 && m[3] == 0xBA) return "FastPair";
    return "Google";
}

static const char *samsungSubtype(const uint8_t *m, size_t n) {
    if (n >= 4) {
        if (m[2] == 0x01 && m[3] == 0x00) return "Samsung-Buds";
        if (m[2] == 0x42 && m[3] == 0x09) return "SmartTag";
    }
    return "Samsung";
}

static const char *eddystoneLabel(const uint8_t *s, size_t n) {
    if (n == 0) return "Eddystone";
    switch (s[0]) {
        case 0x00: return "Eddystone-UID";
        case 0x10: return "Eddystone-URL";
        case 0x20: return "Eddystone-TLM";
        case 0x30: return "Eddystone-EID";
        default:   return "Eddystone";
    }
}

static const char *svcDataLabel(uint16_t uuid, const uint8_t *s, size_t n) {
    switch (uuid) {
        case 0xFEAA: return eddystoneLabel(s, n);
        case 0xFEED: return "Tile";
        case 0xFE9F: return "Google-Nearby";
        case 0xFD6F: return "ExposureNotif";
        case 0xFCF1: return "Google-Stadia";
        case 0xFE2C: return "Google";
        case 0xFE25: return "AppleMHC";
        case 0xFD44: return "AppleAuth";
        case 0xFE61: return "Logitech";
        case 0x1812: return "HID";
        case 0x180D: return "HeartRate";
        case 0x180F: return "Battery";
        case 0x181A: return "Environment";
        default:     return nullptr;
    }
}

static const char *svcUuidLabel(uint16_t uuid) {
    switch (uuid) {
        case 0xFEAA: return "Eddystone";
        case 0xFEED: return "Tile";
        case 0xFE9F: return "Google-Nearby";
        case 0xFD6F: return "ExposureNotif";
        case 0x1812: return "HID";
        case 0x180D: return "HeartRate";
        case 0x180F: return "Battery";
        case 0x181A: return "Environment";
        case 0xFE61: return "Logitech";
        default:     return nullptr;
    }
}

bool bleClassify(const uint8_t *adv, size_t len, char *out, size_t outLen) {
    if (!out || outLen == 0) return false;
    out[0] = '\0';
    if (!adv) return false;

    const uint8_t *mfr = nullptr; size_t mfrLen = 0;
    const uint8_t *sd = nullptr; size_t sdLen = 0; uint16_t sdUuid = 0;
    uint16_t svcUuid = 0; bool haveSvcUuid = false;
    const uint8_t *svcList = nullptr; size_t svcListLen = 0;
    uint16_t appearance = 0; bool haveAppearance = false;

    size_t off = 0;
    while (off + 2 <= len) {
        uint8_t l = adv[off];
        if (l == 0) break;
        if (off + 1 + l > len) break;
        uint8_t t = adv[off + 1];
        const uint8_t *d = adv + off + 2;
        size_t dl = l - 1;
        if (t == 0xFF && !mfr && dl >= 2) { mfr = d; mfrLen = dl; }
        else if (t == 0x16 && !sd && dl >= 2) { sdUuid = (uint16_t)(d[0] | (d[1] << 8)); sd = d + 2; sdLen = dl - 2; }
        else if ((t == 0x02 || t == 0x03) && !haveSvcUuid && dl >= 2) { svcUuid = (uint16_t)(d[0] | (d[1] << 8)); haveSvcUuid = true; svcList = d; svcListLen = dl; }
        else if (t == 0x19 && dl >= 2) { appearance = (uint16_t)(d[0] | (d[1] << 8)); haveAppearance = true; }
        off += 1 + l;
    }

    if (sd) {
        const char *s = svcDataLabel(sdUuid, sd, sdLen);
        if (s) { snprintf(out, outLen, "%s", s); return true; }
    }
    if (mfr) {
        uint16_t company = (uint16_t)(mfr[0] | (mfr[1] << 8));
        switch (company) {
            case 0x004C: appleContinuity(mfr, mfrLen, out, outLen); return true;
            case 0x0006: microsoftSubtype(mfr, mfrLen, out, outLen); return true;
            case 0x00E0: snprintf(out, outLen, "%s", googleSubtype(mfr, mfrLen)); return true;
            case 0x0075: snprintf(out, outLen, "%s", samsungSubtype(mfr, mfrLen)); return true;
            default: break;
        }
    }
    if (haveSvcUuid) {
        const char *s = svcUuidLabel(svcUuid);
        if (s) { snprintf(out, outLen, "%s", s); return true; }
    }
    {
        const char *s = nullptr;
        for (size_t i = 0; !s && i + 1 < svcListLen; i += 2) s = uuid16Class((uint16_t)(svcList[i] | (svcList[i + 1] << 8)));
        if (!s && sd) s = uuid16Class(sdUuid);
        if (!s && mfr) s = companyClass((uint16_t)(mfr[0] | (mfr[1] << 8)));
        if (s) { snprintf(out, outLen, "%s", s); return true; }
    }
    if (haveAppearance) {
        const char *s = appearanceCategory(appearance);
        if (s) { snprintf(out, outLen, "%s", s); return true; }
    }
    return false;
}
