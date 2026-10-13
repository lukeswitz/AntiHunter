#include "ble_class.h"
#include "ble_id_class.h"
#include <stdio.h>
#include <string.h>

volatile bool bleClassifyEnabled = true;

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
        case 0x09: s = "AirPlay-Target"; break;
        case 0x0A: s = "AirPlay-Source"; break;
        case 0x0B: s = "Watch-MagicSwitch"; break;
        case 0x0C: s = "Handoff"; break;
        case 0x0D: s = "Tethering-Target"; break;
        case 0x0E: s = "Tethering-Source"; break;
        case 0x0F: s = "Nearby-Action"; break;
        case 0x10:
            if (n >= 5) {
                switch (m[4] & 0x0F) {
                    case 0x01: s = "Nearby-ReportOff"; break;
                    case 0x03: s = "Nearby-Locked"; break;
                    case 0x05: s = "Nearby-Audio"; break;
                    case 0x07: s = "Nearby-Inactive"; break;
                    case 0x09: s = "Nearby-Video"; break;
                    case 0x0A: s = "Nearby-Locked-Watch"; break;
                    case 0x0B: s = "Nearby-Active"; break;
                    case 0x0D: s = "Nearby-Driving"; break;
                    case 0x0E: s = "Nearby-Call"; break;
                    default:   s = "Nearby-Info"; break;
                }
                if (n >= 6 && (m[5] & 0x04)) { snprintf(out, outLen, "%s-WiFi", s); return; }
            } else {
                s = "Nearby-Info";
            }
            break;
        case 0x12: s = "FindMy"; break;
        default: snprintf(out, outLen, "Apple-%02X", m[2]); return;
    }
    snprintf(out, outLen, "%s", s);
}

static void microsoftSubtype(const uint8_t *m, size_t n, char *out, size_t outLen) {
    if (n < 4) { snprintf(out, outLen, "Microsoft"); return; }
    const char *s = nullptr;
    if (m[2] == 0x01) {
        switch (m[3] & 0x1F) {
            case 1:  s = "CDP-Xbox"; break;
            case 6:  s = "CDP-iPhone"; break;
            case 7:  s = "CDP-iPad"; break;
            case 8:  s = "CDP-Android"; break;
            case 9:  s = "CDP-WinDesktop"; break;
            case 11: s = "CDP-WinPhone"; break;
            case 12: s = "CDP-Linux"; break;
            case 13: s = "CDP-WinIoT"; break;
            case 14: s = "CDP-SurfaceHub"; break;
            case 15: s = "CDP-WinLaptop"; break;
            case 16: s = "CDP-WinTablet"; break;
            default: s = "CDP"; break;
        }
    } else if (m[2] == 0x03) {
        switch (m[3]) {
            case 0x00: s = "SwiftPair-LE"; break;
            case 0x01: s = "SwiftPair-BREDR"; break;
            case 0x02: s = "SwiftPair-Dual"; break;
            default:   s = "SwiftPair"; break;
        }
    } else {
        snprintf(out, outLen, "Microsoft-%02X", m[2]); return;
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
        case 0xFE2C: return "FastPair";
        case 0xFE25: return "AppleMHC";
        case 0xFD44: return "AppleAuth";
        case 0xFE61: return "Logitech";
        case 0x1812: return "HID";
        case 0x180D: return "HeartRate";
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
        case 0x181A: return "Environment";
        case 0xFE61: return "Logitech";
        default:     return nullptr;
    }
}

static bool knownCompany(const uint8_t *m) {
    uint16_t c = (uint16_t)(m[0] | (m[1] << 8));
    return c == 0x004C || c == 0x0006 || c == 0x00E0 || c == 0x0075;
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
        if (t == 0xFF && dl >= 2) {
            if (!mfr || (!knownCompany(mfr) && knownCompany(d))) { mfr = d; mfrLen = dl; }
        }
        else if (t == 0x16 && dl >= 2) {
            uint16_t u = (uint16_t)(d[0] | (d[1] << 8));
            if (!sd || (!svcDataLabel(sdUuid, sd, sdLen) && svcDataLabel(u, d + 2, dl - 2))) { sdUuid = u; sd = d + 2; sdLen = dl - 2; }
        }
        else if ((t == 0x02 || t == 0x03) && dl >= 2) {
            for (size_t i = 0; i + 1 < dl; i += 2) {
                uint16_t u = (uint16_t)(d[i] | (d[i + 1] << 8));
                if (!haveSvcUuid || (!svcUuidLabel(svcUuid) && svcUuidLabel(u))) { svcUuid = u; haveSvcUuid = true; svcList = d; svcListLen = dl; }
            }
        }
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
