#include "sig_match.h"
#include "sig_catalog.h"
#include <ctype.h>
#include <string.h>

static const uint8_t SIG_ANY = 0;
static const uint8_t SIG_BLE = 2;

struct AdvView {
    const uint8_t *mfg[4]; uint8_t mfgLen[4]; uint8_t mfgN;
    uint16_t u16[12]; uint8_t u16N;
    const uint8_t *u128[4]; uint8_t u128N;
    const uint8_t *sd[4]; uint8_t sdLen[4]; uint16_t sdUuid[4]; uint8_t sdN;
};

static void parseAdv(const uint8_t *p, size_t len, AdvView &v) {
    memset(&v, 0, sizeof(v));
    size_t off = 0;
    while (p && off + 2 <= len) {
        uint8_t l = p[off];
        if (l == 0 || off + 1 + l > len) break;
        uint8_t t = p[off + 1];
        const uint8_t *d = p + off + 2;
        size_t dl = l - 1;
        if (t == 0xFF && dl >= 2 && v.mfgN < 4) {
            v.mfg[v.mfgN] = d; v.mfgLen[v.mfgN] = (uint8_t)dl; v.mfgN++;
        } else if (t == 0x02 || t == 0x03) {
            for (size_t i = 0; i + 1 < dl && v.u16N < 12; i += 2) v.u16[v.u16N++] = (uint16_t)(d[i] | (d[i + 1] << 8));
        } else if (t == 0x06 || t == 0x07) {
            for (size_t i = 0; i + 15 < dl && v.u128N < 4; i += 16) v.u128[v.u128N++] = d + i;
        } else if (t == 0x16 && dl >= 2 && v.sdN < 4) {
            uint16_t u = (uint16_t)(d[0] | (d[1] << 8));
            v.sd[v.sdN] = d + 2; v.sdLen[v.sdN] = (uint8_t)(dl - 2); v.sdUuid[v.sdN] = u; v.sdN++;
            if (v.u16N < 12) v.u16[v.u16N++] = u;
        } else if (t == 0x21 && dl >= 16 && v.u128N < 4) {
            v.u128[v.u128N++] = d;
        }
        off += 1 + l;
    }
}

static bool radioOk(uint8_t radio, bool isBLE) {
    return radio == SIG_ANY || (radio == SIG_BLE) == isBLE;
}

static bool containsNoCase(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    if (n == 0) return false;
    for (const char *h = hay; *h; h++) {
        size_t i = 0;
        while (i < n && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == n) return true;
    }
    return false;
}

static bool globNoCase(const char *s, const char *p) {
    const char *star = nullptr, *ss = nullptr;
    while (*s) {
        if (*p == '*') { star = p++; ss = s; continue; }
        if (*p && (*p == '?' || tolower((unsigned char)*p) == tolower((unsigned char)*s))) { p++; s++; continue; }
        if (star) { p = star + 1; s = ++ss; continue; }
        return false;
    }
    while (*p == '*') p++;
    return *p == '\0';
}

static bool bytesContain(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn) {
    if (nn == 0 || nn > hn) return false;
    for (size_t i = 0; i + nn <= hn; i++) if (memcmp(hay + i, needle, nn) == 0) return true;
    return false;
}

static uint16_t fleetIndex(const char *id) {
    for (uint16_t i = 0; i < SIG_FLEET_COUNT; i++) if (strcmp(SIG_FLEETS[i].id, id) == 0) return i;
    return SIG_NONE;
}

uint16_t sigMatch(const uint8_t *mac, bool isBLE, const char *name, const uint8_t *adv, size_t advLen) {
    static const uint16_t airtag = fleetIndex("fleet-airtag");
    static const uint16_t appleDevice = fleetIndex("fleet-apple-device");
    static const uint16_t appleAudio = fleetIndex("fleet-apple-audio");

    bool hits[SIG_FLEET_COUNT];
    memset(hits, 0, sizeof(hits));

    if (mac) {
        uint8_t univ0 = mac[0] & (uint8_t)~0x02;
        bool tryUniv = !isBLE && (mac[0] & 0x02);
        for (uint16_t i = 0; i < SIG_OUI_COUNT; i++) {
            const SigOui &r = SIG_OUI[i];
            if (!radioOk(r.radio, isBLE)) continue;
            if (r.oui[1] != mac[1] || r.oui[2] != mac[2]) continue;
            if (r.oui[0] == mac[0] || (tryUniv && r.oui[0] == univ0)) hits[r.fleet] = true;
        }
        for (uint16_t i = 0; i < SIG_MACP_COUNT; i++) {
            const SigMacPrefix &r = SIG_MACP[i];
            if (radioOk(r.radio, isBLE) && memcmp(r.mac, mac, r.len) == 0) hits[r.fleet] = true;
        }
    }

    if (name && name[0]) {
        for (uint16_t i = 0; i < SIG_NAME_COUNT; i++) {
            const SigName &r = SIG_NAME[i];
            if (hits[r.fleet] || !radioOk(r.radio, isBLE)) continue;
            if (r.glob ? globNoCase(name, r.pat) : containsNoCase(name, r.pat)) hits[r.fleet] = true;
        }
    }

    bool fd44 = false;
    bool appleContinuity = false;
    if (isBLE && adv && advLen) {
        AdvView v;
        parseAdv(adv, advLen, v);
        for (uint8_t k = 0; k < v.u16N; k++) {
            if (v.u16[k] == 0xFD44) fd44 = true;
            for (uint16_t i = 0; i < SIG_UUID16_COUNT; i++) {
                const SigUuid16 &r = SIG_UUID16[i];
                if (r.uuid == v.u16[k] && radioOk(r.radio, isBLE)) hits[r.fleet] = true;
            }
        }
        for (uint8_t k = 0; k < v.u128N; k++) {
            for (uint16_t i = 0; i < SIG_UUID128_COUNT; i++) {
                const SigUuid128 &r = SIG_UUID128[i];
                if (radioOk(r.radio, isBLE) && memcmp(r.uuid, v.u128[k], 16) == 0) hits[r.fleet] = true;
            }
        }
        for (uint8_t k = 0; k < v.mfgN; k++) {
            uint16_t company = (uint16_t)(v.mfg[k][0] | (v.mfg[k][1] << 8));
            const uint8_t *data = v.mfg[k] + 2;
            size_t dataLen = v.mfgLen[k] - 2;
            if (company == 0x004C && dataLen >= 1) {
                uint8_t t = data[0];
                if (t == 0x05 || (t >= 0x07 && t <= 0x10)) appleContinuity = true;
            }
            for (uint16_t i = 0; i < SIG_MFG_COUNT; i++) {
                const SigMfg &r = SIG_MFG[i];
                if (!radioOk(r.radio, isBLE)) continue;
                if (r.len == 0) {
                    if (r.company == company) hits[r.fleet] = true;
                } else if ((r.company == 0 || r.company == company) && dataLen >= r.len && memcmp(data, r.prefix, r.len) == 0) {
                    hits[r.fleet] = true;
                }
            }
        }
        for (uint8_t k = 0; k < v.sdN; k++) {
            for (uint16_t i = 0; i < SIG_SVC_COUNT; i++) {
                const SigSvcData &r = SIG_SVC[i];
                if (!radioOk(r.radio, isBLE)) continue;
                if (r.uuid != 0 && r.uuid != v.sdUuid[k]) continue;
                if (r.len == 0) { hits[r.fleet] = true; continue; }
                if (r.contains) {
                    uint8_t rev[sizeof(r.prefix)];
                    for (uint8_t j = 0; j < r.len; j++) rev[j] = r.prefix[r.len - 1 - j];
                    if (bytesContain(v.sd[k], v.sdLen[k], r.prefix, r.len) ||
                        bytesContain(v.sd[k], v.sdLen[k], rev, r.len)) hits[r.fleet] = true;
                } else if (v.sdLen[k] >= r.len && memcmp(v.sd[k], r.prefix, r.len) == 0) {
                    hits[r.fleet] = true;
                }
            }
        }
    }

    if (airtag != SIG_NONE && hits[airtag]) {
        bool named = name && containsNoCase(name, "AirTag");
        bool appleProduct = (appleDevice != SIG_NONE && hits[appleDevice]) ||
                            (appleAudio != SIG_NONE && hits[appleAudio]);
        if (!named && !fd44 && (appleProduct || appleContinuity)) hits[airtag] = false;
    }

    for (uint16_t i = 0; i < SIG_FLEET_COUNT; i++) if (hits[i]) return i;
    return SIG_NONE;
}

const char *sigFleetName(uint16_t idx) {
    return idx < SIG_FLEET_COUNT ? SIG_FLEETS[idx].name : "";
}

const char *sigFleetKind(uint16_t idx) {
    return idx < SIG_FLEET_COUNT ? SIG_KINDS[SIG_FLEETS[idx].kind] : "";
}
