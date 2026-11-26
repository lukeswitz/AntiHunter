#pragma once

#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

namespace scan_names {

inline int vibModeFromToken(const char *t) {
    if (!t || !t[0]) return 0;
    if (isdigit((unsigned char)t[0])) return atoi(t);
    static const char *const names[] = {"none", "device-scan", "probe-scan", "randomization-detection", "target-scan",
                                        "drone-detection", "deauth", "baseline", "pcap"};
    for (int i = 0; i < 9; i++) if (strcasecmp(t, names[i]) == 0) return i;
    return -1;
}

inline int attackRespMaskFromList(const char *list) {
    static const char *const names[] = {"pcap", "device-scan", "probe-scan", "drone-detection", "interrupt", "none"};
    static const int bits[] = {0x02, 0x04, 0x08, 0x10, 0x20, 0x00};
    if (!list) return -1;
    int mask = 0;
    const char *s = list;
    for (;;) {
        while (*s == ' ') s++;
        const char *e = s;
        while (*e && *e != ',') e++;
        size_t n = (size_t)(e - s);
        while (n > 0 && s[n - 1] == ' ') n--;
        if (n > 0) {
            bool hit = false;
            for (int i = 0; i < 6; i++) {
                if (strlen(names[i]) == n && strncasecmp(s, names[i], n) == 0) { mask |= bits[i]; hit = true; }
            }
            if (!hit) return -1;
        }
        if (!*e) break;
        s = e + 1;
    }
    return mask;
}

}
