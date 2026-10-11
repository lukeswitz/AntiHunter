#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ble_class.h"

static const char *cls(const unsigned char *a, size_t n) {
    static char out[24];
    bleClassify(a, n, out, sizeof(out));
    return out;
}

static void expect(const char *name, const unsigned char *a, size_t n, const char *want) {
    const char *got = cls(a, n);
    printf("%-22s got=%-20s want=%s\n", name, got, want);
    assert(strcmp(got, want) == 0);
}

int main() {
    const unsigned char nearbyActiveWifi[] = {0x0A, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x1B, 0x1C, 0xAA, 0xBB, 0xCC};
    const unsigned char nearbyLockedNoWifi[] = {0x0A, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x13, 0x18, 0xAA, 0xBB, 0xCC};
    const unsigned char nearbyAction[] = {0x07, 0xFF, 0x4C, 0x00, 0x0F, 0x02, 0x00, 0x00};
    const unsigned char airplaySrc[] = {0x05, 0xFF, 0x4C, 0x00, 0x0A, 0x00};
    const unsigned char tethSrc[] = {0x05, 0xFF, 0x4C, 0x00, 0x0E, 0x00};
    const unsigned char findMy[] = {0x05, 0xFF, 0x4C, 0x00, 0x12, 0x19};
    const unsigned char cdpWinDesktop[] = {0x07, 0xFF, 0x06, 0x00, 0x01, 0x29, 0x20, 0x00};
    const unsigned char cdpIphone[] = {0x07, 0xFF, 0x06, 0x00, 0x01, 0x26, 0x20, 0x00};
    const unsigned char swiftPairLE[] = {0x06, 0xFF, 0x06, 0x00, 0x03, 0x00, 0x80};
    const unsigned char fastPairSvc[] = {0x06, 0x16, 0x2C, 0xFE, 0x00, 0x00, 0x01};

    expect("nearby active+wifi", nearbyActiveWifi, sizeof(nearbyActiveWifi), "Nearby-Active-WiFi");
    expect("nearby locked", nearbyLockedNoWifi, sizeof(nearbyLockedNoWifi), "Nearby-Locked");
    expect("nearby action", nearbyAction, sizeof(nearbyAction), "Nearby-Action");
    expect("airplay source", airplaySrc, sizeof(airplaySrc), "AirPlay-Source");
    expect("tethering source", tethSrc, sizeof(tethSrc), "Tethering-Source");
    expect("findmy", findMy, sizeof(findMy), "FindMy");
    expect("cdp win desktop", cdpWinDesktop, sizeof(cdpWinDesktop), "CDP-WinDesktop");
    expect("cdp iphone", cdpIphone, sizeof(cdpIphone), "CDP-iPhone");
    expect("swiftpair le", swiftPairLE, sizeof(swiftPairLE), "SwiftPair-LE");
    expect("fastpair svc", fastPairSvc, sizeof(fastPairSvc), "FastPair");

    puts("ALL_PASS");
    return 0;
}
