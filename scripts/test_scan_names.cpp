#include <assert.h>
#include <stdio.h>

#include "scan_names.h"

int main() {
    using scan_names::attackRespMaskFromList;
    using scan_names::vibModeFromToken;

    assert(vibModeFromToken("") == 0);
    assert(vibModeFromToken("0") == 0);
    assert(vibModeFromToken("8") == 8);
    assert(vibModeFromToken("9") == 9);
    assert(vibModeFromToken("none") == 0);
    assert(vibModeFromToken("device-scan") == 1);
    assert(vibModeFromToken("probe-scan") == 2);
    assert(vibModeFromToken("randomization-detection") == 3);
    assert(vibModeFromToken("target-scan") == 4);
    assert(vibModeFromToken("drone-detection") == 5);
    assert(vibModeFromToken("deauth") == 6);
    assert(vibModeFromToken("baseline") == 7);
    assert(vibModeFromToken("pcap") == 8);
    assert(vibModeFromToken("PCAP") == 8);
    assert(vibModeFromToken("pcaps") == -1);
    assert(vibModeFromToken("-1") == -1);

    assert(attackRespMaskFromList("") == 0);
    assert(attackRespMaskFromList("none") == 0);
    assert(attackRespMaskFromList("pcap") == 0x02);
    assert(attackRespMaskFromList("device-scan") == 0x04);
    assert(attackRespMaskFromList("probe-scan") == 0x08);
    assert(attackRespMaskFromList("drone-detection") == 0x10);
    assert(attackRespMaskFromList("interrupt") == 0x20);
    assert(attackRespMaskFromList("pcap,device-scan") == 0x06);
    assert(attackRespMaskFromList(" PCAP , Device-Scan ") == 0x06);
    assert(attackRespMaskFromList("pcap,,interrupt") == 0x22);
    assert(attackRespMaskFromList("pcap,device-scan,probe-scan,drone-detection,interrupt") == 0x3E);
    assert(attackRespMaskFromList("pcap,bogus") == -1);
    assert(attackRespMaskFromList("pca") == -1);
    assert(attackRespMaskFromList(nullptr) == -1);

    printf("test_scan_names: ok\n");
    return 0;
}
