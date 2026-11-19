#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "fleet_relay.h"

static const char *g_self = "AH09";
static uint32_t g_rand = 0;
static size_t g_cap = 230;
static std::vector<std::string> g_expected;

static uint32_t rnd() { return g_rand; }
static void selfId(char out[fleet::kIdLen]) { snprintf(out, fleet::kIdLen, "%s", g_self); }
static size_t cap() { return g_cap; }
static size_t expected(char out[][fleet::kIdLen], size_t max, uint32_t) {
    size_t n = 0;
    for (const std::string &s : g_expected) {
        if (n == max) break;
        snprintf(out[n++], fleet::kIdLen, "%s", s.c_str());
    }
    return n;
}

static fleet::State g_state;

static void reset(std::vector<std::string> exp = {}) {
    g_expected = exp;
    g_cap = 230;
    g_rand = 0;
    fleet::begin(&g_state, fleet::Hooks{rnd, selfId, cap, expected});
}

static std::string next(uint32_t now, bool ok = true) {
    char buf[300];
    int h = fleet::nextLine(buf, sizeof(buf), now);
    if (h < 0) return "";
    fleet::sendResult(h, ok, now);
    return buf;
}

struct Relayed {
    std::string tag;
    std::string target;
    std::string cmd;
    uint8_t hops;
};

static Relayed parse(const std::string &line) {
    size_t p = line.find(": ");
    assert(p != std::string::npos);
    char tag[fleet::kTagLen], tgt[fleet::kIdLen], cmd[fleet::kCmdLen];
    uint8_t hops = 0;
    assert(fleet::parseFleetCmd(line.c_str() + p + 2, tag, hops, tgt, cmd, sizeof(cmd)));
    return Relayed{tag, tgt, cmd, hops};
}

static std::string tagFor(const char *origin, const char *target, const char *cmd) {
    reset({"AH77"});
    fleet::onCommand(origin, target, cmd, nullptr, 0, 1000);
    std::string line = next(20000);
    assert(!line.empty());
    return parse(line).tag;
}

static void testRunOnce() {
    const std::string tag = tagFor("AH01", "ALL", "DEVICE_SCAN_START:0:300");
    assert(tag.rfind("AH01-", 0) == 0 && tag.size() == 9);

    reset();
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 1000));
    assert(!fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", tag.c_str(), 1, 9000));
    assert(!fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:240", tag.c_str(), 1, 70000));
    assert(!fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 30000));
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 400000));

    reset();
    assert(fleet::onCommand("", "ALL", "DEVICE_SCAN_START:0:300", tag.c_str(), 1, 1000));
    assert(!fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 3000));
    assert(!fleet::onCommand("", "ALL", "DEVICE_SCAN_START:0:300", tag.c_str(), 2, 5000));

    reset();
    assert(fleet::onCommand("AH01", "ALL", "STOP", nullptr, 0, 1000));
    assert(fleet::onCommand("AH02", "ALL", "STOP", nullptr, 0, 2000));
}

static void testRelayAll() {
    reset({"AH02", "AH03"});
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 1000));
    fleet::onReply("AH02", "DEVICE_SCAN_ACK:STARTED", false, 2000);
    assert(next(4000).empty());
    std::string line = next(11000);
    Relayed r = parse(line);
    assert(line.rfind("AH09: FLEET_CMD:AH01-", 0) == 0);
    assert(r.target == "ALL" && r.cmd == "DEVICE_SCAN_START:0:300" && r.hops == 1);
    assert(next(30000).empty());

    reset({"AH02", "AH03", "AH01"});
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 1000));
    fleet::onReply("AH02", "DEVICE_SCAN_ACK:STARTED", false, 2000);
    fleet::onReply("AH03", "DEVICE_SCAN_ACK:BUSY", false, 2500);
    assert(next(11000).empty());
}

static void testRelaySuppressed() {
    const std::string tag = tagFor("AH01", "ALL", "STOP");
    reset({"AH03"});
    assert(fleet::onCommand("AH01", "ALL", "STOP", nullptr, 0, 1000));
    assert(!fleet::onCommand("", "ALL", "STOP", tag.c_str(), 1, 3000));
    assert(next(11000).empty());
}

static void testRelayTarget() {
    reset();
    assert(!fleet::onCommand("AH01", "AH05", "STATUS", nullptr, 0, 1000));
    std::string line = next(11000);
    assert(parse(line).target == "AH05" && parse(line).cmd == "STATUS");
    fleet::onReply("AH05", "STATUS: Mode:WiFi Scan:IDLE Hits:0", false, 13000);
    line = next(16000);
    assert(line == "AH09: AH05: STATUS: Mode:WiFi Scan:IDLE Hits:0");
    fleet::onReply("AH05", "STATUS: Mode:WiFi Scan:IDLE Hits:0", true, 17000);
    assert(next(20000).empty());

    reset();
    assert(!fleet::onCommand("AH01", "AH05", "STATUS", nullptr, 0, 1000));
    fleet::onReply("AH05", "STATUS: Mode:WiFi", false, 2000);
    assert(next(11000).empty());
}

static void testReplyCap() {
    reset();
    g_cap = 40;
    assert(!fleet::onCommand("AH01", "AH05", "STATUS", nullptr, 0, 1000));
    assert(parse(next(11000)).target == "AH05");
    fleet::onReply("AH05", "STATUS: Mode:WiFi Scan:IDLE Hits:0 Temp:40.0C", false, 12000);
    std::string line = next(15000);
    assert(!line.empty() && line.size() <= 40);
    assert(line.rfind("AH09: AH05: STATUS:", 0) == 0);
}

static void testCatchup() {
    reset({"AH02", "AH03"});
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300:CH1,6", nullptr, 0, 1000));
    fleet::onReply("AH02", "DEVICE_SCAN_ACK:STARTED", false, 2000);
    fleet::onReply("AH03", "DEVICE_SCAN_ACK:STARTED", false, 2000);
    assert(next(11000).empty());
    fleet::onNodeBack("AH02", 61000);
    assert(next(80000).empty());
    fleet::onNodeBack("AH04", 61000);
    std::string line = next(70000);
    Relayed r = parse(line);
    assert(r.target == "ALL" && r.cmd == "DEVICE_SCAN_START:0:231:CH1,6");
    fleet::onNodeBack("AH04", 80000);
    assert(next(95000).empty());
    fleet::onNodeBack("AH04", 400000);
    assert(next(420000).empty());
}

static void testCatchupSuperseded() {
    reset({"AH02"});
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:600", nullptr, 0, 1000));
    fleet::onReply("AH02", "DEVICE_SCAN_ACK:STARTED", false, 2000);
    assert(next(11000).empty());
    assert(fleet::onCommand("AH01", "ALL", "STOP", nullptr, 0, 20000));
    fleet::onReply("AH02", "STOP_ACK:OK", false, 21000);
    assert(next(31000).empty());
    fleet::onNodeBack("AH04", 40000);
    std::string line = next(60000);
    assert(parse(line).cmd == "STOP");
    assert(next(70000).empty());
}

static void testCatchupNotOrigin() {
    reset();
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:600", nullptr, 0, 1000));
    assert(next(11000).empty());
    fleet::onNodeBack("AH01", 30000);
    assert(next(60000).empty());
}

static void testMissedCommand() {
    reset();
    fleet::onReply("AH02", "DEVICE_SCAN_ACK:STARTED", false, 1000);
    assert(next(10000).empty());
    fleet::onReply("AH03", "DEVICE_SCAN_ACK:STARTED", false, 2000);
    std::string line = next(9000);
    assert(line == "@AH03 FLEET_WHAT:DEVICE_SCAN_ACK");
    fleet::onReply("AH04", "DEVICE_SCAN_ACK:STARTED", false, 9500);
    assert(next(20000).empty());

    reset();
    fleet::onReply("AH02", "STOP_ACK:OK", false, 1000);
    fleet::onReply("AH03", "STOP_ACK:OK", false, 2000);
    assert(!fleet::onCommand("", "AH03", "FLEET_WHAT:STOP_ACK", nullptr, 0, 3000));
    assert(next(10000).empty());

    reset();
    fleet::onReply("AH02", "STATUS: Mode:WiFi", false, 1000);
    fleet::onReply("AH03", "STATUS: Mode:WiFi", false, 2000);
    assert(next(10000).empty());
}

static void testAnswerWhat() {
    reset();
    assert(fleet::onCommand("AH01", "ALL", "DEVICE_SCAN_START:0:300", nullptr, 0, 1000));
    assert(next(11000).empty());
    fleet::onWhat("DEVICE_SCAN_ACK", 61000);
    std::string line = next(65000);
    assert(parse(line).cmd == "DEVICE_SCAN_START:0:236");
    fleet::onWhat("STOP_ACK", 70000);
    assert(next(80000).empty());
}

static void testParseFleetCmd() {
    char tag[fleet::kTagLen], tgt[fleet::kIdLen], cmd[fleet::kCmdLen];
    uint8_t hops = 0;
    assert(fleet::parseFleetCmd("FLEET_CMD:AH01-3fa2:2:@ALL DEVICE_SCAN_START:0:300", tag, hops, tgt, cmd, sizeof(cmd)));
    assert(strcmp(tag, "AH01-3fa2") == 0 && hops == 2 && strcmp(tgt, "ALL") == 0);
    assert(strcmp(cmd, "DEVICE_SCAN_START:0:300") == 0);
    assert(!fleet::parseFleetCmd("FLEET_CMD:AH01-3fa2:2:ALL STOP", tag, hops, tgt, cmd, sizeof(cmd)));
    assert(!fleet::parseFleetCmd("FLEET_CMD::2:@ALL STOP", tag, hops, tgt, cmd, sizeof(cmd)));
    assert(!fleet::parseFleetCmd("FLEET_CMD:AH01-3fa2:2:@ALL", tag, hops, tgt, cmd, sizeof(cmd)));
}

static void testHopsLimit() {
    reset({"AH03"});
    assert(fleet::onCommand("", "ALL", "STOP", "AH01-000a", fleet::kMaxHops, 1000));
    assert(next(20000).empty());
    reset({"AH03"});
    assert(fleet::onCommand("", "ALL", "STOP", "AH01-000b", 2, 1000));
    assert(next(20000) == "AH09: FLEET_CMD:AH01-000b:3:@ALL STOP");
}

static void testSelfTargetAndNonRelayable() {
    reset();
    assert(fleet::onCommand("AH01", "AH09", "STATUS", nullptr, 0, 1000));
    assert(next(20000).empty());
    assert(fleet::onCommand("AH01", "ALL", "SENTINEL_ON", nullptr, 0, 1000));
    assert(!fleet::onCommand("", "ALL", "SENTINEL_ON", "AH01-000d", 1, 1000));
    assert(!fleet::onCommand("AH01", "AH05", "SENTINEL_ON", nullptr, 0, 1000));
    assert(next(30000).empty());
}

static void testSentNotRelayedByOrigin() {
    reset({"AH02"});
    fleet::onSent("ALL", "STOP", 1000);
    assert(next(20000).empty());
    fleet::onReply("AH02", "STOP_ACK:OK", false, 2000);
    fleet::onNodeBack("AH05", 30000);
    std::string line = next(40000);
    assert(line.rfind("AH09: FLEET_CMD:AH09-", 0) == 0 && parse(line).cmd == "STOP");
}

static void testSendRetry() {
    reset();
    assert(!fleet::onCommand("AH01", "AH05", "STATUS", nullptr, 0, 1000));
    std::string first = next(11000, false);
    assert(parse(first).target == "AH05");
    assert(next(12000).empty());
    assert(next(16000) == first);
}

static void testJson() {
    reset();
    assert(fleet::onCommand("AH01", "ALL", "SCHED_ADD:2026-11-20T08:00|0|/drone|secs=60", nullptr, 0, 1000));
    fleet::onReply("AH02", "SCHED_ACK:OK", false, 2000);
    char buf[2048];
    size_t n = fleet::json(buf, sizeof(buf), 3000);
    assert(n > 0 && buf[0] == '[' && buf[n - 1] == ']');
    assert(strstr(buf, "\"tag\":\"AH01-"));
    assert(strstr(buf, "\"answered\":[\"AH02\"]"));
    assert(fleet::relayable("SCHED_ADD:x") && !fleet::relayable("SENTINEL_ON"));
    assert(strcmp(fleet::replyPrefixOf("DEVICE_SCAN_ACK:STARTED"), "DEVICE_SCAN_ACK") == 0);
    assert(strcmp(fleet::replyPrefixOf("SCAN_ACK:STARTED"), "SCAN_ACK") == 0);
    assert(fleet::replyPrefixOf("GPS: LOCKED") == nullptr);
}

int main() {
    testRunOnce();
    testRelayAll();
    testRelaySuppressed();
    testRelayTarget();
    testReplyCap();
    testCatchup();
    testCatchupSuperseded();
    testCatchupNotOrigin();
    testMissedCommand();
    testAnswerWhat();
    testParseFleetCmd();
    testHopsLimit();
    testSelfTargetAndNonRelayable();
    testSentNotRelayedByOrigin();
    testSendRetry();
    testJson();
    printf("test_fleet: all passed\n");
    return 0;
}
