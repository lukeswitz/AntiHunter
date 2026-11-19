#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <queue>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "fleet_relay.h"

namespace {

constexpr uint32_t kStartMs = 100000;
constexpr uint32_t kTickMs = 250;
constexpr size_t kLineCap = 230;
constexpr uint32_t kHorizonMs = 1500000;
constexpr int kRandomSeeds = 300;
constexpr int kFixedSeeds = 20;
constexpr int kMaxReach = 4;

int g_fail = 0;
int g_findings = 0;
bool g_strict = false;
int g_onlySeed = 0;
char g_onlyScen = 0;
bool g_trace = false;
uint32_t g_now = kStartMs;

bool want(char scen, int seed) { return (!g_onlyScen || g_onlyScen == scen) && (!g_onlySeed || g_onlySeed == seed); }

void check(bool ok, int line, const char *expr, const char *fmt, ...) {
    if (ok) return;
    g_fail++;
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    printf("  FAIL line %d: %s | %s\n", line, expr, msg);
}

void finding(bool ok, int line, const char *expr, const char *fmt, ...) {
    if (ok) return;
    g_findings++;
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    printf("  FINDING line %d: %s | %s\n", line, expr, msg);
}

#define CHECK(cond, ...) check((cond), __LINE__, #cond, __VA_ARGS__)
#define FINDING(cond, ...) finding((cond), __LINE__, #cond, __VA_ARGS__)

struct Run {
    int node;
    int epoch;
    std::string tag;
    bool relayed;
    long secs;
};

struct Node {
    std::string id;
    fleet::State st;
    bool up = true;
    int epoch = 0;
    int whatCalls = 0;
    std::mt19937 rng;
    std::map<std::string, uint32_t> lastDirect;
    std::vector<std::pair<std::string, std::string>> replies;
};

struct Inst {
    std::string tag;
    std::string target;
    std::string cmd;
    int origin;
    uint32_t t;
    long secs;
    std::vector<bool> upAt;
};

Node *g_cur = nullptr;

uint32_t hRand() { return g_cur->rng(); }
void hSelf(char out[fleet::kIdLen]) { snprintf(out, fleet::kIdLen, "%s", g_cur->id.c_str()); }
size_t hCap() { return kLineCap; }
size_t hExpected(char out[][fleet::kIdLen], size_t max, uint32_t withinMs) {
    size_t k = 0;
    for (const auto &kv : g_cur->lastDirect) {
        if (k == max) break;
        if ((uint32_t)(g_now - kv.second) > withinMs) continue;
        snprintf(out[k++], fleet::kIdLen, "%s", kv.first.c_str());
    }
    return k;
}

const fleet::Hooks kHooks = {hRand, hSelf, hCap, hExpected};

bool isNodeTok(const std::string &t) {
    if (t.size() < 2 || t.size() > 5) return false;
    for (char c : t) {
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

std::string upper(const std::string &s) {
    std::string r = s;
    for (char &c : r) c = (char)toupper((unsigned char)c);
    return r;
}

bool starts(const std::string &s, const char *p) { return s.rfind(p, 0) == 0; }

void splitSender(const std::string &line, std::string &sender, std::string &payload) {
    sender.clear();
    payload = line;
    const size_t p = payload.find(": ");
    if (p == std::string::npos) return;
    if (p == 0) {
        payload = payload.substr(2);
        return;
    }
    const std::string first = payload.substr(0, p);
    const std::string rest = payload.substr(p + 2);
    if (isNodeTok(first)) {
        sender = first;
        payload = rest;
        return;
    }
    const size_t q = rest.find(": ");
    if (q != std::string::npos && q > 0 && isNodeTok(rest.substr(0, q))) {
        sender = rest.substr(0, q);
        payload = rest.substr(q + 2);
        return;
    }
    sender = first;
    payload = rest;
}

bool unwrap(const Node &nd, std::string &sender, std::string &payload) {
    if (!isNodeTok(sender)) return false;
    const size_t p = payload.find(": ");
    if (p == std::string::npos || p < 2 || p > 5) return false;
    const std::string inner = payload.substr(0, p);
    if (!isNodeTok(inner) || inner == sender || inner == nd.id) return false;
    const std::string rest = payload.substr(p + 2);
    if (!fleet::replyPrefixOf(rest.c_str())) return false;
    sender = inner;
    payload = rest;
    return true;
}

long secsOf(const std::string &cmd) {
    if (!starts(cmd, "DEVICE_SCAN_START:") && !starts(cmd, "SCAN_START:")) return -1;
    const size_t a = cmd.find(':');
    const size_t b = cmd.find(':', a + 1);
    if (b == std::string::npos) return -1;
    return strtol(cmd.c_str() + b + 1, nullptr, 10);
}

std::string replyFor(const std::string &cmd) {
    if (cmd == "STOP") return "STOP_ACK:OK";
    if (starts(cmd, "DEVICE_SCAN_START:")) return "DEVICE_SCAN_ACK:STARTED";
    if (starts(cmd, "SCAN_START:")) return "SCAN_ACK:STARTED";
    if (cmd == "STATUS") return "STATUS: Mode:WiFi Scan:IDLE Hits:0";
    if (starts(cmd, "SCHED_ADD:") || starts(cmd, "SCHED_DEL:")) return "SCHED_ACK:OK";
    if (cmd == "SCHED_LIST") return "SCHED_LIST:0";
    return "";
}

struct Ev {
    uint32_t t;
    uint64_t seq;
    std::function<void()> fn;
};

struct EvCmp {
    bool operator()(const Ev &a, const Ev &b) const { return a.t != b.t ? a.t > b.t : a.seq > b.seq; }
};

struct Sim {
    int n;
    std::vector<std::unique_ptr<Node>> nodes;
    std::vector<std::vector<double>> loss;
    std::mt19937 rng;
    std::priority_queue<Ev, std::vector<Ev>, EvCmp> q;
    uint64_t seq = 0;
    std::vector<Run> runs;
    std::vector<Inst> insts;
    std::map<std::string, int> cmdTx;
    std::map<std::pair<int, std::string>, int> relayTx;
    int whatTx = 0;
    int replyTx = 0;
    int replyRelayTx = 0;
    int hbTx = 0;
    int otherTx = 0;
    int origTx = 0;
    int relayCmdTx = 0;

    Sim(int count, uint32_t seed) : n(count), rng(seed) {
        g_now = kStartMs;
        loss.assign((size_t)n, std::vector<double>((size_t)n, -1.0));
        for (int i = 0; i < n; ++i) {
            nodes.push_back(std::make_unique<Node>());
            Node &nd = *nodes.back();
            char id[8];
            snprintf(id, sizeof(id), "AH%02d", i + 1);
            nd.id = id;
            nd.rng.seed(seed * 977u + (uint32_t)i * 31u + 5u);
            boot(i, true);
            at(kStartMs + rng() % kTickMs, [this, i]() { tickNode(i); });
        }
    }

    Sim(const Sim &) = delete;
    Sim &operator=(const Sim &) = delete;

    void at(uint32_t t, std::function<void()> fn) { q.push(Ev{t, seq++, std::move(fn)}); }

    void link(int a, int b, double l) {
        loss[(size_t)a][(size_t)b] = l;
        loss[(size_t)b][(size_t)a] = l;
    }

    void lineTopo() {
        for (int i = 0; i + 1 < n; ++i) link(i, i + 1, 0.0);
    }

    void fullTopo() {
        for (int i = 0; i < n; ++i)
            for (int j = i + 1; j < n; ++j) link(i, j, 0.0);
    }

    static void enter(Node &nd) {
        g_cur = &nd;
        fleet::use(&nd.st, kHooks);
    }

    void boot(int i, bool first) {
        Node &nd = *nodes[(size_t)i];
        g_cur = &nd;
        fleet::begin(&nd.st, kHooks);
        nd.lastDirect.clear();
        if (!first) nd.epoch++;
        nd.up = true;
    }

    void heartbeat(int i, uint32_t period, uint32_t first) {
        at(g_now + first, [this, i, period]() {
            const Node &nd = *nodes[(size_t)i];
            if (nd.up) tx(i, nd.id + ": HB:1", "");
            heartbeat(i, period, period);
        });
    }

    void heartbeats(uint32_t period, int skip = -1) {
        for (int i = 0; i < n; ++i) {
            if (i != skip) heartbeat(i, period, rng() % period);
        }
    }

    void takeDown(uint32_t t, int i) {
        at(t, [this, i]() { nodes[(size_t)i]->up = false; });
    }

    void bringUp(uint32_t t, int i) {
        at(t, [this, i]() {
            boot(i, false);
            tx(i, nodes[(size_t)i]->id + ": STARTUP: System initialized", "");
        });
    }

    void tickNode(int i) {
        Node &nd = *nodes[(size_t)i];
        if (nd.up) {
            enter(nd);
            char buf[300];
            const int h = fleet::nextLine(buf, sizeof(buf), g_now);
            if (h >= 0) {
                tx(i, buf, "");
                fleet::sendResult(h, true, g_now);
            }
        }
        at(g_now + kTickMs, [this, i]() { tickNode(i); });
    }

    void account(int from, const std::string &line, const std::string &tag) {
        if (line.find(" HB:") != std::string::npos) {
            hbTx++;
            return;
        }
        if (line[0] == '@') {
            whatTx++;
            return;
        }
        if (!tag.empty()) {
            cmdTx[tag]++;
            origTx++;
            return;
        }
        const size_t p = line.find(": ");
        if (p == std::string::npos) {
            otherTx++;
            return;
        }
        char ftag[fleet::kTagLen], tgt[fleet::kIdLen], cmd[fleet::kCmdLen];
        uint8_t hops = 0;
        if (fleet::parseFleetCmd(line.c_str() + p + 2, ftag, hops, tgt, cmd, sizeof(cmd))) {
            cmdTx[ftag]++;
            relayTx[std::make_pair(from, std::string(ftag))]++;
            relayCmdTx++;
            return;
        }
        const std::string rest = line.substr(p + 2);
        const size_t r = rest.find(": ");
        if (r != std::string::npos && r >= 2 && r <= 5 && isNodeTok(rest.substr(0, r)) &&
            fleet::replyPrefixOf(rest.substr(r + 2).c_str())) {
            replyRelayTx++;
        } else if (fleet::replyPrefixOf(rest.c_str())) {
            replyTx++;
        } else {
            otherTx++;
        }
    }

    void tx(int from, const std::string &line, const std::string &tag) {
        if (!nodes[(size_t)from]->up) return;
        if (g_trace && line.find(" HB:") == std::string::npos) printf("  %8.2f tx %s\n", (double)(g_now - kStartMs) / 1000.0, line.c_str());
        account(from, line, tag);
        for (int j = 0; j < n; ++j) {
            const double l = loss[(size_t)from][(size_t)j];
            if (j == from || l < 0) continue;
            if ((double)(rng() % 100000) / 100000.0 < l) continue;
            const uint32_t d = 1000 + rng() % 2001;
            at(g_now + d, [this, j, line, tag]() { deliver(j, line, tag); });
        }
    }

    void deliver(int j, const std::string &line, const std::string &meta) {
        Node &nd = *nodes[(size_t)j];
        if (!nd.up) return;
        enter(nd);
        std::string clean;
        for (char c : line) {
            if (c >= 32 && c <= 126) clean += c;
        }
        if (clean.empty() || clean[0] == '[') return;
        std::string sender, payload;
        splitSender(clean, sender, payload);
        const bool viaRelay = unwrap(nd, sender, payload);
        observe(nd, sender, !viaRelay);
        observeReply(nd, sender, payload, viaRelay);
        processMesh(j, clean, meta);
    }

    static void observe(Node &nd, const std::string &sender, bool direct) {
        if (sender.empty() || sender == nd.id || !isNodeTok(sender)) return;
        if (direct) nd.lastDirect[sender] = g_now;
    }

    static void observeReply(Node &nd, const std::string &sender, const std::string &payload, bool viaRelay) {
        if (!isNodeTok(sender) || sender == nd.id) return;
        fleet::onReply(sender.c_str(), payload.c_str(), viaRelay, g_now);
        if (fleet::replyPrefixOf(payload.c_str())) nd.replies.emplace_back(sender, payload);
    }

    void processMesh(int idx, const std::string &clean, const std::string &meta) {
        const Node &nd = *nodes[(size_t)idx];
        std::string sendingNode, content;
        splitSender(clean, sendingNode, content);
        const size_t qq = content.find(": @");
        if (qq != std::string::npos && qq >= 2 && qq <= 5 && isNodeTok(content.substr(0, qq))) {
            sendingNode = content.substr(0, qq);
            content = content.substr(qq + 2);
        }
        const bool haveSender = !sendingNode.empty();
        if (haveSender && sendingNode == nd.id) return;

        if (haveSender && starts(content, "FLEET_CMD:")) {
            char tag[fleet::kTagLen], tgt[fleet::kIdLen], cmd[fleet::kCmdLen];
            uint8_t hops = 0;
            if (!fleet::parseFleetCmd(content.c_str(), tag, hops, tgt, cmd, sizeof(cmd))) return;
            const std::string target = upper(tgt);
            const bool mine = target == "ALL" || target == nd.id;
            const bool run = fleet::onCommand("", target.c_str(), cmd, tag, hops, g_now);
            if (mine && run) execute(idx, cmd, tag, true);
            return;
        }

        if (starts(content, "@")) {
            const size_t sp = content.find(' ');
            if (sp == std::string::npos || sp == 0) return;
            const std::string target = upper(content.substr(1, sp - 1));
            const std::string command = content.substr(sp + 1);
            const bool mine = target == "ALL" || target == nd.id;
            const std::string origin = isNodeTok(sendingNode) ? sendingNode : std::string();
            const bool run = fleet::onCommand(origin.c_str(), target.c_str(), command.c_str(), nullptr, 0, g_now);
            if (mine && run) execute(idx, command, meta, false);
        }
    }

    void execute(int idx, const std::string &cmd, const std::string &tag, bool relayed) {
        Node &nd = *nodes[(size_t)idx];
        if (starts(cmd, "FLEET_WHAT:")) {
            if (g_trace) printf("  %8.2f WHAT %s %s\n", (double)(g_now - kStartMs) / 1000.0, nd.id.c_str(), cmd.c_str());
            nd.whatCalls++;
            fleet::onWhat(cmd.c_str() + 11, g_now);
            if (g_trace) {
                static char jb[fleet::kMaxCmds * 1024 + 4];
                fleet::json(jb, sizeof(jb), g_now);
                printf("  %8.2f STATE %s %s\n", (double)(g_now - kStartMs) / 1000.0, nd.id.c_str(), jb);
            }
            return;
        }
        runs.push_back(Run{idx, nd.epoch, tag, relayed, secsOf(cmd)});
        if (g_trace) printf("  %8.2f RUN %s %s %s\n", (double)(g_now - kStartMs) / 1000.0, nd.id.c_str(), relayed ? "relayed" : "direct", cmd.c_str());
        const std::string reply = replyFor(cmd);
        if (reply.empty()) return;
        const std::string line = nd.id + ": " + reply;
        const int epoch = nd.epoch;
        at(g_now + 200 + rng() % 800, [this, idx, line, epoch]() {
            if (nodes[(size_t)idx]->up && nodes[(size_t)idx]->epoch == epoch) tx(idx, line, "");
        });
    }

    static std::string tagOf(const std::string &target, const std::string &cmd) {
        static char buf[fleet::kMaxCmds * 1024 + 4];
        const size_t len = fleet::json(buf, sizeof(buf), g_now);
        const std::string js(buf, len);
        const std::string key = "\"target\":\"" + target + "\",\"cmd\":\"" + cmd + "\",\"age_ms\"";
        const size_t k = js.find(key);
        if (k == std::string::npos) return "";
        const size_t t = js.rfind("\"tag\":\"", k);
        if (t == std::string::npos) return "";
        const size_t e = js.find('"', t + 7);
        return js.substr(t + 7, e - t - 7);
    }

    std::string send(int origin, const std::string &target, const std::string &cmd) {
        Node &nd = *nodes[(size_t)origin];
        if (!nd.up) return "";
        enter(nd);
        fleet::onSent(target.c_str(), cmd.c_str(), g_now);
        const std::string tag = tagOf(target, cmd);
        tx(origin, nd.id + ": @" + target + " " + cmd, tag);
        Inst in;
        in.tag = tag;
        in.target = target;
        in.cmd = cmd;
        in.origin = origin;
        in.t = g_now;
        in.secs = secsOf(cmd);
        for (int i = 0; i < n; ++i) in.upAt.push_back(nodes[(size_t)i]->up);
        insts.push_back(in);
        return tag;
    }

    void runTo(uint32_t t) {
        while (!q.empty() && q.top().t <= t) {
            Ev e = q.top();
            q.pop();
            g_now = e.t;
            e.fn();
        }
        g_now = t;
    }

    int runCount(int node, const std::string &tag) const {
        int c = 0;
        for (const Run &r : runs) {
            if (r.node == node && r.tag == tag) c++;
        }
        return c;
    }

    int totalRuns(int node) const {
        int c = 0;
        for (const Run &r : runs) {
            if (r.node == node) c++;
        }
        return c;
    }

    bool gotReply(int node, const std::string &from, const char *prefix) const {
        for (const auto &r : nodes[(size_t)node]->replies) {
            if (r.first == from && starts(r.second, prefix)) return true;
        }
        return false;
    }

    int cmdTxOf(const std::string &tag) const {
        const auto it = cmdTx.find(tag);
        return it == cmdTx.end() ? 0 : it->second;
    }

    std::vector<int> depthFrom(int origin) const {
        std::vector<int> d((size_t)n, -1);
        std::queue<int> bq;
        d[(size_t)origin] = 0;
        bq.push(origin);
        while (!bq.empty()) {
            const int u = bq.front();
            bq.pop();
            for (int v = 0; v < n; ++v) {
                if (loss[(size_t)u][(size_t)v] >= 0 && d[(size_t)v] < 0) {
                    d[(size_t)v] = d[(size_t)u] + 1;
                    bq.push(v);
                }
            }
        }
        return d;
    }
};

uint32_t rel(uint32_t ms) { return kStartMs + ms; }

struct Report {
    int failBefore = g_fail;
    int findBefore = g_findings;
    const char *label() const {
        if (g_fail != failBefore) return "FAIL   ";
        if (g_findings != findBefore) return "FINDING";
        return "PASS   ";
    }
};

void scenLineAll() {
    Report rep;
    int maxTx = 0;
    int echo = 0;
    for (int seed = 1; seed <= kFixedSeeds; ++seed) {
        if (!want('a', seed)) continue;
        Sim s(4, (uint32_t)seed);
        s.lineTopo();
        s.heartbeats(60000);
        s.runTo(rel(150000));
        const std::string tag = s.send(0, "ALL", "DEVICE_SCAN_START:0:300");
        s.runTo(rel(330000));
        for (int i = 1; i < 4; ++i) CHECK(s.runCount(i, tag) == 1, "seed %d node %d runs=%d", seed, i, s.runCount(i, tag));
        CHECK(s.runCount(3, tag) == 1, "seed %d D not reached", seed);
        echo += s.runCount(0, tag);
        maxTx = std::max(maxTx, s.cmdTxOf(tag));
        CHECK(s.cmdTxOf(tag) <= s.n, "seed %d cmdTx=%d > %d", seed, s.cmdTxOf(tag), s.n);
    }
    FINDING(echo == 0, "origin ran its own @ALL after hearing a relayed copy, %d of %d seeds", echo, kFixedSeeds);
    printf("a line A-B-C-D @ALL scan   %s seeds=%d maxCmdTx=%d bound=4 originEchoRuns=%d\n", rep.label(), kFixedSeeds, maxTx, echo);
}

void scenLineTarget() {
    Report rep;
    int maxTx = 0;
    int maxAll = 0;
    for (int seed = 1; seed <= kFixedSeeds; ++seed) {
        if (!want('b', seed)) continue;
        Sim s(4, (uint32_t)seed);
        s.lineTopo();
        s.heartbeats(60000);
        s.runTo(rel(150000));
        const std::string tag = s.send(0, "AH04", "STATUS");
        s.runTo(rel(330000));
        CHECK(s.runCount(3, tag) == 1, "seed %d D runs=%d", seed, s.runCount(3, tag));
        CHECK(s.totalRuns(0) + s.totalRuns(1) + s.totalRuns(2) == 0, "seed %d non-target ran", seed);
        CHECK(s.gotReply(0, "AH04", "STATUS:"), "seed %d A has no reply from D", seed);
        maxTx = std::max(maxTx, s.cmdTxOf(tag));
        maxAll = std::max(maxAll, s.replyTx + s.replyRelayTx);
    }
    printf("b line @AH04 STATUS        %s seeds=%d maxCmdTx=%d maxReplyTx=%d\n", rep.label(), kFixedSeeds, maxTx, maxAll);
}

void scenFullMeshStop() {
    Report rep;
    int maxRelay = 0;
    int seedsWithRelay = 0;
    int firstBad = 0;
    for (int seed = 1; seed <= kFixedSeeds; ++seed) {
        if (!want('c', seed)) continue;
        Sim s(6, (uint32_t)seed);
        s.fullTopo();
        s.heartbeats(60000);
        s.runTo(rel(150000));
        const std::string tag = s.send(0, "ALL", "STOP");
        s.runTo(rel(330000));
        for (int i = 1; i < 6; ++i) CHECK(s.runCount(i, tag) == 1, "seed %d node %d runs=%d", seed, i, s.runCount(i, tag));
        FINDING(s.runCount(0, tag) == 0, "seed %d origin ran its own command", seed);
        FINDING(s.relayCmdTx == 0, "seed %d FLEET_CMD transmitted %d times", seed, s.relayCmdTx);
        if (s.relayCmdTx > 0) {
            seedsWithRelay++;
            if (!firstBad) firstBad = seed;
        }
        maxRelay = std::max(maxRelay, s.relayCmdTx);
    }
    printf("c full mesh 6 @ALL STOP    %s seeds=%d maxFleetCmdTx=%d seedsWithRelay=%d firstBadSeed=%d\n", rep.label(), kFixedSeeds, maxRelay, seedsWithRelay, firstBad);
}

void scenNodeDownThenBack() {
    Report rep;
    int maxTx = 0;
    for (int seed = 1; seed <= kFixedSeeds; ++seed) {
        if (!want('d', seed)) continue;
        Sim s(5, (uint32_t)seed);
        s.fullTopo();
        s.heartbeats(60000);
        s.takeDown(rel(100000), 2);
        s.runTo(rel(130000));
        const std::string tag = s.send(0, "ALL", "DEVICE_SCAN_START:0:600");
        s.bringUp(rel(190000), 2);
        s.runTo(rel(400000));
        CHECK(s.runCount(2, tag) == 0, "seed %d node that was off ran a stale command %d times", seed, s.runCount(2, tag));
        for (int i = 1; i < 5; ++i) {
            if (i != 2) CHECK(s.runCount(i, tag) == 1, "seed %d node %d runs=%d", seed, i, s.runCount(i, tag));
        }
        CHECK(s.runCount(0, tag) == 0, "seed %d origin runs=%d", seed, s.runCount(0, tag));
        maxTx = std::max(maxTx, s.cmdTxOf(tag));
    }
    printf("d node off, no stale replay %s seeds=%d maxCmdTx=%d\n", rep.label(), kFixedSeeds, maxTx);
}

void scenMissedCommand() {
    Report rep;
    int viaWhat = 0;
    int viaRelayOnly = 0;
    for (int seed = 1; seed <= kFixedSeeds; ++seed) {
        if (!want('e', seed)) continue;
        Sim s(5, (uint32_t)seed);
        s.fullTopo();
        s.link(0, 2, -1.0);
        s.loss[2][0] = 0.0;
        s.heartbeats(60000, 2);
        s.runTo(rel(150000));
        const std::string tag = s.send(0, "ALL", "DEVICE_SCAN_START:0:600");
        s.runTo(rel(330000));
        CHECK(s.runCount(2, tag) <= 1, "seed %d C runs=%d", seed, s.runCount(2, tag));
        FINDING(s.runCount(2, tag) == 1, "seed %d C never ran the command (whatTx=%d relayCmdTx=%d)", seed, s.whatTx, s.relayCmdTx);
        for (int i = 1; i < 5; ++i) CHECK(s.runCount(i, tag) <= 1, "seed %d node %d runs=%d", seed, i, s.runCount(i, tag));
        if (s.whatTx > 0) viaWhat++;
        else viaRelayOnly++;
    }
    CHECK(viaWhat > 0, "FLEET_WHAT never transmitted in %d seeds", kFixedSeeds);
    printf("e missed cmd, FLEET_WHAT   %s seeds=%d seedsWithWhat=%d seedsWithoutWhat=%d\n", rep.label(), kFixedSeeds, viaWhat, viaRelayOnly);
}

void scenRepeat() {
    Report rep;
    int lineFar[4] = {0, 0, 0, 0};
    for (int seed = 1; seed <= kFixedSeeds; ++seed) {
        if (!want('f', seed)) continue;
        Sim s(4, (uint32_t)seed);
        s.fullTopo();
        s.heartbeats(60000);
        s.runTo(rel(150000));
        const std::string tag = s.send(0, "ALL", "STATUS");
        s.runTo(rel(240000));
        const std::string tag2 = s.send(0, "ALL", "STATUS");
        s.runTo(rel(400000));
        CHECK(tag == tag2, "seed %d tags differ", seed);
        for (int i = 1; i < 4; ++i) CHECK(s.runCount(i, tag) == 2, "seed %d node %d runs=%d", seed, i, s.runCount(i, tag));

        Sim l(4, (uint32_t)seed);
        l.lineTopo();
        l.heartbeats(60000);
        l.runTo(rel(150000));
        const std::string t1 = l.send(0, "ALL", "STATUS");
        l.runTo(rel(240000));
        l.send(0, "ALL", "STATUS");
        l.runTo(rel(400000));
        for (int i = 1; i < 4; ++i) lineFar[i] += l.runCount(i, t1);
    }
    printf("f repeat @ALL STATUS x2    %s seeds=%d fullMesh=2/node; line total runs over %d seeds B=%d C=%d D=%d (2 each = %d)\n", rep.label(), kFixedSeeds, kFixedSeeds, lineFar[1], lineFar[2], lineFar[3], kFixedSeeds * 2);
}

struct Stats {
    int seeds = 0;
    int skipped = 0;
    int instances = 0;
    int allInstances = 0;
    int cleanInstances = 0;
    double reachSum = 0;
    double reachCleanSum = 0;
    double reachAnySum = 0;
    int maxCmdTx = 0;
    double maxTxPerNode = 0;
    int maxRelayPerNodeTag = 0;
    int originEcho = 0;
    int whatSeeds = 0;
    int rebootSeeds = 0;
    int cleanSeeds = 0;
    int cleanMiss = 0;
    char firstMiss[128] = {0};
};

void analyze(Sim &s, Stats &st, bool clean, uint32_t seed, bool rebooted) {
    for (const Inst &in : s.insts) {
        st.instances++;
        std::map<std::pair<int, int>, std::pair<int, int>> perNodeEpoch;
        for (const Run &r : s.runs) {
            if (r.tag != in.tag) continue;
            auto &pe = perNodeEpoch[std::make_pair(r.node, r.epoch)];
            if (r.relayed) pe.second++;
            else pe.first++;
            if (in.secs > 0) CHECK(r.secs <= in.secs && r.secs >= 10, "seed %u node %d secs=%ld orig=%ld", seed, r.node, r.secs, in.secs);
            if (in.target != "ALL") CHECK(s.nodes[(size_t)r.node]->id == in.target, "seed %u %s ran targeted cmd for %s", seed, s.nodes[(size_t)r.node]->id.c_str(), in.target.c_str());
        }
        for (const auto &kv : perNodeEpoch) {
            const int total = kv.second.first + kv.second.second;
            CHECK(total <= 1, "seed %u node %d epoch %d ran %s %d times (direct=%d relayed=%d)", seed, kv.first.first, kv.first.second, in.tag.c_str(), total, kv.second.first, kv.second.second);
            CHECK(!(kv.second.first >= 1 && kv.second.second >= 1), "seed %u node %d ran %s direct and relayed", seed, kv.first.first, in.tag.c_str());
        }
        int sumBound = 1;
        for (int i = 0; i < s.n; ++i) {
            const Node &nd = *s.nodes[(size_t)i];
            const auto it = s.relayTx.find(std::make_pair(i, in.tag));
            const int got = it == s.relayTx.end() ? 0 : it->second;
            const int bound = (nd.epoch + 1) + nd.whatCalls;
            CHECK(got <= bound, "seed %u node %d relayed %s %d times, bound %d", seed, i, in.tag.c_str(), got, bound);
            st.maxRelayPerNodeTag = std::max(st.maxRelayPerNodeTag, got);
            sumBound += bound;
        }
        const int tx = s.cmdTxOf(in.tag);
        CHECK(tx <= sumBound, "seed %u %s cmdTx=%d bound=%d", seed, in.tag.c_str(), tx, sumBound);
        if (!rebooted && s.whatTx == 0) CHECK(tx <= s.n, "seed %u %s cmdTx=%d > N=%d with no reboot and no FLEET_WHAT", seed, in.tag.c_str(), tx, s.n);
        st.maxCmdTx = std::max(st.maxCmdTx, tx);
        st.maxTxPerNode = std::max(st.maxTxPerNode, (double)tx / (double)s.n);
        for (const Run &r : s.runs) {
            if (r.tag == in.tag && r.node == in.origin) st.originEcho++;
        }
        if (in.target != "ALL") continue;
        const std::vector<int> depth = s.depthFrom(in.origin);
        int pop = 0, ran = 0, popAny = 0, ranAny = 0;
        for (int i = 0; i < s.n; ++i) {
            if (i == in.origin || depth[(size_t)i] < 0) continue;
            const bool did = s.runCount(i, in.tag) > 0;
            if (in.upAt[(size_t)i]) {
                popAny++;
                if (did) ranAny++;
                if (depth[(size_t)i] <= kMaxReach) {
                    pop++;
                    if (did) ran++;
                }
            }
        }
        if (pop == 0) continue;
        st.allInstances++;
        st.reachSum += (double)ran / (double)pop;
        st.reachAnySum += popAny ? (double)ranAny / (double)popAny : 1.0;
        if (clean) {
            st.cleanInstances++;
            st.reachCleanSum += (double)ran / (double)pop;
            if (ran != pop) {
                st.cleanMiss++;
                if (!st.firstMiss[0]) snprintf(st.firstMiss, sizeof(st.firstMiss), "seed %u %s reached %d/%d within %d hops", seed, in.tag.c_str(), ran, pop, kMaxReach);
            }
        }
    }
}

void randomSeed(uint32_t seed, Stats &st) {
    std::mt19937 g(seed * 7919u + 13u);
    const bool clean = seed % 5 == 0;
    const int n = 4 + (int)(g() % 5);
    Sim s(n, seed);
    std::vector<std::vector<bool>> adj((size_t)n, std::vector<bool>((size_t)n, false));
    for (int i = 1; i < n; ++i) {
        const int j = (int)(g() % (uint32_t)i);
        adj[(size_t)i][(size_t)j] = adj[(size_t)j][(size_t)i] = true;
    }
    for (int i = 0; i < n; ++i)
        for (int j = i + 1; j < n; ++j)
            if (!adj[(size_t)i][(size_t)j] && g() % 4 == 0) adj[(size_t)i][(size_t)j] = adj[(size_t)j][(size_t)i] = true;
    const double maxLoss = clean ? 0.0 : (double)(g() % 21) / 100.0;
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            if (i != j && adj[(size_t)i][(size_t)j]) s.loss[(size_t)i][(size_t)j] = maxLoss > 0 ? (double)(g() % 1001) / 1000.0 * maxLoss : 0.0;

    if (g_trace) {
        printf("  seed %u n=%d maxLoss=%.2f clean=%d links:", seed, n, maxLoss, (int)clean);
        for (int i = 0; i < n; ++i)
            for (int j = i + 1; j < n; ++j)
                if (adj[(size_t)i][(size_t)j]) printf(" %d-%d", i + 1, j + 1);
        printf("\n");
    }

    const uint32_t hbPeriod = 60000 + g() % 120000;
    s.heartbeats(hbPeriod);

    bool rebooted = false;
    if (!clean) {
        for (int i = 0; i < n; ++i) {
            if (g() % 100 >= 35) continue;
            const uint32_t downAt = 200000 + g() % 300000;
            const bool longDown = g() % 100 < 15;
            const uint32_t len = longDown ? 660000 + g() % 180000 : 10000 + g() % 80000;
            s.takeDown(rel(downAt), i);
            s.bringUp(rel(downAt + len), i);
            rebooted = true;
        }
    }

    const int cmds = 1 + (int)(g() % 4);
    std::set<std::string> used;
    std::set<std::string> tagsUsed;
    bool collision = false;
    for (int k = 0; k < cmds; ++k) {
        const int origin = (int)(g() % (uint32_t)n);
        std::string target = "ALL";
        if (g() % 100 >= 70) {
            int t = (int)(g() % (uint32_t)n);
            if (t == origin) t = (t + 1) % n;
            target = s.nodes[(size_t)t]->id;
        }
        std::string cmd;
        switch (g() % 6) {
            case 0: cmd = "DEVICE_SCAN_START:0:" + std::to_string(300 + k * 13 + (int)(g() % 10)); break;
            case 1: cmd = "SCAN_START:0:" + std::to_string(320 + k * 13 + (int)(g() % 10)); break;
            case 2: cmd = "STOP"; break;
            case 3: cmd = "STATUS"; break;
            case 4: cmd = "SCHED_ADD:2026-11-20T08:00|0|/drone|secs=" + std::to_string(60 + k); break;
            default: cmd = "DEVICE_SCAN_START:0:" + std::to_string(400 + k * 17 + (int)(g() % 10)); break;
        }
        const std::string key = s.nodes[(size_t)origin]->id + "|" + target + "|" + cmd;
        if (!used.insert(key).second) continue;
        const uint32_t when = 180000 + g() % 300000;
        s.at(rel(when), [&s, &tagsUsed, &collision, origin, target, cmd]() {
            const std::string tag = s.send(origin, target, cmd);
            if (!tag.empty() && !tagsUsed.insert(tag).second) collision = true;
        });
    }

    s.runTo(rel(kHorizonMs));
    st.seeds++;
    if (collision) {
        st.skipped++;
        return;
    }
    if (rebooted) st.rebootSeeds++;
    if (clean) st.cleanSeeds++;
    if (s.whatTx > 0) st.whatSeeds++;
    analyze(s, st, clean, seed, rebooted);
}

void scenRandom() {
    Report rep;
    Stats st;
    for (int seed = 1; seed <= kRandomSeeds; ++seed) {
        if (want('g', seed)) randomSeed((uint32_t)seed, st);
    }
    FINDING(st.cleanMiss == 0, "lossless no-reboot @ALL missed reachable nodes in %d of %d instances, first: %s", st.cleanMiss, st.cleanInstances, st.firstMiss);
    FINDING(st.originEcho == 0, "origin ran its own command after hearing a relayed copy, %d runs", st.originEcho);
    const double reach = st.allInstances ? st.reachSum / st.allInstances : 1.0;
    const double reachAny = st.allInstances ? st.reachAnySum / st.allInstances : 1.0;
    const double reachClean = st.cleanInstances ? st.reachCleanSum / st.cleanInstances : 1.0;
    printf("g random %d seeds          %s instances=%d skippedTagCollision=%d rebootSeeds=%d cleanSeeds=%d seedsWithWhat=%d\n", kRandomSeeds, rep.label(), st.instances, st.skipped, st.rebootSeeds, st.cleanSeeds, st.whatSeeds);
    printf("g   max cmd tx per instance=%d (%.2f per node), max relays by one node per instance=%d, originEchoRuns=%d\n", st.maxCmdTx, st.maxTxPerNode, st.maxRelayPerNodeTag, st.originEcho);
    printf("g   @ALL reach within %d hops: up-at-issue %.3f, any depth %.3f, clean seeds %.3f (%d @ALL instances)\n", kMaxReach, reach, reachAny, reachClean, st.allInstances);
}

}

int main() {
    const char *only = getenv("FLEET_SIM_ONLY");
    const char *seed = getenv("FLEET_SIM_SEED");
    g_trace = getenv("FLEET_SIM_TRACE") != nullptr;
    g_strict = true;
    if (only && only[0]) g_onlyScen = only[0];
    if (seed) g_onlySeed = atoi(seed);
    scenLineAll();
    scenLineTarget();
    scenFullMeshStop();
    scenNodeDownThenBack();
    scenMissedCommand();
    scenRepeat();
    scenRandom();
    if (g_fail || (g_strict && g_findings)) {
        printf("test_fleet_sim: %d failures, %d findings\n", g_fail, g_findings);
        return 1;
    }
    printf("test_fleet_sim: no invariant failures, %d findings\n", g_findings);
    return 0;
}
