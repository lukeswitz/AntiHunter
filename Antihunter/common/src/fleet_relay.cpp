#include "fleet_relay.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace fleet {

namespace {

struct Verb {
    const char *verb;
    bool exact;
    const char *reply;
    bool catchup;
    uint32_t lifeMs;
};

constexpr uint32_t kScanLife = 0;
constexpr uint32_t kForeverMs = 86400000;
constexpr uint32_t kMinRanMs = 600000;
constexpr uint32_t kMissWindowMs = 15000;
constexpr uint32_t kRepeatGapMs = 60000;
constexpr uint32_t kRelayMinMs = 8000;
constexpr uint32_t kRelayMaxMs = 16000;
constexpr uint32_t kWhatRepeatMs = 120000;
constexpr uint8_t kMaxTries = 3;

const Verb kVerbs[] = {
    {"STATUS", true, "STATUS:", false, 120000},
    {"STOP", true, "STOP_ACK", true, 1800000},
    {"DEVICE_SCAN_START:", false, "DEVICE_SCAN_ACK", true, kScanLife},
    {"SCAN_START:", false, "SCAN_ACK", true, kScanLife},
    {"SCHED_ADD:", false, "SCHED_ACK", true, 3600000},
    {"SCHED_LIST", true, "SCHED_LIST:", false, 120000},
    {"SCHED_DEL:", false, "SCHED_ACK", false, 120000},
    {"CAMPAIGN_START:", false, "CAMPAIGN_ACK", true, 3600000},
    {"CAMPAIGN_STOP", true, "CAMPAIGN_ACK", true, 3600000},
    {"CAMPAIGN_STATUS", true, "CAMPAIGN_STATUS:", false, 120000},
    {"BLE_CLASSIFY:", false, "CONFIG_ACK:BLE_CLASSIFY", true, 3600000},
    {"CALIBRATE:", false, "CALIBRATE_ACK", false, 120000},
    {"CALIBRATE_RESET", true, "CALIBRATE_ACK", false, 120000},
};

State *g_s = nullptr;
Hooks g_h = {};

bool expired(uint32_t now, uint32_t at, uint32_t life) { return (uint32_t)(now - at) >= life; }

bool startsWith(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

void copyStr(char *dst, size_t cap, const char *src) {
    if (!cap) return;
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

const Verb *verbOf(const char *cmd) {
    for (const Verb &v : kVerbs) {
        if (v.exact ? strcmp(cmd, v.verb) == 0 : startsWith(cmd, v.verb)) return &v;
    }
    return nullptr;
}

const Verb *verbOfReply(const char *payload) {
    const Verb *best = nullptr;
    for (const Verb &v : kVerbs) {
        if (startsWith(payload, v.reply) && (!best || strlen(v.reply) > strlen(best->reply))) best = &v;
    }
    return best;
}

bool scanSecs(const char *cmd, long &secs, bool &forever) {
    const char *p = strchr(cmd, ':');
    if (!p) return false;
    forever = strstr(cmd, "FOREVER") != nullptr;
    p = strchr(p + 1, ':');
    if (!p) return false;
    secs = strtol(p + 1, nullptr, 10);
    return true;
}

uint32_t lifeOf(const Verb &v, const char *cmd) {
    if (v.lifeMs != kScanLife) return v.lifeMs;
    long secs = 0;
    bool forever = false;
    if (!scanSecs(cmd, secs, forever) || forever || secs <= 0) return kForeverMs;
    if (secs > 86400) secs = 86400;
    return (uint32_t)secs * 1000u;
}

bool rewriteSecs(const char *cmd, long remain, char *out, size_t cap) {
    const char *a = strchr(cmd, ':');
    const char *b = a ? strchr(a + 1, ':') : nullptr;
    if (!b) return false;
    const char *c = b + 1;
    while (*c >= '0' && *c <= '9') c++;
    int n = snprintf(out, cap, "%.*s%ld%s", (int)(b + 1 - cmd), cmd, remain, c);
    return n > 0 && (size_t)n < cap;
}

void self(char out[kIdLen]) {
    out[0] = 0;
    if (g_h.selfId) g_h.selfId(out);
}

uint32_t backoff(uint32_t lo, uint32_t hi) {
    uint32_t r = g_h.rand32 ? g_h.rand32() : 0;
    return lo + (hi > lo ? r % (hi - lo) : 0);
}

void originOf(const char *tag, char out[kIdLen]) {
    const char *d = strchr(tag, '-');
    size_t n = d ? (size_t)(d - tag) : 0;
    if (n >= kIdLen) n = 0;
    memcpy(out, tag, n);
    out[n] = 0;
}

void hashTag(const char *origin, const char *target, const char *cmd, char tag[kTagLen]) {
    uint32_t h = 2166136261u;
    for (const char *p = origin; *p; ++p) h = (h ^ (uint8_t)*p) * 16777619u;
    h = (h ^ '|') * 16777619u;
    for (const char *p = target; *p; ++p) h = (h ^ (uint8_t)*p) * 16777619u;
    h = (h ^ ' ') * 16777619u;
    for (const char *p = cmd; *p; ++p) h = (h ^ (uint8_t)*p) * 16777619u;
    char o[kIdLen];
    copyStr(o, kIdLen, origin);
    snprintf(tag, kTagLen, "%s-%04x", o, (unsigned)((h ^ (h >> 16)) & 0xFFFF));
}

Cmd *findCmd(const char *tag) {
    for (Cmd &c : g_s->cmds) if (c.used && strcmp(c.tag, tag) == 0) return &c;
    return nullptr;
}

Cmd *newCmd() {
    Cmd *free = nullptr, *oldest = nullptr;
    for (Cmd &c : g_s->cmds) {
        if (!c.used) { free = &c; break; }
        if (!oldest || (int32_t)(c.heardMs - oldest->heardMs) < 0) oldest = &c;
    }
    Cmd *c = free ? free : oldest;
    memset(c, 0, sizeof(*c));
    c->used = true;
    return c;
}

bool answered(const Cmd &c, const char *node) {
    for (uint8_t i = 0; i < c.nAnswered; ++i) if (strcmp(c.answered[i], node) == 0) return true;
    return false;
}

int answerIndex(const Cmd &c, const char *node) {
    for (uint8_t i = 0; i < c.nAnswered; ++i) if (strcmp(c.answered[i], node) == 0) return i;
    return -1;
}

void addAnswered(Cmd &c, const char *node, uint32_t at) {
    int i = answerIndex(c, node);
    if (i < 0 && c.nAnswered < kMaxAnswered) {
        i = c.nAnswered++;
        copyStr(c.answered[i], kIdLen, node);
    }
    if (i >= 0) c.answeredMs[i] = at;
}

bool replied(const Cmd &c, const char *node) {
    for (uint8_t i = 0; i < c.nReplied; ++i) if (strcmp(c.replied[i], node) == 0) return true;
    return false;
}

Ran *findRan(const char *tag, uint32_t now) {
    for (Ran &r : g_s->ran) {
        if (r.tag[0] && strcmp(r.tag, tag) == 0 && !expired(now, r.atMs, r.lifeMs)) return &r;
    }
    return nullptr;
}

void markRan(const char *tag, uint32_t life, uint32_t now, bool relayed) {
    Ran *r = findRan(tag, now);
    if (!r) {
        r = &g_s->ran[g_s->ranNext];
        g_s->ranNext = (uint8_t)((g_s->ranNext + 1) % kMaxRan);
        copyStr(r->tag, kTagLen, tag);
    }
    r->relayed = relayed;
    r->atMs = now;
    r->lifeMs = life < kMinRanMs ? kMinRanMs : life;
}

void schedule(Cmd &c, uint8_t why, uint32_t delayMs, uint32_t now) {
    c.relay = R_PENDING;
    c.why = why;
    c.tries = 0;
    c.relaySchedMs = now;
    c.relayAtMs = now + delayMs;
}

bool pendingQuerySuppressedBy(const char *prefix) {
    return g_s->whatPending && strcmp(g_s->whatPrefix, prefix) == 0;
}

void queueOut(const char *line, uint32_t delayMs, uint32_t now) {
    for (Out &o : g_s->out) {
        if (o.used) continue;
        o.used = true;
        o.tries = 0;
        o.atMs = now + delayMs;
        copyStr(o.line, kLineLen, line);
        return;
    }
}

bool allCovered(const Cmd &c) {
    if (!g_h.expected) return true;
    char me[kIdLen], origin[kIdLen];
    self(me);
    originOf(c.tag, origin);
    char nodes[48][kIdLen];
    size_t n = g_h.expected(nodes, 48, kRosterWindowMs);
    for (size_t i = 0; i < n; ++i) {
        if (strcmp(nodes[i], me) == 0 || strcmp(nodes[i], origin) == 0) continue;
        if (!answered(c, nodes[i])) return false;
    }
    return true;
}

struct Appender {
    char *buf;
    size_t cap;
    size_t n;
};

__attribute__((format(printf, 2, 3))) void appendf(Appender &a, const char *fmt, ...) {
    if (a.n + 1 >= a.cap) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(a.buf + a.n, a.cap - a.n, fmt, ap);
    va_end(ap);
    if (w > 0) a.n = ((size_t)w < a.cap - a.n) ? a.n + (size_t)w : a.cap - 1;
}

size_t capOf() {
    size_t cap = g_h.lineCap ? g_h.lineCap() : kLineLen - 1;
    return cap < kLineLen ? cap : kLineLen - 1;
}

}

void begin(State *s, const Hooks &h) {
    if (s) memset(s, 0, sizeof(*s));
    g_h = h;
    g_s = s;
}

void use(State *s, const Hooks &h) {
    g_h = h;
    g_s = s;
}

bool relayable(const char *cmd) { return verbOf(cmd) != nullptr; }

const char *replyPrefixOf(const char *payload) {
    const Verb *v = verbOfReply(payload);
    return v ? v->reply : nullptr;
}

bool onCommand(const char *origin, const char *target, const char *cmd, const char *relayTag, uint8_t hops, uint32_t now) {
    char me[kIdLen];
    self(me);
    const bool relayed = relayTag != nullptr;
    const bool forMe = strcmp(target, "ALL") == 0 || strcmp(target, me) == 0;
    if (g_s && startsWith(cmd, "FLEET_WHAT:") && strcmp(target, me) != 0 && pendingQuerySuppressedBy(cmd + 11)) {
        g_s->whatPending = false;
    }
    const Verb *v = verbOf(cmd);
    if (!g_s || !v) return forMe && !relayed;

    char id[kTagLen];
    if (relayed) copyStr(id, kTagLen, relayTag);
    else hashTag(origin ? origin : "", target, cmd, id);
    const uint32_t life = lifeOf(*v, cmd);

    if (pendingQuerySuppressedBy(v->reply)) g_s->whatPending = false;

    bool run = false;
    if (forMe) {
        const Ran *r = findRan(id, now);
        run = !r || (!relayed && (!r->relayed || (uint32_t)(now - r->atMs) > kRepeatGapMs));
        if (relayed) {
            char from[kIdLen];
            originOf(id, from);
            if (strcmp(from, me) == 0) run = false;
        }
        if (run) markRan(id, life, now, relayed);
    }

    if (strcmp(target, me) == 0) return run;

    Cmd *c = findCmd(id);
    if (c && !relayed && (uint32_t)(now - c->heardMs) > kRepeatGapMs) {
        memset(c, 0, sizeof(*c));
        c->used = true;
    } else if (!c) {
        c = newCmd();
    } else {
        c->copyMs = now;
        if (run) c->ran = true;
        if (relayed && c->relay == R_PENDING && (int32_t)(now - c->relaySchedMs) > 0) {
            if (c->why == WHY_RELAY) c->relayAtMs = now + backoff(kRelayMinMs, kRelayMaxMs);
            else c->relay = R_DONE;
        }
        return run;
    }
    {
        copyStr(c->tag, kTagLen, id);
        copyStr(c->target, kIdLen, target);
        copyStr(c->cmd, kCmdLen, cmd);
        c->heardMs = now;
        c->lifeMs = life;
        c->hops = hops;
        c->ran = run;
        c->copyMs = now;
        for (const Seen &s : g_s->seen) {
            if (!s.node[0] || strcmp(s.prefix, v->reply) != 0 || expired(now, s.atMs, kMissWindowMs)) continue;
            if (strcmp(target, "ALL") == 0 || strcmp(target, s.node) == 0) addAnswered(*c, s.node, s.atMs);
        }
        if (hops < kMaxHops) schedule(*c, WHY_RELAY, backoff(kRelayMinMs, kRelayMaxMs), now);
        else c->relay = R_DONE;
    }
    return run;
}

void onSent(const char *target, const char *cmd, uint32_t now) {
    if (!g_s || !verbOf(cmd)) return;
    char me[kIdLen], id[kTagLen];
    self(me);
    hashTag(me, target, cmd, id);
    Cmd *c = findCmd(id);
    if (c) {
        memset(c, 0, sizeof(*c));
        c->used = true;
    } else {
        c = newCmd();
    }
    copyStr(c->tag, kTagLen, id);
    copyStr(c->target, kIdLen, target);
    copyStr(c->cmd, kCmdLen, cmd);
    c->heardMs = now;
    c->copyMs = now;
    c->lifeMs = lifeOf(*verbOf(cmd), cmd);
    c->mine = true;
    c->relay = R_DONE;
    markRan(id, c->lifeMs, now, false);
}

void onReply(const char *node, const char *payload, bool viaRelay, uint32_t now) {
    if (!g_s) return;
    const Verb *v = verbOfReply(payload);
    if (!v) return;
    char me[kIdLen];
    self(me);
    if (strcmp(node, me) == 0) return;

    Cmd *best = nullptr;
    for (Cmd &c : g_s->cmds) {
        if (!c.used || strcmp(verbOf(c.cmd)->reply, v->reply) != 0) continue;
        if (strcmp(c.target, "ALL") != 0 && strcmp(c.target, node) != 0) continue;
        if (expired(now, c.copyMs, kReplyWindowMs)) continue;
        if (!best || (int32_t)(c.copyMs - best->copyMs) > 0) best = &c;
    }

    if (best) {
        addAnswered(*best, node, now);
        if (!best->mine && best->relayedMs && (int32_t)(now - best->relayedMs) > 0 && !replied(*best, node) &&
            best->nReplied < kMaxAnswered) {
            copyStr(best->replied[best->nReplied++], kIdLen, node);
            char line[kLineLen];
            int n = snprintf(line, sizeof(line), "%s: %s: %s", me, node, payload);
            size_t cap = capOf();
            if (n > 0 && (size_t)n > cap) {
                line[cap] = 0;
                char *sp = strrchr(line, ' ');
                if (sp && (size_t)(sp - line) > strlen(me) + strlen(node) + 4) *sp = 0;
            }
            queueOut(line, backoff(500, 2000), now);
        }
        return;
    }

    Seen &s = g_s->seen[g_s->seenNext];
    g_s->seenNext = (uint8_t)((g_s->seenNext + 1) % kMaxSeen);
    copyStr(s.node, kIdLen, node);
    copyStr(s.prefix, kPrefixLen, v->reply);
    s.atMs = now;
    s.relayed = viaRelay;
    if (viaRelay || !v->catchup) return;

    size_t peers = 0;
    for (const Seen &o : g_s->seen) {
        if (!o.node[0] || o.relayed || strcmp(o.prefix, v->reply) != 0 || expired(now, o.atMs, kMissWindowMs)) continue;
        bool dup = false;
        for (const Seen &p : g_s->seen) {
            if (p.relayed) continue;
            if (&p == &o) break;
            if (p.node[0] && strcmp(p.prefix, v->reply) == 0 && !expired(now, p.atMs, kMissWindowMs) &&
                strcmp(p.node, o.node) == 0) { dup = true; break; }
        }
        if (!dup) peers++;
    }
    if (peers < 2 || g_s->whatPending) return;
    if (strcmp(g_s->lastWhatPrefix, v->reply) == 0 && !expired(now, g_s->lastWhatMs, kWhatRepeatMs)) return;
    g_s->whatPending = true;
    g_s->whatTries = 0;
    copyStr(g_s->whatPrefix, kPrefixLen, v->reply);
    copyStr(g_s->whatNode, kIdLen, node);
    g_s->whatSchedMs = now;
    g_s->whatAtMs = now + backoff(2000, 6000);
}

void onWhat(const char *prefix, uint32_t now) {
    if (!g_s) return;
    Cmd *best = nullptr;
    for (Cmd &c : g_s->cmds) {
        if (!c.used || strcmp(c.target, "ALL") != 0) continue;
        if (strcmp(verbOf(c.cmd)->reply, prefix) != 0 || expired(now, c.heardMs, c.lifeMs)) continue;
        if (!best || (int32_t)(c.heardMs - best->heardMs) > 0) best = &c;
    }
    if (best) schedule(*best, WHY_ANSWER, backoff(1000, 3000), now);
}

bool parseFleetCmd(const char *body, char tag[kTagLen], uint8_t &hops, char target[kIdLen], char *cmd, size_t cmdCap) {
    if (!startsWith(body, "FLEET_CMD:")) return false;
    const char *p = body + 10;
    const char *a = strchr(p, ':');
    if (!a || (size_t)(a - p) >= kTagLen || a == p) return false;
    memcpy(tag, p, (size_t)(a - p));
    tag[a - p] = 0;
    const char *b = strchr(a + 1, ':');
    if (!b) return false;
    long h = strtol(a + 1, nullptr, 10);
    if (h < 0 || h > 255) return false;
    hops = (uint8_t)h;
    if (b[1] != '@') return false;
    const char *sp = strchr(b + 2, ' ');
    if (!sp || (size_t)(sp - (b + 2)) >= kIdLen || sp == b + 2) return false;
    memcpy(target, b + 2, (size_t)(sp - (b + 2)));
    target[sp - (b + 2)] = 0;
    copyStr(cmd, cmdCap, sp + 1);
    return cmd[0] != 0;
}

int nextLine(char *buf, size_t cap, uint32_t now) {
    if (!g_s || cap < 2) return -1;
    char me[kIdLen];
    self(me);
    const size_t lineCap = capOf() < cap - 1 ? capOf() : cap - 1;

    for (size_t i = 0; i < kMaxOut; ++i) {
        const Out &o = g_s->out[i];
        if (!o.used || (int32_t)(now - o.atMs) < 0) continue;
        copyStr(buf, lineCap + 1, o.line);
        return (int)(100 + i);
    }

    if (g_s->whatPending && (int32_t)(now - g_s->whatAtMs) >= 0) {
        int n = snprintf(buf, cap, "@%s FLEET_WHAT:%s", g_s->whatNode, g_s->whatPrefix);
        if (n > 0 && (size_t)n <= lineCap) return 200;
        g_s->whatPending = false;
    }

    for (size_t i = 0; i < kMaxCmds; ++i) {
        Cmd &c = g_s->cmds[i];
        if (!c.used || c.relay != R_PENDING || (int32_t)(now - c.relayAtMs) < 0) continue;
        if (c.why == WHY_RELAY) {
            const bool all = strcmp(c.target, "ALL") == 0;
            if (all ? allCovered(c) : answered(c, c.target)) { c.relay = R_DONE; continue; }
        } else if (expired(now, c.heardMs, c.lifeMs)) {
            c.relay = R_DONE;
            continue;
        }
        char cmd[kCmdLen];
        copyStr(cmd, sizeof(cmd), c.cmd);
        if (c.why != WHY_RELAY && c.lifeMs != kForeverMs && verbOf(c.cmd)->lifeMs == kScanLife) {
            long remain = (long)((c.lifeMs - (uint32_t)(now - c.heardMs)) / 1000u);
            if (remain < 10 || !rewriteSecs(c.cmd, remain, cmd, sizeof(cmd))) { c.relay = R_DONE; continue; }
        }
        int n = snprintf(buf, cap, "%s: FLEET_CMD:%s:%u:@%s %s", me, c.tag, (unsigned)(c.hops + 1), c.target, cmd);
        if (n <= 0 || (size_t)n > lineCap) { c.relay = R_DONE; continue; }
        return (int)i;
    }
    return -1;
}

void sendResult(int handle, bool ok, uint32_t now) {
    if (!g_s || handle < 0) return;
    if (handle >= 100 && handle < 100 + (int)kMaxOut) {
        Out &o = g_s->out[handle - 100];
        if (ok || ++o.tries >= kMaxTries) o.used = false;
        else o.atMs = now + 5000;
        return;
    }
    if (handle == 200) {
        if (ok || ++g_s->whatTries >= kMaxTries) {
            g_s->whatPending = false;
            copyStr(g_s->lastWhatPrefix, kPrefixLen, g_s->whatPrefix);
            g_s->lastWhatMs = now;
        } else {
            g_s->whatAtMs = now + 5000;
        }
        return;
    }
    if (handle >= (int)kMaxCmds) return;
    Cmd &c = g_s->cmds[handle];
    if (ok) {
        c.relay = R_DONE;
        c.relayedMs = now;
        c.copyMs = now;
    } else if (++c.tries >= kMaxTries) {
        c.relay = R_DONE;
    } else {
        c.relayAtMs = now + 5000;
    }
}

size_t json(char *buf, size_t cap, uint32_t now) {
    if (!g_s || cap < 3) return 0;
    Appender a{buf, cap, 0};
    appendf(a, "[");
    bool first = true;
    for (const Cmd &c : g_s->cmds) {
        if (!c.used) continue;
        char cmd[kCmdLen * 2];
        size_t k = 0;
        for (const char *p = c.cmd; *p && k + 2 < sizeof(cmd); ++p) {
            if (*p == '"' || *p == '\\') cmd[k++] = '\\';
            cmd[k++] = *p;
        }
        cmd[k] = 0;
        appendf(a, "%s{\"tag\":\"%s\",\"target\":\"%s\",\"cmd\":\"%s\",\"age_ms\":%u,\"mine\":%s,\"ran\":%s,\"relayed\":%s,\"pending\":%s,\"answered\":[",
                first ? "" : ",", c.tag, c.target, cmd, (unsigned)(now - c.heardMs), c.mine ? "true" : "false",
                c.ran ? "true" : "false", c.relayedMs ? "true" : "false", c.relay == R_PENDING ? "true" : "false");
        for (uint8_t i = 0; i < c.nAnswered; ++i) appendf(a, "%s\"%s\"", i ? "," : "", c.answered[i]);
        appendf(a, "]}");
        first = false;
    }
    appendf(a, "]");
    return a.n;
}

}
