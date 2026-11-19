#pragma once
#include <stddef.h>
#include <stdint.h>

namespace fleet {

constexpr size_t kIdLen = 6;
constexpr size_t kTagLen = 12;
constexpr size_t kCmdLen = 232;
constexpr size_t kPrefixLen = 24;
constexpr size_t kLineLen = 248;
constexpr size_t kMaxCmds = 24;
constexpr size_t kMaxAnswered = 16;
constexpr size_t kMaxRan = 48;
constexpr size_t kMaxSeen = 32;
constexpr size_t kMaxOut = 8;
constexpr uint8_t kMaxHops = 3;
constexpr uint32_t kRosterWindowMs = 3600000;
constexpr uint32_t kReplyWindowMs = 120000;

struct Hooks {
    uint32_t (*rand32)();
    void (*selfId)(char out[kIdLen]);
    size_t (*lineCap)();
    size_t (*expected)(char out[][kIdLen], size_t max, uint32_t withinMs);
};

enum : uint8_t { R_NONE = 0, R_PENDING = 1, R_DONE = 2 };
enum : uint8_t { WHY_RELAY = 0, WHY_ANSWER = 2 };

struct Cmd {
    bool used;
    bool mine;
    bool ran;
    uint8_t hops;
    uint8_t relay;
    uint8_t why;
    uint8_t tries;
    uint8_t nAnswered;
    uint8_t nReplied;
    char tag[kTagLen];
    char target[kIdLen];
    char cmd[kCmdLen];
    uint32_t heardMs;
    uint32_t copyMs;
    uint32_t lifeMs;
    uint32_t relayAtMs;
    uint32_t relaySchedMs;
    uint32_t relayedMs;
    char answered[kMaxAnswered][kIdLen];
    uint32_t answeredMs[kMaxAnswered];
    char replied[kMaxAnswered][kIdLen];
};

struct Ran {
    char tag[kTagLen];
    bool relayed;
    uint32_t atMs;
    uint32_t lifeMs;
};

struct Seen {
    char node[kIdLen];
    char prefix[kPrefixLen];
    bool relayed;
    uint32_t atMs;
};

struct Out {
    bool used;
    uint8_t tries;
    uint32_t atMs;
    char line[kLineLen];
};

struct State {
    Cmd cmds[kMaxCmds];
    Ran ran[kMaxRan];
    Seen seen[kMaxSeen];
    Out out[kMaxOut];
    uint8_t ranNext;
    uint8_t seenNext;
    bool whatPending;
    uint8_t whatTries;
    char whatPrefix[kPrefixLen];
    char whatNode[kIdLen];
    uint32_t whatAtMs;
    uint32_t whatSchedMs;
    char lastWhatPrefix[kPrefixLen];
    uint32_t lastWhatMs;
};

void begin(State *s, const Hooks &h);
void use(State *s, const Hooks &h);

bool relayable(const char *cmd);
const char *replyPrefixOf(const char *payload);

bool onCommand(const char *origin, const char *target, const char *cmd, const char *relayTag, uint8_t hops, uint32_t now);
void onSent(const char *target, const char *cmd, uint32_t now);
void onReply(const char *node, const char *payload, bool viaRelay, uint32_t now);
void onWhat(const char *prefix, uint32_t now);
bool parseFleetCmd(const char *body, char tag[kTagLen], uint8_t &hops, char target[kIdLen], char *cmd, size_t cmdCap);

int nextLine(char *buf, size_t cap, uint32_t now);
void sendResult(int handle, bool ok, uint32_t now);
size_t json(char *buf, size_t cap, uint32_t now);

}
