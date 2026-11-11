#pragma once
#include <map>
#include <string>

class Preferences {
public:
    std::map<std::string, bool> bools;
    bool getBool(const char *key, bool def) {
        auto it = bools.find(key);
        return it == bools.end() ? def : it->second;
    }
    size_t putBool(const char *key, bool v) {
        bools[key] = v;
        return 1;
    }
};
