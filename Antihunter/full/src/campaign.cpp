#include "campaign.h"
#include "hardware.h"
#include <Preferences.h>

extern Preferences prefs;

static char g_name[24] = {0};

static void appendEvent(const char *ev) {
    if (!SafeSD::isAvailable()) return;
    File f = SafeSD::open(CAMPAIGN_FILE, FILE_APPEND);
    if (!f) f = SafeSD::open(CAMPAIGN_FILE, FILE_WRITE);
    if (!f) return;
    String line = String(ev) + "," + g_name + "," + String((unsigned long)getRTCEpoch()) + "," +
                  String((unsigned long)(millis() / 1000)) + "\n";
    SafeSD::write(f, reinterpret_cast<const uint8_t *>(line.c_str()), line.length());
    f.close();
}

void campaignInit() {
    String n = prefs.getString("campaign", "");
    strlcpy(g_name, n.c_str(), sizeof(g_name));
    if (g_name[0]) appendEvent("RESUME");
}

const char *campaignName() { return g_name; }

bool campaignStart(const String &name) {
    char clean[sizeof(g_name)];
    size_t j = 0;
    for (size_t i = 0; i < name.length() && j < sizeof(clean) - 1; i++) {
        char c = name[i];
        if (isalnum((unsigned char)c) || c == '-' || c == '_') clean[j++] = c;
    }
    clean[j] = '\0';
    if (!j) return false;
    if (g_name[0]) campaignStop();
    strlcpy(g_name, clean, sizeof(g_name));
    prefs.putString("campaign", g_name);
    appendEvent("START");
    logToSD(String("CAMPAIGN START ") + g_name);
    return true;
}

bool campaignStop() {
    if (!g_name[0]) return false;
    logToSD(String("CAMPAIGN STOP ") + g_name);
    appendEvent("STOP");
    g_name[0] = '\0';
    prefs.remove("campaign");
    return true;
}
