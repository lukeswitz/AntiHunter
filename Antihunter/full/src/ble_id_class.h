#pragma once
#include <stdint.h>

static const char *const BLE_ID_LABELS[] = {
    "Audio-AIAIAI", "Audio-Anker", "Audio-Auracast", "Audio-Beats", "Audio-Bose", "Audio-Bragi", "Audio-Dolby", "Audio-GN",
    "Audio-GamingAud", "Audio-Google", "Audio-Harman", "Audio-HearingAid", "Audio-Jabra", "Audio-LE", "Audio-Marshall", "Audio-Plantronic",
    "Audio-Sennheiser", "Audio-Shokz", "Audio-Skullcandy", "Audio-Sonos", "Audio-Sony", "Beacon-Accent", "Beacon-Blue", "Beacon-ESL",
    "Beacon-Eddystone", "Beacon-Estimote", "Beacon-Gimbal", "Beacon-Hubble", "Beacon-IndoorPos", "Beacon-Kontakt", "Beacon-Minew", "Beacon-Quuppa",
    "Beacon-Radius", "Beacon-Reelables", "Beacon-Trackonomy", "Beacon-Wiliot", "Camera-Arlo", "Camera-Axis", "Camera-Flock", "Camera-GoPro",
    "Camera-Hikvision", "Camera-Insta360", "Camera-Raven", "Camera-Rhombus", "Camera-Verkada", "Camera-Wyze", "Drone-DJI", "Drone-Parrot",
    "Drone-RemoteID", "Glasses-Even", "Glasses-IXI", "Glasses-Luxottica", "Glasses-Meta", "Glasses-Snap", "Glasses-Vuzix", "Health-Abbott",
    "Health-BD", "Health-BP", "Health-BodyComp", "Health-CGM", "Health-Dexcom", "Health-Eli", "Health-FitMach", "Health-GN",
    "Health-Glucose", "Health-HealthSns", "Health-InPen", "Health-Insulet", "Health-Insulin", "Health-Masimo", "Health-Medtronic", "Health-Novo",
    "Health-Omnipod", "Health-Omron", "Health-Owlet", "Health-PulseOx", "Health-ResMed", "Health-Resmed", "Health-Scale", "Health-Starkey",
    "Health-Tandem", "Health-Thermom", "Health-Withings", "Health-Zoll", "Health-iHealth", "Home-ASSA", "Home-Alarm", "Home-Amazon",
    "Home-Aqara", "Home-August", "Home-AutoIO", "Home-BinSensor", "Home-Dyson", "Home-EnvSense", "Home-Haier", "Home-Lumi",
    "Home-Lutron", "Home-Mesh", "Home-Midea", "Home-MikroTik", "Home-Nest", "Home-Qingping", "Home-Resideo", "Home-Ruuvi",
    "Home-Sensirion", "Home-Shelly", "Home-Signify", "Home-SimpliSafe", "Home-SwitchBot", "Home-Tuya", "Home-Victron", "Home-Vivint",
    "Home-Wyze", "Home-Xiaomi", "Home-Yeelight", "Home-Yeelink", "Home-ecobee", "Home-iRobot", "Input-HID", "Input-Logitech",
    "Lock-ABUS", "Lock-ASSA", "Lock-August", "Lock-DOM", "Lock-Salto", "Lock-Schlage", "Lock-Sesame", "Lock-Tapkey",
    "Lock-Yale", "Phone-AppleGoog", "Phone-Huawei", "Phone-TelBearer", "Radio-Axon", "Radio-Inseego", "Radio-Kenwood", "Radio-Motorola",
    "Tag-Apple", "Tag-Chipolo", "Tag-ImmAlert", "Tag-Samsung", "Tag-Tile", "Vehicle-70mai", "Vehicle-Automatic", "Vehicle-BMW",
    "Vehicle-BYD", "Vehicle-Ford", "Vehicle-Fortin", "Vehicle-GM", "Vehicle-Geotab", "Vehicle-NIO", "Vehicle-PSA", "Vehicle-Rivian",
    "Vehicle-Samsara", "Vehicle-Sony", "Vehicle-TPMS", "Vehicle-Tesla", "Vehicle-Toyota", "Vehicle-VW", "Vehicle-Volkswagen", "Vehicle-Volvo",
    "Wearable-ActivMon", "Wearable-CSC", "Wearable-Circular", "Wearable-CyclePwr", "Wearable-Garmin", "Wearable-HeartRate", "Wearable-Huami", "Wearable-Jawbone",
    "Wearable-Meta", "Wearable-Motiv", "Wearable-Oura", "Wearable-Pebble", "Wearable-Polar", "Wearable-RSC", "Wearable-Suunto", "Wearable-Wahoo",
    "Wearable-Withings", "Wearable-Zwift",
};

static const uint16_t BLE_UUID16_KEYS[] = {
    0x1802, 0x1808, 0x1809, 0x180D, 0x1810, 0x1812, 0x1814, 0x1815, 0x1816, 0x1818, 0x181A, 0x181B, 0x181D, 0x181F, 0x1821, 0x1822,
    0x1826, 0x1827, 0x1828, 0x183A, 0x183B, 0x183E, 0x1840, 0x1844, 0x1846, 0x184B, 0x184E, 0x184F, 0x1850, 0x1851, 0x1852, 0x1853,
    0x1854, 0x1856, 0x1857, 0x1858, 0x1860, 0x3100, 0x3101, 0x3102, 0x3200, 0x3300, 0x3400, 0x3500, 0xFC25, 0xFC2C, 0xFC30, 0xFC31,
    0xFC39, 0xFC3D, 0xFC4A, 0xFC55, 0xFC58, 0xFC69, 0xFC6A, 0xFC6B, 0xFC7E, 0xFC81, 0xFC82, 0xFC83, 0xFC86, 0xFC87, 0xFC8F, 0xFC90,
    0xFC98, 0xFCA6, 0xFCA7, 0xFCA8, 0xFCA9, 0xFCB0, 0xFCB4, 0xFCB5, 0xFCB6, 0xFCB9, 0xFCBF, 0xFCC6, 0xFCCD, 0xFCD4, 0xFCDF, 0xFCE1,
    0xFCE4, 0xFCE5, 0xFCF4, 0xFD03, 0xFD20, 0xFD23, 0xFD25, 0xFD26, 0xFD2A, 0xFD3A, 0xFD3B, 0xFD3D, 0xFD41, 0xFD44, 0xFD4D, 0xFD4E,
    0xFD50, 0xFD54, 0xFD56, 0xFD57, 0xFD58, 0xFD59, 0xFD5A, 0xFD5E, 0xFD5F, 0xFD6F, 0xFD71, 0xFD72, 0xFD75, 0xFD76, 0xFD77, 0xFD78,
    0xFD79, 0xFD7A, 0xFD7B, 0xFD81, 0xFD82, 0xFD84, 0xFD86, 0xFD8A, 0xFD8E, 0xFD93, 0xFDA3, 0xFDA4, 0xFDA8, 0xFDA9, 0xFDAF, 0xFDB0,
    0xFDB1, 0xFDC5, 0xFDC6, 0xFDC7, 0xFDCA, 0xFDCD, 0xFDCE, 0xFDD2, 0xFDDF, 0xFDE1, 0xFDE3, 0xFDF6, 0xFDFA, 0xFDFB, 0xFE00, 0xFE03,
    0xFE04, 0xFE07, 0xFE0F, 0xFE15, 0xFE1F, 0xFE21, 0xFE22, 0xFE23, 0xFE24, 0xFE2C, 0xFE30, 0xFE31, 0xFE33, 0xFE3D, 0xFE3E, 0xFE45,
    0xFE47, 0xFE48, 0xFE4A, 0xFE4B, 0xFE4C, 0xFE54, 0xFE61, 0xFE65, 0xFE6A, 0xFE6B, 0xFE6C, 0xFE72, 0xFE73, 0xFE7A, 0xFE81, 0xFE82,
    0xFE83, 0xFE87, 0xFE88, 0xFE95, 0xFE96, 0xFE97, 0xFE9A, 0xFE9B, 0xFEA5, 0xFEA6, 0xFEAA, 0xFEAF, 0xFEB0, 0xFEB7, 0xFEB8, 0xFEBC,
    0xFEBE, 0xFED5, 0xFED9, 0xFEDC, 0xFEDD, 0xFEE0, 0xFEE1, 0xFEEC, 0xFEED, 0xFEEE, 0xFEEF, 0xFEFC, 0xFEFD, 0xFEFE, 0xFEFF, 0xFFFA,
};

static const uint8_t BLE_UUID16_LABEL[] = {
    138, 64, 81, 165, 57, 118, 173, 90, 161, 163, 93, 58, 78, 59, 28, 75,
    62, 97, 97, 68, 91, 160, 65, 13, 13, 131, 13, 13, 13, 13, 13, 13,
    11, 2, 23, 8, 154, 42, 42, 42, 42, 42, 42, 42, 34, 44, 41, 145,
    10, 33, 17, 144, 30, 10, 19, 19, 10, 132, 177, 84, 152, 152, 4, 35,
    103, 27, 27, 70, 70, 145, 73, 73, 73, 95, 85, 35, 14, 73, 149, 20,
    152, 152, 125, 31, 63, 123, 98, 71, 20, 44, 44, 108, 87, 136, 141, 141,
    109, 94, 77, 159, 159, 139, 139, 127, 168, 129, 7, 119, 72, 72, 176, 176,
    82, 82, 112, 126, 20, 140, 55, 106, 135, 143, 133, 133, 150, 43, 35, 170,
    170, 142, 61, 61, 146, 101, 16, 4, 10, 146, 55, 0, 80, 80, 87, 87,
    135, 19, 106, 87, 164, 4, 83, 83, 89, 9, 157, 157, 137, 56, 56, 53,
    147, 147, 73, 106, 157, 169, 119, 137, 29, 132, 132, 55, 55, 5, 70, 70,
    22, 115, 124, 113, 155, 155, 25, 152, 39, 39, 24, 100, 100, 168, 168, 60,
    4, 15, 171, 167, 167, 166, 166, 140, 140, 172, 172, 26, 26, 7, 7, 48,
};

static const uint16_t BLE_COMPANY_KEYS[] = {
    0x0043, 0x0055, 0x0057, 0x0068, 0x006B, 0x0087, 0x0089, 0x008A, 0x008C, 0x009E, 0x009F, 0x00BA, 0x00C7, 0x00CC, 0x00D0, 0x00D1,
    0x0118, 0x011F, 0x012D, 0x012E, 0x013B, 0x0157, 0x015D, 0x0164, 0x0171, 0x01AB, 0x01B5, 0x01D1, 0x01DA, 0x01F9, 0x01FC, 0x01FD,
    0x020E, 0x022B, 0x0241, 0x0243, 0x0275, 0x027D, 0x0293, 0x02B2, 0x02D5, 0x02E1, 0x02F2, 0x0304, 0x0309, 0x034D, 0x0360, 0x036F,
    0x038D, 0x03BB, 0x03C2, 0x03C5, 0x03FF, 0x048E, 0x0494, 0x0499, 0x04DE, 0x04EC, 0x058E, 0x059D, 0x05A7, 0x0600, 0x060C, 0x060F,
    0x0639, 0x065A, 0x067C, 0x06B1, 0x06C1, 0x06D5, 0x0723, 0x075D, 0x07C9, 0x07D0, 0x07D6, 0x0870, 0x08AA, 0x08C0, 0x08C3, 0x0909,
    0x0941, 0x094A, 0x094F, 0x0977, 0x09C8, 0x0A12, 0x0B01, 0x0B27, 0x0B48, 0x0B6B, 0x0BA9, 0x0BDE, 0x0C19, 0x0C34, 0x0CAC, 0x0CC2,
    0x0CC4, 0x0D10, 0x0D53, 0x0D5B, 0x0DE8, 0x0E25, 0x0E7B, 0x0E9F, 0x0EDE, 0x10D7, 0x10F9, 0x112B,
};

static const uint8_t BLE_COMPANY_LABEL[] = {
    47, 15, 10, 147, 172, 164, 12, 167, 26, 4, 174, 79, 31, 3, 60, 172,
    32, 158, 20, 121, 125, 166, 25, 114, 87, 168, 100, 122, 119, 70, 175, 29,
    73, 155, 5, 69, 148, 130, 22, 170, 73, 110, 39, 170, 6, 132, 67, 169,
    76, 55, 53, 55, 82, 66, 16, 103, 96, 135, 52, 80, 19, 117, 54, 106,
    30, 14, 140, 107, 86, 104, 145, 43, 18, 109, 116, 45, 46, 21, 137, 141,
    151, 177, 99, 156, 38, 92, 102, 88, 149, 152, 105, 128, 36, 144, 17, 1,
    120, 134, 51, 37, 111, 40, 162, 74, 153, 41, 49, 50,
};
