# Antihunter: Wireless Pursuit System
<img width="433" height="59" alt="image" src="https://github.com/user-attachments/assets/3008acbb-f969-4b7d-be2d-589c9ea52b62" />

## What is Antihunter?

Antihunter is a state-of-the-art ESP32-powered platform engineered for advanced wireless signal detection and tracking. Born from the need for a precise "RSSI foxhunting" tool at throwaway prices, Antihunter transforms your development board into a digital predator, capable of sniffing out both WiFi and Bluetooth Low Energy (BLE) transmissions with unparalleled agility. It's your essential gear for locating elusive devices, mapping wireless landscapes, or uncovering hidden signals with pinpoint accuracy.

## What Does Antihunter Do?

Antihunter provides powerful, real-time wireless intelligence through an intuitive web-based interface. It operates in two primary modes:

1.  **List Scan Mode (Area Surveillance):**
    Upload a list of target MAC addresses (full 6-byte) or OUI prefixes (first 3-byte Vendor ID). Antihunter will meticulously sweep the designated WiFi channels and BLE frequencies. Upon detection, you receive immediate audible alerts (customizable beep patterns) and detailed logs, including signal strength (RSSI), channel, and device name. This mode is perfect for:
    *   Passive monitoring of specific devices in an environment.
    *   Initial reconnaissance in a wireless survey.
    *   Identifying rogue access points or suspicious BLE beacons.

2.  **Tracker Mode (The Digital Foxhunt):**
    This is Antihunter's specialty for close-quarters signal pursuit. Provide a single target MAC address, and Antihunter transforms into a responsive "Geiger counter" for that specific device. As you move (or point a directional antenna), the device's integrated buzzer will dynamically adjust its pitch and tempo – faster and higher-pitched tones indicate you're closing in on the target, while a slow, deep click means the signal is weak or lost. Tracker mode is indispensable for:
    *   Locating lost or stolen wireless devices.
    *   Pinpointing the exact physical location of a transmitting device.
    *   Real-time "foxhunting" games and exercises.

**Mesh Network Integration (Meshtastic-compatible):**
Antihunter seamlessly integrates with Meshtastic-compatible mesh networks. When enabled, it can broadcast alerts for detected targets (from either List Scan or Tracker mode) directly over your meshtastic radio. This feature extends Antihunter's reach, allowing remote teams or distant nodes to receive immediate notifications about target activity, making it a critical asset for coordinated detection efforts over long ranges. Alerts are sent at a configurable interval (default: 10 seconds).

## How to Get Started

Getting Antihunter up and running is straightforward. Simply clone the repository, open it in VS Code with PlatformIO, and flash your desired configuration.

### 1. Prerequisites

*   **VS Code:** Visual Studio Code IDE.
*   **PlatformIO Extension:** Install the PlatformIO IDE extension in VS Code.
*   **Hardware:** 
    - ESP32 development board (Seeed XIAO ESP32S3, or ESP32-WROOM-32UE-N8/N16)
    - Passive piezo buzzer connected to the designated pin
    - Meshtastic board (Heltec, etc.)


### 2. Clone the Repository

Open your terminal or command prompt and execute:

```bash
git clone https://github.com/lukeswitz/AntiHunter.git Antihunter_Project
cd Antihunter_Project
```

This creates a new folder `Antihunter_Project` containing the Antihunter source code.

### 3. Open in VS Code

Open the `Antihunter_Project` folder as your workspace in VS Code. PlatformIO will automatically detect the `platformio.ini` file at the root.

### 4. Flashing the Firmware

Antihunter supports multiple boards and two project variants (core `Antihunter` and `Antihunter_Mesh`). Your `platformio.ini` is set up to let you choose.

*   **Select Your Target:**
    *   In the **VS Code Status Bar** (the blue bar at the bottom), locate the PlatformIO environment selector. It typically shows something like `Default (esp32s3)`.
    *   Click on it. A list of available environments will appear, clearly prefixed:
    *   Select the environment corresponding to your board and the project variant you wish to upload.

*   **Upload:** Click the "Upload" button (the right arrow icon) in the PlatformIO status bar. PlatformIO will compile the selected project and flash it to your connected ESP32 board.

## How to Use Antihunter (Web Interface)

Once flashed, Antihunter hosts a web interface for all operations.

1.  **Connect to Antihunter's Access Point (AP):**
    *   On your computer, phone, or tablet, scan for WiFi networks.
    *   Connect to the network: `Antihunter` 
    *   Default Password: `ouispy123`

2.  **Access the Web UI:**
    *   Open a web browser and navigate to `http://192.168.4.1/`.

3.  **Core Functionality:**

    *   **Targets (List Scan Watchlist):**
        *   Enter full MAC addresses (e.g., `00:11:22:33:44:55`) or OUI prefixes (e.g., `00:11:22`), one per line.
        *   Click `Save` to update your watchlist.
        *   `Download` exports your current target list.

    *   **List Scan:**
        *   **Scan Mode:** Choose `WiFi Only`, `BLE Only`, or `WiFi + BLE`.
        *   **Duration:** Set the scan duration in seconds (0 for "Forever").
        *   **WiFi Channels CSV:** Specify channels to hop through (e.g., `1,6,11` or `1..13`).
        *   Click `Start List Scan`. (Note: The AP will go offline during the scan and return when stopped).
        *   Click `Stop` to end any active scan.

        <img width="1064" height="521" alt="Screenshot 2025-08-28 at 5 37 21 PM" src="https://github.com/user-attachments/assets/284dc031-ce8e-47f9-aaab-e98fe19acae1" />

    *   **Tracker (Single MAC "Geiger"):**
        *   **Scan Mode:** Choose `WiFi Only`, `BLE Only`, or `WiFi + BLE`.
        *   **Target MAC:** Enter the precise MAC address of the device you're tracking (e.g., `34:21:09:83:D9:51`).
        *   **Duration:** Set the tracking duration in seconds (0 for "Forever").
        *   **WiFi Channels CSV:** For best results, use a single channel (e.g., `6`) for smoother tracking.
        *   Click `Start Tracker`. The buzzer will emit tones that change in frequency and period based on the target's signal strength (RSSI) – higher pitch/faster for closer, lower pitch/slower for further.
        *   Click `Stop` to end tracking.

           <img width="1062" height="495" alt="image" src="https://github.com/user-attachments/assets/73757dbb-ed8e-48d1-947f-4feb873b506c" />

    *   **Buzzer:**
        *   **Beeps per hit (List Scan):** Configure how many times the buzzer beeps when a target is detected in List Scan mode (default: 2).
        *   **Gap between beeps (ms):** Adjust the pause between beeps (default: 80 ms).
        *   `Save Config` applies changes. `Test Beep` triggers a single test pattern.
    
    *   **Mesh Network:**
        *   **Enable Mesh Notifications:** Toggle this checkbox to send detected target alerts over your connected Meshtastic device (default: enabled).
        *   `Test Mesh`: Sends a test message via UART to confirm mesh communication is active.
        *   Mesh alerts are sent approximately every 10 seconds if a target is detected.
        *   *(Hardware: The ESP32 communicates with your Meshtastic radio via `Serial1` on pins `RX=7`, `TX=6` at 115200 baud).
        *   **Meshtastic Configuration:** Enable serial, Set RX/TX (19/20 for Heltec v3), text message mode, 115200 baud.*

        <img width="1065" height="666" alt="image" src="https://github.com/user-attachments/assets/6e7b6fda-7775-47be-8469-53de7712facc" />
    
    *   **Diagnostics:**
        *   Provides real-time system status: scan mode, scanning status, frames seen (WiFi/BLE), total hits, unique devices, active targets, ESP32 temperature, and more.

    *   **Last Results:**
        *   Displays a summary of the most recent scan or tracking session, including identified MACs, RSSI values, and other pertinent data.

Antihunter empowers you to assert control over your wireless environment, turning the invisible into actionable intelligence. Happy hunting.

## Credits

Built by @SirhaXalot_

Thanks to 

- @colonelpanichacks devices for pushing this development
- @lukeswitz for various firmware contributions
