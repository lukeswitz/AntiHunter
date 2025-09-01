
# Antihunter

![00C0E4AA-395F-4243-A6D5-737C3BED2442_1_105_c](https://github.com/user-attachments/assets/2f789984-bca3-4a45-8470-ba2d638e512f)

> [!NOTE]
> Early release. Stablility issues, breaking changes and other unexpected behavior may occur. 

## What is Antihunter?

A low-cost, open-source tool for wireless threat detection, tracking, and counter-surveillance.

## What Does Antihunter Do?

- Detect rogue WiFi/BLE devices and activity
- Hunt with directional antennas or proximity
- Deploy distributed perimeters via Meshtastic

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

**3. RF Security Analysis (Blue Team Defense):**
Antihunter's defensive suite transforms your device into a wireless threat detection platform, monitoring the RF spectrum for malicious activities commonly deployed by adversaries. The system analyzes 802.11 management frames in real-time, identifying attack patterns that could compromise network security or indicate active penetration testing. This mode is essential for:

* **Deauth/Disassociation Detection:** Monitors for deauth and disassoc attack frames, capturing source/destination MACs, BSSID, signal strength, and reason codes.

* **Beacon Flood Detection:** Identifies suspicious beacon patterns - tracks timing intervals and flags abnormally high beacon rates (>50 per 10s window) or short intervals (<50ms) indicating automated attacks.

* **Evil Twin/Rogue AP Detection:** Detects potential rogue access points through multiple methods:
     - Twin detection (multiple BSSIDs with same SSID)
     - Strong signal analysis (unusually close equipment)  
     - KARMA attack detection (excessive probe responses >10)
     - Open network spoofing (secure networks appearing as open)
     - Timing anomalies in beacon intervals

    Real-time alerting with audio notifications, GPS logging, and detailed reporting via web interface. AP goes offline during monitoring for dedicated radio resources.

    *Lots Coming Soon: Red Team tools, additional Blue Team detections, triangulation and richer correlation across WiFi/BLE/GPS.*

**GPS Location**

- Parses NMEA on UART2 (RX=GPIO44, TX=GPIO43) at 9600 baud (TinyGPSPlus).
- Web UI shows GPS Status and Last GPS Data; `/gps` endpoint returns lat/lon.
- Hits include GPS lat/lon when a valid fix exists.
- Perimeter mapping and more integrations on the way

**SD Logging:**

- SPI pins: CS=2, SCK=7, MISO=8, MOSI=9 (ESP32S3).
- Logs to `/antihunter.log` with timestamp, type (WiFi/BLE), MAC, RSSI, and GPS (if valid).
- Status and file list shown in Diagnostics.

**Mesh Network Integration (Meshtastic-compatible):**

Antihunter seamlessly integrates with Meshtastic-compatible mesh networks. When enabled, it can broadcast alerts for detected targets (from either List Scan or Tracker mode) directly over your meshtastic radio. 

This feature extends Antihunter's reach, allowing remote teams or distant nodes to receive immediate notifications about target activity, making it a critical asset for coordinated detection efforts over long ranges. Alerts are sent at a configurable interval (default: 10 seconds).

## How to Get Started

Getting Antihunter up and running is straightforward. Use the quick flasher or build from source: Simply clone the repository, open it in VS Code with PlatformIO, and flash your desired configuration.


### Quick Flasher Option
- If you choose not to build from source, precompiled bins are available in the `Dist` folder
- For Linux & macOS 
- Plug in your esp32s3 device, download & flash:
```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/refs/heads/main/Dist/flashAntihunter.sh && chmod +x flashAntihunter.sh && ./flashAntihunter.sh
```

> [!IMPORTANT]
> Early stage project, the hardware requirements shown here will be rapidly evolving. 

### 1. Prerequisites

*   **VS Code:** Visual Studio Code IDE.
*   **PlatformIO Extension:** Install the PlatformIO IDE extension in VS Code.
*   **Hardware:** 
    - ESP32 development board (Seeed XIAO ESP32S3 and other s3 varients) • **8MB** flash memory boards required for reliably
    - Passive piezo buzzer connected to the designated pin (optional)
    - Meshtastic board (Heltec, etc.) 

### 2. Clone the Repository

Open your terminal or command prompt and execute:

```bash
git clone https://github.com/lukeswitz/AntiHunter.git Antihunter_Project
cd Antihunter_Project
```

This creates a new folder `Antihunter_Project` containing the Antihunter source code.

### 3. Open in VS Code

Open the enclosed `AntiHunter` folder as your workspace in VS Code. PlatformIO will automatically detect the `platformio.ini` file at the root.

### 4. Flashing the Firmware

Antihunter supports multiple boards and two project variants (core `Antihunter` and `Antihunter_Mesh`). Your `platformio.ini` is set up to let you choose. 

*   **Select Your Target:**
    *   In the **VS Code Status Bar** (the blue bar at the bottom), locate the PlatformIO environment selector. It typically shows something like `Default (esp32s3)`.
    *   Click on it. A list of available environments will appear, clearly prefixed: `AntiHunter`, `AntiHunter_Mesh`
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
   <img width="1072" height="605" alt="image" src="https://github.com/user-attachments/assets/a0655482-0917-485e-b459-1ec46d322b94" />


*   **Targets (List Scan Watchlist):**
      *   Enter full MAC addresses (e.g., `00:11:22:33:44:55`) or OUI prefixes (e.g., `00:11:22`), one per line.
      *   Click `Save` to update your watchlist.
      *   `Download` exports your current target list.

*   **List Scan:**
      *   **Scan Mode:** Choose `WiFi Only`, `BLE Only`, or `WiFi + BLE`.
      *   **Duration:** Set the scan duration in seconds (0 for "Forever").
      *   **WiFi Channels CSV:** Specify channels to hop through (e.g., `1,6,11` or `1..13`).
      *   Click `Start List Scan`. (Note: The AP will go offline during the scan and return when stopped).
    
*   **Tracker (Single MAC "Geiger"):**
     *   **Scan Mode:** Choose `WiFi Only`, `BLE Only`, or `WiFi + BLE`.
     *   **Target MAC:** Enter the precise MAC address of the device you're tracking (e.g., `34:21:09:83:D9:51`).
     *   **Duration:** Set the tracking duration in seconds (0 for "Forever").
     *   Click `Start Tracker`. AP will disappear for the duration of the scan. The buzzer will emit tones that change in frequency and period based on the target's signal strength (RSSI) – higher pitch/faster for closer, lower pitch/slower for further.

*   **WiFi Traffic Sniffers:**
     *  Deauth/Disassoc Detection: Detects and logs deauthentication/disassociation frames (source, destination, BSSID, channel, RSSI, reason). Optional audio alert.
     *  Beacon Flood Detection: Flags abnormal/excess beacons (short intervals, bursty timing). Logs SSID, channel, RSSI, interval.

 *   **Buzzer:**
     *   **Beeps per hit (List Scan):** Configure how many times the buzzer beeps when a target is detected in List Scan mode (default: 2).
     *   **Gap between beeps (ms):** Adjust the pause between beeps (default: 80 ms).
     *   `Save Config` applies changes. `Test Beep` triggers a single test pattern.
    
*   **Mesh Network:**
     *   **Enable Mesh Notifications:** Toggle this checkbox to send detected target alerts over your connected Meshtastic device (default: enabled).
     *   `Test Mesh`: Sends a test message via UART to confirm mesh communication is active.
    *   Mesh alerts are sent approximately every 10 seconds if a target is detected.
     *   *(Hardware: The ESP32 communicates with your Meshtastic radio via `Serial1` on pins `RX=4`, `TX=5` at 115200 baud).
    *   **Meshtastic Configuration:** Enable serial, Set RX/TX (19/20 for Heltec v3), text message mode, 115200 baud.*

<img width="520" height="568" alt="Screenshot 2025-08-31 at 7 35 09 AM" src="https://github.com/user-attachments/assets/731b03f0-8d17-464f-9005-df27bb35d119" />

*   **Diagnostics:**
    *   Provides real-time system status: scan mode, scanning status, frames seen (WiFi/BLE), total hits, unique devices, active targets, ESP32 temperature, SD stats & files, GPS data and more.

*   **Last Results:**
    *   Displays a summary of the most recent scan or tracking session, including identified MACs, RSSI values, frame count, and other pertinent data.

Antihunter empowers you to assert control over your wireless environment, turning the invisible into actionable intelligence. Happy hunting.

## Credits

Thanks to

- @colonelpanichacks gadgets for pushing this development
- All the hackers/builders making it happen, and those who taught us along the way

## Disclaimer

> [!IMPORTANT]
> DISCLAIMER AND LIMITATION OF LIABILITY

THE SOFTWARE IN THIS REPOSITORY (“SOFTWARE”) IS PROVIDED “AS IS” AND “AS AVAILABLE,” WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, OR RELIABILITY. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL THE DEVELOPERS, MAINTAINERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OF OR OTHER DEALINGS IN THE SOFTWARE, INCLUDING WITHOUT LIMITATION ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, OR LOSS OF DATA, PROFITS, GOODWILL, OR BUSINESS INTERRUPTION, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

YOU ALONE ARE RESPONSIBLE FOR COMPLYING WITH ALL APPLICABLE LAWS, REGULATIONS, AND THIRD-PARTY RIGHTS. NO ADVICE OR INFORMATION, WHETHER ORAL OR WRITTEN, OBTAINED FROM THE PROJECT OR THROUGH THE SOFTWARE, CREATES ANY WARRANTY OR OBLIGATION NOT EXPRESSLY STATED HEREIN. IF APPLICABLE LAW DOES NOT ALLOW THE EXCLUSION OF CERTAIN WARRANTIES OR LIMITATION OF LIABILITY, THE DEVELOPERS’, MAINTAINERS’, AND CONTRIBUTORS’ AGGREGATE LIABILITY SHALL NOT EXCEED THE GREATER OF: (A) THE AMOUNT YOU PAID (IF ANY) FOR THE COPY OF THE SOFTWARE THAT GAVE RISE TO THE CLAIM, OR (B) USD $0.

BY ACCESSING, DOWNLOADING, INSTALLING, COMPILING, EXECUTING, OR OTHERWISE USING THE SOFTWARE, YOU ACCEPT THIS DISCLAIMER AND THESE LIMITATIONS OF LIABILITY.
