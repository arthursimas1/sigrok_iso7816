# ISO 7816 Smart Card Protocol Decoder for Sigrok

[![Codecov](https://img.shields.io/badge/codecov-76%25-brightgreen.svg?logo=codecov)]()
[![Sigrok](https://img.shields.io/badge/libsigrokdecode-supported-green.svg)](https://sigrok.org/)
[![Python](https://img.shields.io/badge/python-3.x-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A robust protocol decoder for the **ISO 7816 Smart Card** standard, built as a plug-in for the [libsigrokdecode](https://sigrok.org/wiki/Libsigrokdecode) framework. 

Whether you are reverse engineering a SIM card, analyzing EMV transactions, or troubleshooting custom smart cards with a logic analyzer via **PulseView** or **sigrok-cli**, this decoder provides deep packet inspection, automated baud rate detection, and seamless Wireshark integration.

---

## ✨ Features

- **Multi-ATR Handling:** Unlike other implementations (e.g., [`svenso/sigrok_iso7816`](https://github.com/svenso/sigrok_iso7816)), this decoder gracefully handles mid-session hardware resets and multiple ATR broadcasts, avoiding incorrect parsing or dropping messages.
- **Dynamic Auto-Baud Detection:** No clock line required! The decoder handles baud rates in two distinct phases: (1) measuring the initial ETU directly from the first falling edge pulse of the Answer To Reset (ATR), and (2) parsing the ATR data parameters and Protocol Parameter Selection (PPS) to dynamically adjust the baud rate for all subsequent messages.
- **Direct & Inverse Convention Support:** Natively adapts to both standard (Direct: `0x3B`) and reversed/inverted (Inverse: `0x3F`) bit-ordering conventions on the fly.
- **Deep Protocol Inspection (T=0 & T=1):** 
  - **T=0:** Parses headers, procedure bytes, and groups the payload into contiguous APDUs.
  - **T=1:** Extracts the Prologue (NAD, PCB, LEN), Information Field, and validates the Epilogue (LRC/CRC).
- **Wireshark Integration (PCAP Export):** Automatically exports raw card traffic into a standard binary PCAP file encapsulated with GSMTAP/UDP headers. Simply open the output in Wireshark for instant deep-dive APDU packet analysis.
- **Robust State Machine:** Built with a clean `PhysicalLayer` and `ProtocolLayer` architecture, verified by a comprehensive End-to-End bit stream testing framework.

---

## 🚀 Installation

To use this decoder, place the project folder into your local `libsigrokdecode` decoders directory.

### Linux
```bash
# Create the local decoders directory if it doesn't exist
mkdir -p ~/.local/share/libsigrokdecode/decoders/

# Clone or copy this repository into the decoders folder
git clone https://github.com/arthursimas1/sigrok_iso7816.git ~/.local/share/libsigrokdecode/decoders/iso7816
```

### Windows
Open Command Prompt or PowerShell and run:
```cmd
:: Create the local decoders directory if it doesn't exist
mkdir "%APPDATA%\sigrokdecode\decoders"

:: Clone the repository directly into the decoders folder
git clone https://github.com/arthursimas1/sigrok_iso7816.git "%APPDATA%\sigrokdecode\decoders\iso7816"
```

Restart PulseView or `sigrok-cli` to reload the decoders.

---

## 🛠️ Usage

### Channels Required
- **`RST` (Reset):** The decoder waits for a LOW-to-HIGH transition to kickstart the session. If `RST` goes LOW mid-session, the state machine resets appropriately.
- **`I/O` (Data):** The main bi-directional data line.

### Using PulseView (GUI)
1. Open your logic capture in PulseView.
2. Add the **"ISO 7816 Smart Card"** decoder from the protocol list.
3. Assign your logic analyzer traces to the `RST` and `I/O` channels.
4. *(Optional)* Configure the PCAP output path in the decoder options to export the APDUs to Wireshark.

### Using `sigrok-cli`
Run the decoder headlessly and immediately dump the output to a Wireshark PCAP file:

```bash
sigrok-cli -i capture.sr -P iso7816:rst=D0:io=D1 -B iso7816=pcap > output.pcap
```

*In the example above, `0` and `1` represent the logic analyzer pin numbers connected to RST and I/O respectively.*

---

## 🧪 Architecture & Testing

This decoder is built for maintainability and correctness, strictly separating signal processing from protocol mathematics:

- `PhysicalLayer`: Handles bit sampling, ETU timing delays, and parity checking.
- `ProtocolLayer`: Manages ATR parsing, PPS (Protocol Parameter Selection) negotiation, and T=0/T=1 framing.
- `Decoder`: Interfaces with the `sigrokdecode` API lifecycle.

**Testing:** The project includes a 100% native bit-stream simulation (`ISO7816Stream`) that feeds exact logical edge transitions to the `wait()` condition loops, allowing the entire physical and protocol pipeline to be unit tested End-to-End without external mocks.

Before running the tests, ensure you have installed the required development dependencies:
```bash
pip install -r requirements.txt
```

```bash
# Run the integration test suite with coverage
python3 -m coverage run test_pd.py

# Generate the HTML coverage report
python3 -m coverage html
```
