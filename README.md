# BX2debug 🔬

**BX2debug** is an advanced, high-performance **Behavioral Malware Analysis CLI** tool. It is built directly on top of the powerful [BX2trace](https://pypi.org/project/BX2trace/) engine to provide real-time, deep visibility into malicious activities.

Unlike standard debuggers, BX2debug is designed specifically for **automated malware analysis** and **stealth tracking**, allowing you to trace APIs, extract live strings from memory, and intercept network connections in real-time, all while evading anti-debugging techniques.

---

## 🌟 Features

- **🖥️ Live API Hooking:** Intercepts critical Windows APIs (e.g., CreateProcessW, connect, WSAConnect) dynamically via INT3 breakpoints.
- **🧠 Dynamic Memory Scanning:** Periodically scans the target's RW/RWX memory pages to extract new strings, URLs, and IoCs in real-time.
- **💣 Stealth Engine:** Automatically patches the PEB (BeingDebugged and NtGlobalFlag) to bypass anti-debugging protections.
- **🕸️ Child Process Tracking:** Automatically attaches to and follows spawned child processes (e.g., Process Hollowing).
- **📄 Structured JSON Reports:** Generates highly detailed JSON reports containing loaded DLLs, hooked events, extracted strings, and network connections.
- **⚡ Pure Python:** No heavy C++ dependencies required, running entirely in Python using ctypes.

---

## ⚙️ Requirements

- Windows 10 / 11 (x64)
- Python 3.11+
- **Administrator Privileges** (Required for SeDebugPrivilege to monitor processes).

---

## 📥 Installation

First, you must install the core engine BX2trace from PyPI, and then you can run the tool.

`ash
# 1. Install the core library
pip install BX2trace

# 2. Clone the BX2debug tool repository
git clone https://github.com/fareed1-ataf/BX2debug.git
cd BX2debug

# 3. Install requirements
pip install -r requirements.txt
`

---

## 🚀 Usage

You can run BX2debug directly from the command line against any executable.

### Basic Analysis
`ash
python main.py -t "C:\path\to\malware.exe"
`

### Advanced Usage with Custom Report Path
`ash
python main.py -t "C:\path\to\malware.exe" -o reports\my_analysis_report.json
`

### Command Line Arguments
- -t, --target: (Required) The path to the executable you want to analyze.
- -o, --output: (Optional) The path to save the generated JSON report (defaults to 
eports/report_<name>_<date>.json).

---

## 📋 Example Output

When running the tool, you will see a real-time ANSI-colored dashboard:

`	ext
============================================================
 [ BX2DEBUG - BEHAVIORAL ANALYSIS TOOL ] 
 Advanced Behavioral Malware Analysis CLI v1.0
============================================================
[*] Target Acquired: malware.exe
[*] Engines launched. Monitoring behavioral activity...

[+] [   DLL   ] Loaded: C:\Windows\System32\ntdll.dll @ 0x7ff9b4d10000
[*] [ PROCESS ] Spawned: C:\Windows\System32\cmd.exe (PID: 14396)
[!] [ API_CALL ] WSAConnect called -> 8.8.8.8:80 (PID: 14396)
[>] [ MEM_STR ] Extracted: "http://malicious-c2.com/payload.bin" (PID: 14396)
`

---

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.
