# SiberRecon v1.6

SiberRecon is a Python-based security reconnaissance tool designed to accelerate the process of network discovery and vulnerability analysis. Powered by multithreading, it scans targets in seconds and provides visual results.

## Features

- **Fast Scanning:** Parallel scanning of 18 critical ports (Threading) in seconds.
- **Banner Grabbing:** Capable of capturing service information (versions, etc.) on open ports.
- **Colorized Output:** Easy-to-read, color-coded status notifications on the terminal.
- **Reporting:** Save scan results in JSON or TXT formats.
- **System Metrics:** Collects detailed architecture and OS information about the target system.

## Installation

Python 3 must be installed on your computer to use this project.

1. **Clone the repository:**

   ```bash
   git clone https://github.com/ogulcantekines/SiberRecon.git
   cd SiberRecon
   ```

2. **Create a virtual environment (Recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   # venv\Scripts\activate     # Windows
   ```

3. **Install the required packages:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To perform a basic scan:

```bash
python3 main.py -t <TARGET_IP>
```

To save results to a file:

```bash
python3 main.py -t 127.0.0.1 -o report.txt
```

To view the help menu:

```bash
python3 main.py --help
```

## Legal Disclaimer

This tool is for legal penetration testing and educational purposes only. Usage on unauthorized systems is entirely the responsibility of the user.

**Developed by:** [ogulcantekines](https://github.com/ogulcantekines)
