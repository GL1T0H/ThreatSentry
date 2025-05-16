# ThreatSentry

A PowerShell tool for threat hunters to collect and analyze system information, including architecture, IP, processes, security events, and more. Outputs are saved in JSON format, with basic info sent to Telegram.
![image](https://github.com/user-attachments/assets/8b9d74fa-8d94-49c6-bb97-920dbab1e59b)


## Features
- Collects system details (architecture, IP, users, version, etc.).
- Analyzes security events for specified Event IDs.
- Sends basic report to Telegram with file paths.

## Requirements
- Windows OS
- PowerShell 5.1 or higher
- Administrator privileges
- Telegram Bot Token and Chat ID

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/GL1T0H/ThreatSentry.git
## Usage
1. Run the script as an administrator
   ```bash
   .\ThreatSentry.ps1 -Telegram $true

