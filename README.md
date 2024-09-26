# Tin-Gate WiFi Deauthentication Tool

Welcome to **Tin-Gate**, a powerful WiFi deauthentication tool designed for security professionals and ethical hackers. This tool utilizes deauthentication packets to force devices off a network, allowing you to discover hidden targets and test the security of WiFi networks.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Disclaimer](#disclaimer)
- [Author](#author)

## Features

- **ARP Scanning**: Detect devices on the network using ARP requests.
- **mDNS Scanning**: Discover devices using multicast DNS queries.
- **Live Deauthentication Attack**: Continuously send deauthentication packets to specified target devices.
- **Colorful Terminal Output**: Enjoy a user-friendly experience with colorful ANSI terminal output.
- **Multi-threaded Operations**: Efficiently handle multiple targets using threading.

## Requirements

This tool requires Python 3 and the following libraries:

- `scapy`
- `pythonping`

You can install these libraries using the `requirements.txt` file.

## Installation

Clone the repository:

   ```bash
   git clone https://github.com/q4n0/tingate.git
   cd tingate
## Create a virtual environment (optional but recommended):


python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
#Install the required packages:

## Usage

    After launching the tool, select a network interface from the available options.
    The tool will perform an initial ARP scan followed by an mDNS scan to identify devices on the network.
    Once the targets are detected, it will initiate a live deauthentication attack against them.
    The tool will continuously send deauthentication packets to the identified devices, allowing you to monitor network behavior.

Note: Ensure you have the necessary permissions and ethical considerations in mind before using this tool.
Disclaimer

This tool is intended for educational and ethical hacking purposes only. The author is not responsible for any misuse or illegal activities performed using this tool. Always obtain permission before conducting any network security assessments.

This project is unlicensed and comes under no warranty and .
Author
b0urn3
Instagram: @onlybyhive
GitHub: q4n0

## “The night is darkest just before the dawn.” – The Dark Knight
