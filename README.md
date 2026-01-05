# epson-projector-discovery

## Overview
This project provides a Python script to discover Epson projectors on a network using UDP broadcast. It sends a discovery packet and listens for responses from projectors, returning their IP addresses and projector IDs.

## Features
- Discovers Epson projectors on the network.
- Configurable timeout, broadcast IP, port, and local IP.
- Returns a list of discovered devices with their IP addresses and projector IDs.

## Requirements
- Python 3.9 or higher

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/Evangelisches-Schulzentrum-Leipzig/epson-projector-discovery.git
   ```
2. Navigate to the project directory:
   ```bash
   cd epson-projector-discovery
   ```
3. Customize your `local_ip` for the correct network on the last row in the python file `epson-discover.py`
4. Run the script:
   ```bash
   python3 epson-discover.py
   ```
   You can customize the parameters like `local_ip`, `timeout`, etc., by modifying the `discover` function call in the script.

## Example Output
```
Sending discovery packet: 45 53 43 2f 56 50 2e 6e 65 74 10 01 00 00 00 00
ASCII: ESC/VP.net
Broadcasting to: 10.1.255.255 : 3629
Binding to local IP: 10.1. : 3629
Timeout: 2.0
Discovered devices: 1
[{'ip': '10.1.195.1', 'projector_id': 'EB205'}]
```

## Contributing

Contributions and Improvements of any kind are welcome!

## License
This project is licensed under the Open Software License 3.0.