# Network Emulator

## Overview
A simple network emulator simulating communication between nodes through hubs and routing between two networks via a router. It allows packet transmission, broadcasting, and routing between different network segments.

## Network Setup

### Network A
- **Node 1**: IP: `192.168.1.2`, MAC: `AA:BB`
- **Node 2**: IP: `192.168.1.3`, MAC: `CC:DD`
- **Hub**: IP: `192.168.1.1`

### Network B
- **Node 3**: IP: `192.168.2.2`, MAC: `EE:FF`
- **Hub**: IP: `192.168.2.1`

### Router
- **Interface 1** (Network A): IP: `192.168.1.254`
- **Interface 2** (Network B): IP: `192.168.2.254`

## Features
- **Node-to-Node Communication**: Direct message exchange within the same network.
- **Broadcasting**: Nodes can broadcast messages to all other nodes in the same network.
- **Routing**: Facilitates communication between different networks.
  
## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/network-emulator.git
   cd network-emulator
    ```
2. Run the Hub:
   ```bash
   python hub.p
    ```
3. Run the Nodes:
   ```bash
   python node-A,py # AA:BB
   python node-B.py # CC:DD
    ```