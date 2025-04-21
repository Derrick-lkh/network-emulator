# 🌐 Network Emulator

## Overview
This project is a simple network emulator written in Python that simulates communication between nodes, hubs, and routers. It enables packet transmission, broadcasting within the same network, and routing between different network segments. The emulator is designed to mimic basic networking concepts such as node-to-node communication, broadcasting, and inter-network routing via a router.

## Features
- **Node-to-Node Communication**: Nodes within the same network can exchange messages directly.
- **Broadcasting**: Nodes can broadcast messages to all other nodes in the same network.
- **Routing**: Facilitates communication between nodes in different networks through a router.
- **VPN Support**: Includes VPN client and server implementations for secure communication (based on `VPN.py`, `VPNClient.py`, `VPNServer.py`).
- **Firewall Simulation**: Supports basic firewall rules for packet filtering (based on `Firewall.py`).

## Network Setup

### Network 0x1
- **Hub A** (`hub_1.py`): Runs on `127.0.0.1:9000`
- **Node 1** (`node_1.py`): IP: `0x1A`

### Network 0x2
- **Hub B** (`hub_2.py`): Runs on `127.0.0.1:9900`
- **Node 2** (`node_2.py`): IP: `0x2A`
- **Node 3** (`node_3.py`): IP: `0x2B`
- **Node 4** (`node_4.py`): Not specified in the original setup but included for completeness.

### Router
- **Router** (`router_main.py`):
  - **Interface 1** (Network 0x1): IP: `0x11`
  - **Interface 2** (Network 0x2): IP: `0x21`

### VPN Setup
- **VPN Server** (`vpn_server_1.py`): Configurable for secure communication.
- **VPN Clients** (`vpn_client_1.py`, `vpn_client_2.py`): Connect to the VPN server for encrypted communication.

## File Structure
- `consts.py`: Defines constants used across the project (e.g., packet types, network configurations).
- `Enums.py`: Contains enumerations for packet types, protocols, or states.
- `Firewall.py`: Implements basic firewall functionality for packet filtering.
- `Frame.py`: Handles frame creation and parsing for data transmission.
- `Hub.py`: Base class or utilities for hub implementations.
- `NIC.py`: Simulates Network Interface Cards for nodes.
- `Node.py`: Base class for network nodes.
- `NodeInputHandler.py`: Manages input handling for nodes (e.g., user commands).
- `Packet.py`: Defines packet structure and handling logic.
- `Router.py`: Implements routing logic between networks.
- `VPN.py`, `VPNClient.py`, `VPNServer.py`: Handle VPN functionality for secure communication.
- `hub_1.py`, `hub_2.py`: Scripts to run Hub A and Hub B, respectively.
- `node_1.py`, `node_2.py`, `node_3.py`, `node_4.py`: Scripts to run individual nodes.
- `router_main.py`: Main script to run the router.
- `vpn_client_1.py`, `vpn_client_2.py`: Scripts to run VPN clients.
- `vpn_server_1.py`: Script to run the VPN server.
- `.env.sample`: Sample environment file for configuration.

## Setup and Running

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Derrick-lkh/network-emulator.git
   cd network-emulator
   ```

2. **Set Up Environment** (Optional):
   - Copy `.env.sample` to `.env`:
     ```bash
     cp .env.sample .env
     ```
   - Edit `.env` if you need to change default configurations (e.g., ports).

3. **Run the Router**:
   ```bash
   python router_main.py
   ```

4. **Run the Hubs**:
   - Hub A (Network 0x1):
     ```bash
     python hub_1.py
     ```
   - Hub B (Network 0x2):
     ```bash
     python hub_2.py
     ```

5. **Run the Nodes**:
   - Node 1 (Network 0x1):
     ```bash
     python node_1.py
     ```
   - Node 2 (Network 0x2):
     ```bash
     python node_2.py
     ```
   - Node 3 (Network 0x2):
     ```bash
     python node_3.py
     ```
   - Node 4 (Network 0x2, optional):
     ```bash
     python node_4.py
     ```

6. **Run the VPN** (Optional):
   - Start the VPN Server:
     ```bash
     python vpn_server_1.py
     ```
   - Start the VPN Clients:
     ```bash
     python vpn_client_1.py
     python vpn_client_2.py
     ```

## Usage
- Each node can send messages to other nodes in the same network directly.
- Use broadcasting to send messages to all nodes in the same network.
- The router facilitates communication between Network 0x1 and Network 0x2.
- Use the VPN server and clients for secure communication between nodes.
