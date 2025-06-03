# CAKE-ConnMark - For ASUS router running MERLIN firmware.  
  
This script reads active connections from conntrack and dynamically generates iptables rules to mark packets with DSCP values helping CAKE QoS classify and prioritize traffic properly. Once installed, the script will run every minute from 9:00 AM to 3:59 AM. You can update the cronjob as needed (cru).  
  
### __DEPENDENCIES:__  
1. ASUS Router running on the latest MERLIN firmware. (https://sourceforge.net/projects/asuswrt-merlin/files/)  
2. Must have custom script support and built in CAKE QoS feature.  
3. CAKE QoS must be enabled in diffserv4. Works well with CAKE-SpeedSync (enables diffserv4) - Install first here: https://github.com/SlashUsrVin/CAKE-SpeedSync  
  
### __INSTALLATION:__  
1. Ensure router is running on MERLIN firmware (check DEPENDENCIES section above)  
2. Login to your ASUS Router Web UI  
3. Enable JFFS custom scripts and configs (Administration > System)  
4. Enable SSH (LAN Only)  
5. Open CMD or PowerShell and connect to your router via SSH (example: ssh admin@192.168.1.1)  
6. Run syntax to install:            
```markdown
curl -fsSL "https://raw.githubusercontent.com/SlashUsrVin/CAKE-ConnMark/main/install.sh" | sh  
```
  
### __CONFIGURATION FILES:__  
This script comes with sample configurations for gaming and video streaming, which you’ll need to customize by adding your own device IPs (e.g., gaming PCs, smart TVs, Fire Sticks). Once configured, it tags traffic so latency-sensitive applications like online games or video playback are prioritized.  
1. You must modify the configuration files to reflect your device IPs on SRCIP lines here (also check example below): /jffs/scripts/cake-connmark/cfg  
2. You can create your own config files and place it in the same directory.  
  
#### __Supported Config Parameters:__  
_CAKE-ConnMark will only read the following parameters from the *.cfg files.  
DO NOT include inline comments with these parameters. Comments on a separate line is fine._  
| Parameter | Description                                                              | Example/Usage                          |  
| --------- | ------------------------------------------------------------------------ | -------------------------------------- |  
| __PROTOCOL__  [_udp/tcp/icmp_] | Protocol to look for in conntrack. Can set 1 or more (separate with space ) protocol                                 | PROTOCOL udp                           |  
| __SRCIP__ [_ip address_] | Picks active connection from conntrack with this Source IP. Multiple ips can be set separated by a single space or a separate SRCIP line. Can set CIDR i.e 192.168.1.1/24 | SRCIP 192.168.2.10  |  
| __!SRCIP__ [_ip address_] | Opposite of SRCIP, exclude connection with this Source IP. Usage is the same as SRCIP just put ! at the beginning | !SRCIP 192.168.2.10 |  
| __DSTIP__ [ip address] | Picks active connection from conntrack with this Destination IP. Multiple ips can be set separated by a single space or a separate SRCIP line. Can set CIDR i.e 192.168.1.1/24 | DSTIP 8.8.8.8 8.8.4.4 |  
| __!DSTIP__ [_ip address_] | Opposite of DSTIP, exclude connection with this Destination IP. Usage is the same as DSTIP just put ! at the beginning | !DSTIP 8.8.8.8 8.8.4.4 |  
| __PORT__ [_port number_] | This is destination port (remote port) (the one used in port forwarding). Can be set for multiple protocol (separate with 1 space) | PORT 7000:8000 |  
| __!PORT__ [_port number_] | Opposite of PORT, exclude connection with this destination port. Usage is the same as PORT just put ! at the beginning | !PORT 443 80 |  
| __DSCP__ [_hex value_] | Check table below for the list of supported dscp value. Priority to set when creating iptables rules | DSCP 0x2e |    
| __ICHAIN__ [_CHAIN NAME_] | Define which iptable (mangle) chain to be used for incoming traffic. Separate with space for multiple chains.  | ICHAIN FORWARD |  
| __OCHAIN__ [_CHAIN NAME_] | Define which iptable (mangle) chain to be used for outgoing traffic. Separate with space for multiple chains.  | ICHAIN FORWARD POSTROUTING |  
| __NCHAIN__ [_CUSTOM NAME_] (required for now)| This is a custom chain. It will be created when the script runs. This is used to group rules into single chain. Example, if you have multiple *.cfg files with the same NCHAIN, rules created based of those cfg will be grouped in the same chain.  | NCHAIN GAMING_TRAFFIC |  
  
#### Supported DSCP Classes by CAKE-ConnMark (diffserv4):  
_Install CAKE-SpeedSync to enable diffserv4: https://github.com/SlashUsrVin/CAKE-SpeedSync_  
| Priority | DSCP Name | Decimal | Hex    | CAKE Class  |  
| -------- | --------- | ------- | ------ | ----------- |  
| Highest  | EF        | 46      | 0x2e   | Voice       |  
|          | VA        | 44      | 0x2c   | Voice       |  
|          | CS5       | 40      | 0x28   | Voice       |  
| High     | AF41      | 34      | 0x22   | Video       |  
|          | AF42      | 36      | 0x24   | Video       |  
|          | AF43      | 38      | 0x26   | Video       |  
|          | CS4       | 32      | 0x20   | Video       |  
| Normal   | CS0       | 0       | 0x00   | Best Effort |  
| Lowest   | CS1       | 8       | 0x08   | Bulk        |  
  
### Example Configurations  
#### Example 1: Streaming (i.e for Apple Tv, FireStick, Roku devices)  
    # Target Protocol
    PROTOCOL tcp udp
    #  My FireStick Devices
    SRCIP 192.168.2.199 192.168.2.200
    # These are the ports that are commonly used for streaming (but mostly 443).
    PORT 80 443 1935 8080
    # Target chain for incoming traffic
    ICHAIN FORWARD
    # Since this are streaming devices no need to prioritize outgoing traffic.
    # Add OCHAIN line to also mark outgoing traffic (not recommended for streaming)
    # Redirect to custom chain (STREAMING) for marking
    NCHAIN STREAMING
    # Mark connection with DSCP 0x26 (video)
    DSCP 0x26
  
#### Example 2: Gaming (i.e for PCs, Nintendo, Xbox, PlayStation, etc)  
    # Target protocol
    PROTOCOL udp
    # My Gaming PCs
    SRCIP 192.168.2.11 192.168.2.10
    # My Nintendo Switch Consoles
    SRCIP 192.168.2.20 192.168.2.21
    # Exclude ports unrelated to game traffic instead of specifying ports for each game. 
    # Use PORT (not !PORT) to specify ports per game
    # DNS - Networking/Core Service  
    !PORT 53
    # DHCP Server - Networking/Core Service  
    !PORT 67
    # DHCP Client - Networking/Core Service  
    !PORT 68
    # TFTP - File Transfer / Networking  
    !PORT 69
    # HTTP - Web Traffic  
    !PORT 80
    # NTP - Time Sync / Networking  
    !PORT 123
    # NetBIOS Name Service - Legacy Windows Networking  
    !PORT 137
    # NetBIOS Datagram Service - Legacy Windows Networking  
    !PORT 138
    # SNMP - Monitoring/Network Management  
    !PORT 161
    # SNMP Trap - Monitoring/Network Management  
    !PORT 162
    # HTTPS - Web Traffic  
    !PORT 443
    # IKE (IPsec VPN) - VPN / Security  
    !PORT 500
    # RIP (Routing Information Protocol) - Routing / Networking  
    !PORT 520
    # SSDP (UPnP Discovery) - Device Discovery / IoT  
    !PORT 1900
    # WS-Discovery - Device Discovery / IoT  
    !PORT 3702
    # IPsec NAT Traversal - VPN / Security  
    !PORT 4500
    # mDNS (Multicast DNS / Bonjour) - Device Discovery / Local DNS  
    !PORT 5353
    # HTTP Alternate (Dev/Proxy Servers) - Web Traffic / Dev Tools  
    !PORT 8080
    # Unspecified / App-specific (e.g., IoT, Unifi, etc.) - Application-Specific  
    !PORT 19001
    # Target chain for incoming traffic
    ICHAIN FORWARD
    # Target chain for outgoing traffic
    OCHAIN FORWARD
    # Redirect to custom chain for marking
    NCHAIN GAMING
    # Mark connection with DSCP 0x2e (highest priority)
    DSCP 0x2e
  
### # Sample iptables output generated by this script (dummy IPs for illustration)
    -A FORWARD -s 192.168.2.10/32 -c 3171 683312 -j GAMING
    -A FORWARD -d 192.168.2.10/32 -c 5511 5149829 -j GAMING
    -A FORWARD -d 192.168.2.199/32 -c 25211 6347225 -j STREAMING
    -A GAMING -s 1.1.1.1/32 -p tcp -m tcp --sport 5223 -c 52 2080 -j DSCP --set-dscp 0x28
    -A GAMING -d 1.1.1.1/32 -p tcp -m tcp --dport 5223 -c 52 2860 -j DSCP --set-dscp 0x28
    -A GAMING -j RETURN
    -A STREAMING -s 8.8.8.8/32 -p tcp -m tcp --sport 443 -c 52 2080 -j DSCP --set-dscp 0x28
    -A STREAMING -j RETURN