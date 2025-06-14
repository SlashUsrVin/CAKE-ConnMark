# CAKE-ConnMark - For ASUS router running MERLIN firmware.  

CAKE-ConnMark enhances traffic classification for CAKE QoS on Asuswrt-Merlin routers. It parses a user-defined configuration to identify active conntrack sessions based on protocol, IP addresses (with CIDR support), and ports. Matching connections are updated with a unique connection mark (connmark), which is then used to restore and apply the corresponding DSCP value via iptables.

By marking and tagging flows in real time, the script enables targeted prioritization of traffic types—such as gaming, streaming, or VoIP—based on user-defined rules. This ensures CAKE can enforce QoS policies even for ongoing connections that would otherwise bypass initial classification.

Once installed, the script will run every minute from 9:00 AM to 3:59 AM. You can update the cronjob as needed (cru).  
  
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
This script comes with sample configurations for gaming and video streaming, which __YOU WILL NEED TO CUSTOMIZE__ by adding your own device IPs (e.g., gaming PCs, smart TVs, Fire Sticks). Once configured, it tags traffic so latency-sensitive applications like online games or video playback are prioritized.  
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

  
#### Supported DSCP Classes by CAKE-ConnMark (diffserv4):  
_Install CAKE-SpeedSync to enable diffserv4: https://github.com/SlashUsrVin/CAKE-SpeedSync_  
| Priority | __DSCP Class__ | Decimal | Hex        | CAKE Tin        |  Conntrack Mark / Hex  |  
| -------- | -------------- | ------- | ---------- | --------------- | ---------------------- |  
| Highest  | __EF__         | 46      | __0x2e__   | __Voice__       |     4002  /  0xfa2     |  
|          | __VA__         | 44      | __0x2c__   | __Voice__       |     4001  /  0xfa1     |  
|          | __CS5__        | 40      | __0x28__   | __Voice__       |     4000  /  0xfa0     |  
| High     | __AF41__       | 34      | __0x22__   | __Video__       |     3003  /  0xbbb     |  
|          | __AF42__       | 36      | __0x24__   | __Video__       |     3002  /  0xbba     |  
|          | __AF43__       | 38      | __0x26__   | __Video__       |     3001  /  0xbb9     |  
|          | __CS4__        | 32      | __0x20__   | __Video__       |     3000  /  0xbb8     |  
| Normal   | __CS0__        | 0       | __0x00__   | __Best Effort__ |     2000  /  0x7d0     |  
| Lowest   | __CS1__        | 8       | __0x08__   | __Bulk__        |     1000  /  0x3e8     |  
  
### Example Configurations  
#### Example 1: Streaming (i.e for Apple Tv, FireStick, Roku devices)  
    # Target Protocol
    PROTOCOL tcp udp
    #  My FireStick Devices
    SRCIP 192.168.2.199 192.168.2.200
    # These are the ports that are commonly used for streaming (but mostly 443).
    PORT 80 443 1935 8080
    # Chain where CONNMARK will happen
    MARKCHAIN FORWARD
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
    # Mark connection with DSCP 0x2e (highest priority)
    DSCP 0x2e
  
### MANGLE restore mark and DSCP tagging  
#### Example unmarked flow (mark=0) in conntrack.  
###### (dummy IPs for illustration)  
    udp      17 179 src=192.168.2.11 dst=1.1.1.1 sport=52077 dport=59700 src=128.116.54.33 dst=127.0.0.1 sport=59700 dport=52077 [ASSURED] mark=0 use=1

#### Example marked flow in conntrack (i.e mark=4002, see table above for list of conntrack mark values)  
###### (dummy IPs for illustration)  
    udp      17 179 src=192.168.2.11 dst=1.1.1.1 sport=52077 dport=59700 src=128.116.54.33 dst=127.0.0.1 sport=59700 dport=52077 [ASSURED] mark=4002 use=1

#### Restore rules will be created in mangle table once, this will keep the marked flow prioritized until inactive/disconnected.  
###### The --mark argument is in hex value (see table above for list of conntrack mark values)  
    -A PREROUTING -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
    -A PREROUTING -m mark --mark 0xfa2 -j DSCP --set-dscp 0x2e
    -A PREROUTING -m mark --mark 0xfa1 -j DSCP --set-dscp 0x2c
    -A PREROUTING -m mark --mark 0xfa0 -j DSCP --set-dscp 0x28
    -A PREROUTING -m mark --mark 0xbbb -j DSCP --set-dscp 0x22
    -A PREROUTING -m mark --mark 0xbba -j DSCP --set-dscp 0x24
    -A PREROUTING -m mark --mark 0xbb9 -j DSCP --set-dscp 0x26
    -A PREROUTING -m mark --mark 0xbb8 -j DSCP --set-dscp 0x20
    -A PREROUTING -m mark --mark 0x7d0 -j DSCP --set-dscp 0x00
    -A PREROUTING -m mark --mark 0x3e8 -j DSCP --set-dscp 0x08