# CAKE-ConnMark - For ASUS router running MERLIN firmware.  
  
This script reads active connections from conntrack and dynamically generates iptables rules to mark packets with DSCP values helping CAKE QoS classify and prioritize traffic properly. Once installed, the script will run every minute from 9:00 AM to 3:59 AM. You can update the cronjob as needed (cru).  
  
### __DEPENDENCIES:__  
1. ASUS Router running on the latest MERLIN firmware. (https://sourceforge.net/projects/asuswrt-merlin/files/)  
2. Must have custom script support and built in CAKE QoS feature.  
3. CAKE QoS must be enabled in diffserv4. Works well with CAKE-SpeedSync (enables diffserv4) - Install first here: https://github.com/mvin321/CAKE-SpeedSync  
  
### __INSTALLATION:__  
1. Ensure router is running on MERLIN firmware (check DEPENDENCIES section above)  
2. Login to your ASUS Router Web UI  
3. Enable JFFS custom scripts and configs (Administration > System)  
4. Enable SSH (LAN Only)  
5. Open CMD or PowerShell and connect to your router via SSH (example: ssh admin@192.168.1.1)  
6. Run syntax to install:            
```markdown
curl -fsSL "https://raw.githubusercontent.com/mvin321/CAKE-ConnMark/main/install.sh" | sh  
```
7. Script runs immediately after installation.  
  
### __CONFIGURATION FILES:__  
This scrip comes with sample configurations for gaming and video streaming, which you’ll need to customize by adding your own device IPs (e.g., gaming PCs, smart TVs, Fire Sticks). Once configured, it tags traffic so latency-sensitive applications like online games or video playback are prioritized.  
1. You must modify the configuration files to reflect your device IPs on SRCIP lines here (also check example below): /jffs/scripts/cake-connmark/cfg
2. You can create your own config files and place it in the same directory.

#### __Supported Config Parameters:__  
_CAKE-ConnMark will only read the following parameters from the *.cfg files.  
DO NOT include inline comments with these parameters. Comments on a separate line is fine._
| Parameter | Description                                                              | Example/Usage                          |
| --------- | ------------------------------------------------------------------------ | -------------------------------------- |
| __PROTOCOL__  [_udp/tcp/icmp_] | Protocol to look for in conntrack. Can set 1 or more (separate with space ) protocol                                 | PROTOCOL udp                           |
| __SRCIP__ [_ip address_] | Picks active connection from conntrack with this Source IP. Multiple ips can be set separated by a single space or a separate SRCIP line. Can set CIDR i.e 192.168.1.1/24 | SRCIP 192.168.2.10 192.168.2.11  |
| __DSTIP__ [ip address] | Picks active connection from conntrack with this Destination IP. Multiple ips can be set separated by a single space or a separate SRCIP line. Can set CIDR i.e 192.168.1.1/24 | DSTIP 8.8.8.8 8.8.4.4 |
| __PORT__ [_port number_] | This is destination port (remote port) (the one used in port forwarding). Can be set for multiple protocol (separate with 1 space) | PROTOCOL udp |
| __DSCP__ [_hex value_] | Check table below for the list of supported dscp value. Priority to set when creating iptables rules | DSCP 0x2e |
| __!SRCIP__ [_ip address_] | Opposite of SRCIP, exclude connection with this source IP. Usage is the same as SRCIP just put ! at the beginning | !SRCIP 192.168.2.10 |
| __!DSTIP__ [_ip address_] | Opposite of DSTIP, exclude connection with this source IP. Usage is the same as DSTIP just put ! at the beginning | !DSTIP 8.8.8.8 8.8.4.4 |
| __!PORT__ [_port number_] | Opposite of PORT, exclude connection with this destination port. Usage is the same as PORT just put ! at the beginning | !PROTOCOL udp |
| __!CHAIN__ [_FORWARD/POSTROUTING_] | Normally both outgoing and incoming traffic will be prioritized. In case you only need 1 way, you can exclude one here. i.e !CHAIN POSTROUTING if you only want the incoming packets prioritized. (good for streaming devices) | !CHAIN POSTROUTING |

#### Supported DSCP Classes by CAKE-ConnMark (diffserv4):  
_Install CAKE-SpeedSync to enable diffserv4: https://github.com/mvin321/CAKE-SpeedSync_
| Priority | DSCP Name | Decimal | Hex    | CAKE Class  |
| -------- | --------- | ------- | ------ | ----------- |
| Highest  | EF        | 46      | 0x2e   | Voice       |
| High     | AF41      | 34      | 0x22   | Video       |
|          | AF42      | 36      | 0x24   | Video       |
|          | AF43      | 38      | 0x26   | Video       |
| Normal   | CS0       | 0       | 0x00   | Best Effort |
| Lowest   | CS1       | 8       | 0x08   | Bulk        |

### Example Configurations  
#### Example 1: Streaming (i.e for Apple Tv, FireStick, Roku devices)  
    # Target protocol are both tcp and udp since video streaming can use either
    PROTOCOL tcp udp  

    #  My FireStick Devices  
    SRCIP 192.168.2.199  
    SRCIP 192.168.2.200  
    
    # DESTINATION PORT - these are the ports that are commonly used for streaming (but mostly 443). Update it as needed.  
    PORT 80 443 1935 8080  
    
    # Mark connection with DSCP 0x26 (lowest priority in Video tin, but higher than best-effort/default traffic)  
    DSCP 0x26  
    
    # EXCLUDE CHAIN - Exclude POSTROUTING chain. Only prioritize incoming traffic (use FORWARD chain only)  
    !CHAIN POSTROUTING  

#### Example 2: Gaming (i.e for PCs, Nintendo, Xbox, PlayStation, etc)  
    # Online games uses udp protocol for real-time game communication  
    PROTOCOL udp  
      
    # SOURCE IP (SCRIP)- Gaming Device IPs (Assign static IP to your devices). REPLACE IPS WITH YOUR GAMING DEVICE IPS.  
      
    #   My Gaming PCs  
    SRCIP 192.168.2.11  
    SRCIP 192.168.2.10  
      
    #   My Nintendo Switch Consoles  
    SRCIP 192.168.2.20  
    SRCIP 192.168.2.21  
      
    #   You can add more SRCIP lines as much as you need  
      
    # Any UDP traffic coming from SRCIP above that are NOT using ports (!PORT) below. 
    # Excluding ports that are not usable by games since I'm too lazy to put ports for each game. "!"" at the beginning means exclude (reverse match).  
    # If you want to specify the ports for a specific device you can also create your own cfg file. i.e pc-udp.cfg, nintendo-udp.cfg, xbox-udp.cfg, etc and use PORT instead of !PORT  
      
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
      
    # Mark connection with DSCP 0x22 (highest priority (Voice Tin))  
    DSCP 0x2e  
    # You can't have more than 1 line with DSCP tag. The last one will be followed otherwise.  
      
    # No !CHAIN line -- This means both Incoming and Outgoing traffic will be prioritized (use FORWARD and POSTROUTING chains)  
  
