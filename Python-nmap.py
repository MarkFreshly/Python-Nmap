
import sys
import nmap3
import simplejson as json
from pygments import highlight, lexers, formatters
import pyfiglet
import pathlib

ascii_banner = pyfiglet.figlet_format("My NMAP \n")
print(ascii_banner)
nmap = nmap3.Nmap()

print("Welcome, this is a simple nmap automation tool")
print("<*********************************************>  \n")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)


response = input("""\nPlease enter the scan you want to run
                1) OS Dection
                2) Stealth
                3) TCP Silent
                4) ARP
                5) ICMP
                6) Subnet
                7) Exit
                Your pick: """)
print('You have selected option: ', response)

while response != '7':

    if response == '1':

        os_results = nmap.nmap_os_detection(ip_addr)
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        OS_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)

        with open("OSscan.txt", "a") as outfile:
            outfile.writelines(OS_json)



    elif response == '2':

        os_results = nmap.nmap_stealth_scan(ip_addr)
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        s_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
                
        with open("Stealthscan.txt", "a") as outfile:
            outfile.writelines(s_json)
        
    elif response == '3':

        os_results = nmap.scan_top_ports(ip_addr, args='-sS -Pn -sV -vv -T4 --reason')
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        tcp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("TCPscan.txt", "a") as outfile:
            outfile.writelines(tcp_json)

    elif response == '4':

        os_results = nmap.scan_top_ports(ip_addr, args='-PR -vv -T4--reason')
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        arp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("ARPscan.txt", "a") as outfile:
            outfile.writelines(arp_json)
            

    elif response == '5':

        os_results = nmap.scan_top_ports(ip_addr, args='-PE -vv -T4 --reason')
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        icmp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("ICMPscan.txt", "a") as outfile:
            outfile.writelines(icmp_json)
            
    elif response == '6':

        os_results = nmap.nmap_subnet_scan(ip_addr)
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        sub_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("Subnetscan.txt", "a") as outfile:
            outfile.writelines(sub_json)  
        
    response = input("""\nPlease enter the scan you want to run
                1) OS Dection
                2) Stealth
                3) TCP Silent
                4) ARP
                5) ICMP
                6) Subnet
                7) Exit
                Your pick: """)
    print('You have selected option: ', response)
    continue