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
                Your pick: """)
print('You have selected option: ', response)


if response == '1' or 'OS':

    os_results = nmap.nmap_os_detection(ip_addr)
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    file_json = json.dumps(os_results, indent=4, sort_keys=True)
    print("\n\n", colored_json)

    file_path = pathlib.Path('home/master/OSscan.txt')
    if file_path.exists():
        with open("OSscan.txt", "w") as outfile:
            outfile.writelines(file_json)
    else:        
        with open("OSscan.txt", "x") as outfile:
            outfile.writelines(file_json)



elif response == '2' or 'Stealth':

    os_results = nmap.nmap_stealth_scan(ip_addr)
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    file_json = json.dumps(os_results, indent=4, sort_keys=True)
    print("\n\n", colored_json)
          
    file_path = pathlib.Path('home/master/Stealthscan.txt')
    if file_path.exists():
        with open("Stealthscan.txt", "w") as outfile:
            outfile.writelines(file_json)
        
    else:        
        with open("Stealthscan.txt", "x") as outfile:
            outfile.writelines(file_json)
        
elif response == '3' or 'TCP':

    os_results = nmap.scan_top_ports(ip_addr, args='-sS -Pn -sV -vv -T4 --reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    file_json = json.dumps(os_results, indent=4, sort_keys=True)
    print("\n\n", colored_json)
    with open("TCPscan.txt", "xaw") as outfile:
        outfile.writelines(file_json)

elif response == '4' or 'ARP':

    os_results = nmap.scan_top_ports(ip_addr, args='-PR -vv -T4--reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    file_json = json.dumps(os_results, indent=4, sort_keys=True)
    print("\n\n", colored_json)
    with open("ARPscan.txt", "w") as outfile:
        outfile.writelines(file_json)
            

elif response == '5' or 'ICMP':

    os_results = nmap.scan_top_ports(ip_addr, args='-PE -vv -T4 --reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    file_json = json.dumps(os_results, indent=4, sort_keys=True)
    print("\n\n", colored_json)
    with open("ICMPscan.txt", "w") as outfile:
        outfile.writelines(file_json)
            
elif response == '6' or 'Subnet':

    os_results = nmap.nmap_subnet_scan(ip_addr)
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    file_json = json.dumps(os_results, indent=4, sort_keys=True)
    print("\n\n", colored_json)
    with open("Subnetscan.txt", "w") as outfile:
        outfile.writelines(file_json)  
        
  