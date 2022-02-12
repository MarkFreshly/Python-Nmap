
import sys
import nmap3
import simplejson as json
from pygments import highlight, lexers, formatters
import pyfiglet

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
                2) UPD Silent
                3) TCP Silent
                4) ARP
                5) ICMP
                Your pick: """)
print('You have selected option: ', response)


if response == '1' or 'OS':

    os_results = nmap.nmap_os_detection(ip_addr)
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    print("\n\n", colored_json)

elif response == '2' or 'UDP':

    os_results = nmap.scan_top_ports(ip_addr, args='-sU -Pn -sV -vv -T4 --reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    print("\n\n", colored_json)

elif response == '3' or 'TCP':

    os_results = nmap.scan_top_ports(ip_addr, args='-sS -Pn -sV -vv -T4 --reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    print("\n\n", colored_json)

elif response == '4' or 'ARP':

    os_results = nmap.scan_top_ports(ip_addr, args='-PR -vv -T4--reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    print("\n\n", colored_json)

elif response == '5' or 'ICMP':

    os_results = nmap.scan_top_ports(ip_addr, args='-PE -vv -T4 --reason')
    colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
    print("\n\n", colored_json)