import nmap3
import simplejson as json
from pygments import highlight, lexers, formatters
import pyfiglet


ascii_banner = pyfiglet.figlet_format("My NMAP \n")
print(ascii_banner)
nmap = nmap3.Nmap() #Nmap
nmapST = nmap3.NmapScanTechniques()

print("Welcome, this is a simple nmap automation tool")
print("<*********************************************>  \n")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)


response = input("""\nPlease enter the scan you want to run
                1) OS Dection
                2) DNS enumeration
                3) Syn/Sealth
                4) All ports
                5) Vulns
                6) Discovery
                7) Auth
                8) Brute
            
                9) Exit
                Your pick: """)
print('You have selected option: ', response)

while response != '9':

    if response == '1':

        os_results = nmap.nmap_os_detection(ip_addr, args="-sV")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        OS_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)

        with open("OSscan.txt", "a") as outfile:
            outfile.writelines(OS_json)


    elif response == '2':

        os_results = nmapST.nmap_dns_brute_script(ip_addr)
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        s_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
                
        with open("DNSscan.txt", "a") as outfile:
            outfile.writelines(s_json)
        
    elif response == '3':

        os_results = nmapST.nmap_syn_scan(ip_addr, args="-Pn -T4 ")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        tcp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("Synscan.txt", "a") as outfile:
            outfile.writelines(tcp_json)

    elif response == '4':

        os_results = nmap.nmap_subnet_scan(ip_addr, args="-T4")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        arp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("AllPortsscan.txt", "a") as outfile:
            outfile.writelines(arp_json)


    elif response == '5':

        os_results = nmap.nmap_version_detection(ip_addr, args="-sC --script=vuln")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        arp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("VulnScan.txt", "a") as outfile:
            outfile.writelines(arp_json)      

    elif response == '6':

        os_results = nmap.nmap_version_detection(ip_addr, args="-sC --script=discovery")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        arp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("Discovery.txt", "a") as outfile:
            outfile.writelines(arp_json)               

    elif response == '7':

        os_results = nmap.nmap_version_detection(ip_addr, args="-sC --script=auth")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        arp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("Auth.txt", "a") as outfile:
            outfile.writelines(arp_json)  

    elif response == '8':

        os_results = nmap.nmap_version_detection(ip_addr, args="-sC --script=brute")
        colored_json = highlight(json.dumps(os_results, indent=4, sort_keys=True), lexers.JsonLexer(),
                                     formatters.TerminalFormatter())
        arp_json = json.dumps(os_results, indent=4, sort_keys=True)
        print("\n\n", colored_json)
        with open("Brute.txt", "a") as outfile:
            outfile.writelines(arp_json)          
            
        
    response = input("""\nPlease enter the scan you want to run
                1) OS Dection
                2) DNS enumeration
                3) Syn/Sealth
                4) All ports
                5) Vulns
                6) Discovery
                7) Auth
                8) Brute
            
                9) Exit
                Your pick: """)
    print('You have selected option: ', response)
    continue