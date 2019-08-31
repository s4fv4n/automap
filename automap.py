import nmap 
import sys
import time

nm_scan = nmap.PortScanner()

try:
    sys.argv[1]
except IndexError:
    print("Usage : python3 auto-nmap.py <ip address>\n")
    print("Example: python3 auto-nmap.py 45.33.32.156\n")
    sys.exit()

print('\nRunning...\n')

nm_scanner = nm_scan.scan(sys.argv[1],'80,22,443',arguments='-sSV -O')

host_is_up = "The host is: "+nm_scanner['scan'][sys.argv[1]]['status']['state']+".\n"
guessed_os = "There is a %s percent chance that the host is running %s"%(nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['accuracy'],nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['name'])+".\n"

ports = nm_scanner['scan'][sys.argv[1]].all_tcp()
num_ports = len(nm_scanner['scan'][sys.argv[1]].all_tcp())


with open("%s.txt"%sys.argv[1], 'w') as f:
    if num_ports > 0:
        for p in ports:
            r = nm_scanner['scan'][sys.argv[1]]['tcp'][p]
            f.write("Port: %s"%p)
            f.write("\n-----------------\n")
            port_is_open = "The port %s is: "%p+r['state']+".\n"
            service = "Service: "+r['product']+"\n"
            version = "Version : "+r['version']+"\n"
            method_scan = "The method of scan is: "+r['reason']+".\n"
            f.write(host_is_up+port_is_open+service+version+method_scan)
            f.write("=====================\n")
    f.write(guessed_os)
    f.write("\nReport generated "+time.strftime("%d-%m-%Y_%H:%M:%S IST")+".\n")

print("\nA Report %s.txt was generated\n"%sys.argv[1])
print("\nFinished.\n")