from scapy.all import *

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]

def scan_common_ports(target_domain, timeout=2):
    open_ports = []
    target_ip = socket.gethostbyname(target_domain)
    
    for port in COMMON_PORTS:
        reponse = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"),
        timeout=timeout, verbose=0)
        
        if reponse and reponse.haslayer(TCP) and reponse[TCP].flags == 0x12:
            open_ports.append(port)
            send(IP(dst=target_ip)/ TCP(dport=port, flags="R"), verbose=0)
        
    return open_ports

def main():
    target_domain = input("Enter the target domain: ")
    
    open_ports = scan_common_ports(target_domain)
    
    if open_ports:
        print("Opent common ports: ")
        print(open_ports)
    else:
        print("No open common not found.")
        
if __name__=='__main__':
    main()