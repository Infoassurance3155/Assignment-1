import optparse
from socket import *
from threading import *
import sys  
import os  
import prettytable
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #This is supress scapy warnings

from scapy.all import *

#conf.iface='eth0' # network interface to use
conf.verb=0 # enable verbose mode - Is this actually working?
conf.nofilter=1
screenlock = Semaphore(value=1)

def bannerScanner(ip_address,port):
    banner = ""
    try:  
        s=socket(AF_INET, SOCK_STREAM)
        s.connect((ip_address,port))
        s.send("Data\r\n")
        print '[+] Connection to port ' + str(port)  + ' succeeded!'
        banner = s.recv(64)  
        print 'Banner: \n' + banner + "\n" 
    except Exception, e:
        print '[-] Connection to ' + ip_address + ' port ' + str(port) + ' failed: ' + str(e)
    finally:
        s.close()    
        
    #checkVul(banner)
    return

def tcp_connect_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
        return "Closed"
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
            return "Open"
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    else:
        return "CHECK"


def stealth_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
        return "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=dst_timeout)
            return "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def xmas_scan(dst_ip,dst_port,dst_timeout):
    xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=dst_timeout)
    if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(xmas_scan_resp.haslayer(TCP)):
        if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(xmas_scan_resp.haslayer(ICMP)):
        if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def fin_scan(dst_ip,dst_port,dst_timeout):
    fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=dst_timeout)
    if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(fin_scan_resp.haslayer(TCP)):
        if(fin_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def null_scan(dst_ip,dst_port,dst_timeout):
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=dst_timeout)
    if (str(type(null_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def ack_flag_scan(dst_ip,dst_port,dst_timeout):
    ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
    if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
        return "Stateful firewall present\n(Filtered)"
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
            return "No firewall\n(Unfiltered)"
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Stateful firewall present\n(Filtered)"
    else:
        return "CHECK"


def window_scan(dst_ip,dst_port,dst_timeout):
    window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
    if (str(type(window_scan_resp))=="<type 'NoneType'>"):
        return "No response"
    elif(window_scan_resp.haslayer(TCP)):
        if(window_scan_resp.getlayer(TCP).window == 0):
            return "Closed"
        elif(window_scan_resp.getlayer(TCP).window > 0):
            return "Open"
    else:
        return "CHECK"


def udp_scan(dst_ip,dst_port,dst_timeout):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
    if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
        for item in retrans:
            if (str(type(item))!="<type 'NoneType'>"):
                udp_scan(dst_ip,dst_port,dst_timeout)
        return "Open|Filtered"
    elif (udp_scan_resp.haslayer(UDP)):
        return "Open"
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            return "Closed"
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"

def start(your_target,your_ports,your_timeout):
    x = prettytable.PrettyTable(["Port No.","TCP Connect Scan","Stealth Scan","XMAS Scan","FIN Scan","NULL Scan", "ACK Flag Scan", "Window Scan", "UDP Scan"])
    x.align["Port No."] = "l"

    user_dst_ip = your_target
    port_list = your_ports
    user_dst_timeout = your_timeout

    print "[+] Target : %s\n" % user_dst_ip
    print "[*] Scan started\n"

    for i in port_list:
        tcp_connect_scan_res = tcp_connect_scan(user_dst_ip,int(i),int(user_dst_timeout))
        stealth_scan_res = stealth_scan(user_dst_ip,int(i),int(user_dst_timeout))
        xmas_scan_res = xmas_scan(user_dst_ip,int(i),int(user_dst_timeout))
        fin_scan_res = fin_scan(user_dst_ip,int(i),int(user_dst_timeout))
        null_scan_res = null_scan(user_dst_ip,int(i),int(user_dst_timeout))
        ack_flag_scan_res = ack_flag_scan(user_dst_ip,int(i),int(user_dst_timeout))
        window_scan_res = window_scan(user_dst_ip,int(i),int(user_dst_timeout))
        udp_scan_res = udp_scan(user_dst_ip,int(i),int(user_dst_timeout))
        x.add_row([i,tcp_connect_scan_res,stealth_scan_res,xmas_scan_res,fin_scan_res,null_scan_res,ack_flag_scan_res,window_scan_res,udp_scan_res])
    print x

    print "\n[*] Scan completed\n"

def checkVul(banner):  
    if len(sys.argv) >=2:  
        filename = sys.argv[1]  
        for line in filename.strip():  
            line = line.strip('\n')  
            if banner in line:  
                print "%s is vulnerable" %banner  
            else:  
                print "%s is not vulnerable" 
                
                
def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve " + tgtHost + ": Unknown host"
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print "\n[+] Scan results for: " + tgtName[0]
    except:
        print "\n[+] Scan Results for: " + tgtIP

    setdefaulttimeout(5)
    for tgtPort in tgtPorts:
        t = Thread(target=bannerScanner, args=(tgtHost, int(tgtPort)))
        t.start()
        

def Main():
    parser = optparse.OptionParser("usage %prog -H <target host> " +\
                                   "-p <target port>")
    parser.add_option("-H", dest="tgtHost", type="string", \
                      help="specify target host")
    parser.add_option("-p", dest="tgtPort", type="string", \
                      help="specify target port[s] seperated by comma")    
    (options, args) = parser.parse_args()
    
    if(options.tgtHost == None) | (options.tgtPort == None):
        print parser.usage
        exit(0)
    else:
        tgtHost = options.tgtHost
        tgtPorts = str(options.tgtPort).split(',')

    #portScan(tgtHost, tgtPorts)
    start(tgtHost,tgtPorts,1)


if __name__ == "__main__":
    Main()

    
