import optparse
from socket import *
from threading import *
import sys  
import os  

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

    portScan(tgtHost, tgtPorts)


if __name__ == "__main__":
    Main()

    
