import optparse
import crypt
from threading import *

screenlock = Semaphore(value=1)
results = []
def gen_hash(password, salt, hashtype, hashPW):
    
    screenlock.acquire()    
    print "[+] Attempting password: " + password + "\n"
     
    hashdata = crypt.crypt(password, ("$" + hashtype + "$" + salt))
    genhash = (str(hashdata).split('$'))[3]
    
    if genhash == hashPW:
        print "[+] Password Found: " + password + '\n'
        #print "[+] generated hash: " + genhash + '\n'
        #print "[+] original hash: " + hashPW + '\n'
    screenlock.release()
    results.append(password)
    return


def Main():
    parser = optparse.OptionParser("usage %prog -o <OS> -u <user> -d <dictionary file> --hf <hashfile>")
    parser.add_option('-o', dest='osType', type='string',\
                      help='sepcify OS Type')
    parser.add_option('-u', dest='uname', type='string',\
                      help='specify username')
    parser.add_option('--hf', dest='hfile', type='string',\
                      help='specify hashfile') 
    parser.add_option('-d', dest='dfile', type='string',\
                      help='specify dectionary file')    
    (options, arg) = parser.parse_args()
    
    if(options.osType == None) | (options.uname == None) | (options.hfile == None) | (options.dfile == None):
        print parser.usage
        exit(0)
    else:
        osType = options.osType
        uname = options.uname
        hfile = options.hfile
        dfile = options.dfile
        
    hashfile = open(hfile)
    passFile = open(dfile)
    
    for line in hashfile.readlines():
        data = line.strip('\n')
        dataFields = str(data).split(':')
        username = dataFields[0]
        
        if username == uname:
            print "[+] Username " + username +": found\n"
            hashdata = dataFields[1]
            hdFields = str(hashdata).split('$')
            hashType = hdFields[1]
            salt = hdFields[2]
            hashPW = hdFields[3]
            
            for line in passFile.readlines():
                password = line.strip('\n')
                t = Thread(target=gen_hash, args=(password, salt, hashType, hashPW))
                t.start()
                t.join()
    
    print "_______________________________________\n"    
    for success in results:
        print "[+] Password Found: " + success + '\n'


if __name__ == '__main__':
    Main()