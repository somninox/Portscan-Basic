#sudo apt-get install nmap
#sudo apt-get install python-setuptools
#sudo easy_install

import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)
#only want one thread to print at once

def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCKET_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send("hello\r\n")
		#create and test connection to host and port

		results = connSkt.recv(100)
		screenLock.acquire()
		print "[+] " + str(tgtPort) + "/tcp open"
		#returns whether port is open or closed

	except:
		screenLock.acquire()
		print "[-] " + str(tgtPort) + "/tcp closed"

	finally:
		screenLock.release()
		connSkt.close()
		#closes connection

def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
		#get host IP address from host variable

	except:
		print "[-] Cannot resolve " + tgtHost + ": Unknown host"
		return
		#fails to return host IP address

	try:
		tgtName = gethostbyaddr(tgtIP)
		print "\n[+] Scan Results for: " + tgtName[0]
		#return scan results for host after IP is obtained/host resolved

	except:
		print "\n[+] Scan Results for: " + tgtIP

	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
		#create thread for connection scan and socket connection

def Main():
	parser = optparse.OptionParser("usage %prog -H <target host> " + \
		"-p <target port>")
	parser.add_option("-H", dest="tgtHost", type="string", \
		help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", \
		help="specify target port[s] separated by a comma")

	#define options for parser

	(options, args) = parser.parse_args()
	if (options.tgtHost == None) | (options.tgtPort == None):
		print parser.usage
		exit(0);
		#if options are null exit program

	else:
		tgtHost = options.tgtHost
		tgtPorts = str(options.tgtPort).split(',')
		#obtain target host and ports through parser

	portScan(tgtHost, tgtPorts)
	#scan target host and ports

if __name__ == '__main__':
	Main() 