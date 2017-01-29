# pyrevtun.py (v.001) - Reverse Tunnel/Reverse Port Forward utility to tunnel TCP protocols over SSL/TLS
#					  - Tested on Python 2.7.10 on Windows and Python 2.7.3 on Linux
#					  - Bugs/Issues: Sometimes RDP can be finicky, just try it again if it doesnt work (also try non-full screen mode)
#									 Graceful socket closure and shutdown - I'll work on this
# Motivation - firecat: http://www.bishopfox.com/resources/tools/other-free-tools/firecat/
#              powercat: https://github.com/besimorhino/powercat
# Credits - recvall function: http://code.activestate.com/recipes/213239-recvall-corollary-to-socketsendall/
# External Requirements - PEM SSL certificate and private key files for the listener
# Usage - 
#	Listener - python pyrevtun.py -m listener -l <listener IP:port> -t <local tunnel port> -s <certificate file> -k <private key file> -p <auth password>
#        e.g. On Local Machine - python pyrevtun.py -m listener -l 192.168.1.59:443 -t 33389 -s cert.pem -k key.pem -p password
#     Client - pyrevtun.py -m client -l <listener IP:port> -c <target IP:port> -p <password>
#		 e.g. On Remote Machine - pyrevtun.py -m client -l 192.168.102.59:443 -c 10.5.5.5:3389 -p password
#     App - Using app (i.e. RDP, SSH client), connect to specified local port as localhost:<local tunnel port> (i.e. localhost:33389)

import socket, ssl
import sys, os
import time
from optparse import OptionParser

BUFFER_SIZE = 1024
RECV_TIMEOUT = .00001

def recvall(the_socket, timeout= ''):
    #setup to use non-blocking sockets
    #if no data arrives it assumes transaction is done
    #recv() returns a string
    the_socket.setblocking(0)
    total_data=[];data=''
    begin=time.time()
    if not timeout:
        timeout=1
    while 1:
        #if you got some data, then break after wait sec
        if total_data and time.time()-begin>timeout:
            break
        #if you got no data at all, wait a little longer
        elif time.time()-begin>timeout*2:
            break
        wait=0
        try:
            data=the_socket.recv(BUFFER_SIZE)
            if data:
                total_data.append(data)
                begin=time.time()
                data='';wait=0
            else:
                time.sleep(0.1)
        except:
            pass
        #When a recv returns 0 bytes, other side has closed
    result=''.join(total_data)
    return result

def mode_listener(listenHost, listenPort, tunnelPort, sslfile, keyfile, passwd):
	#1 - Wait for connection from the remote target host
	try:
		listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listenSock.bind((listenHost, listenPort))
		listenSock.listen(1)
		print ('[*] Listening on TCP ' + str(listenPort))
	except socket.error, msg:
		print ('[-] Socket Error: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()
	
	#2 - Wait for target tunnel association
	try:
		listen_client_conn_tmp, listen_client_addr = listenSock.accept()
		listen_client_conn = ssl.wrap_socket(listen_client_conn_tmp, certfile=sslfile, keyfile=keyfile, server_side=True)
		
		print ('[*] Connection from ' + str(listen_client_addr[0]))	
		print ('[*] Establishing association between client and listener')
		if (listen_client_conn.recv(BUFFER_SIZE) != passwd):
			print ('[-] Failed to associate tunnel')
			listen_client_conn.close()
			sys.exit()
		else:
			print ('[*] Tunnel is now associated on listener side')
	except socket.error, msg:
		print ('[-] Tunnel Association Error: ' + str(msg))
		sys.exit()
	
	#3 - #Bind localhost port for tunneling
	try:
		tunnelSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		tunnelSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		tunnelSock.bind(('127.0.0.1', tunnelPort))
		tunnelSock.listen(1)
		print ('[*] Tunnel socket is accessible at localhost:' + str(tunnelPort))
	except socket.error, msg:
		print ('[-] Socket Error: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()
	
	#4 - Initate connection to target and tunnel traffic
	try:
		tunnel_client_conn, tunnel_client_addr = tunnelSock.accept()
		print ('[*] Connecting to target host through tunnel')
		listen_client_conn.send(passwd)
		print ('[*] Connected')
		while(1):
			data = recvall(tunnel_client_conn, RECV_TIMEOUT)
			listen_client_conn.sendall(data)
			data = recvall(listen_client_conn, RECV_TIMEOUT)
			tunnel_client_conn.sendall(data)
	except socket.error, msg:
		print ('[*] Socket Closed: ' + str(msg[0]) + ' Message ' + msg[1])

def mode_client(listenHost, listenPort, clientHost, clientPort, passwd):
	#1 - Establish connection with listener host
	try:
		print ('[*] Connecting to listening host at ' + listenHost + ':' + str(listenPort))
		listenSockTmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listenSock = ssl.wrap_socket(listenSockTmp)
		listenSock.connect((listenHost, listenPort))
	except socket.error, msg:
		print ('[-] Socket Error: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()		
		
	#2 - Send/receive client-listener association to move forward with tunnel establi
	try:
		print ('[*] Establishing association between client and listener')
		listenSock.send(passwd)
		if (listenSock.recv(BUFFER_SIZE) != passwd):
			print ('[-] Failed to associate tunnel')
			listenSock.close()
			sys.exit()
		else:
			print ('[*] Tunnel is now associated on client side')
	except socket.error, msg:
		print ('[-] Tunnel Association Error: ' + str(msg))
		sys.exit()
	
	#3 - Setup tunneling to client host/service
	try:
		print ('[*] Connecting to tunneled client service at ' + clientHost + ':' + str(clientPort))
		tunnelSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		tunnelSock.connect((clientHost, clientPort))
	except socket.error, msg:
		print ('[-] Socket Error: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()	
	
	#4 - Tunnel traffic
	try:
		print ('[*] Connected')
		while(1):
			data = recvall(listenSock, RECV_TIMEOUT)
			tunnelSock.sendall(data)
			data = recvall(tunnelSock, RECV_TIMEOUT)
			listenSock.sendall(data)
	except socket.error, msg:
		print ('[*] Socket Closed: ' + str(msg[0]) + ' Message ' + msg[1]) 
	
if __name__ == "__main__":
	parser = OptionParser()
	parser.add_option("-m","--mode", dest="mode", type="string", help="Modes- listener or client")
	parser.add_option("-p","--pass", dest="passwd", type="string", help="Passphrase for Authentication")
	parser.add_option("-s","--certfilessl", dest="sslfile", type="string", help="SSL cert file")
	parser.add_option("-k","--keyfilessl", dest="keyfile", type="string", help="SSL key file")
	parser.add_option("-l","--listenport", dest="listener", type="string", help="Listener Socket- host:port (i.e. 10.10.10.10:443)")
	parser.add_option("-t","--tunnelport", dest="tunnelport", type="int", help="Tunnel port for listener")
	parser.add_option("-c","--client", dest="client", type="string", help="Client Socket- host:port (i.e. 192.168.1.100:3389)")
	(options, args) = parser.parse_args()

	if (not options.mode) or (not options.passwd):
		print ('[-] Mode(-m) and password(-p) are mandatory switches')
		sys.exit()

	if (options.mode == 'listener'):
		if (not options.listener) or (not options.tunnelport) or (not options.sslfile) or (not options.keyfile):
			print('[-] Listener(-l), tunnel port(-t), SSL Cert file(-s) and SSL Key File(-k) are mandatory switches')
			sys.exit()
		else:
			if (':' not in options.listener):
				print('[-] Could not identify socket delimeter - :')
				sys.exit()
			else:
				listenhost, listenport = options.listener.split(':')
				mode_listener(listenhost, int(listenport), options.tunnelport, options.sslfile, options.keyfile, options.passwd)
	elif (options.mode == 'client'):
		if (not options.listener) or (not options.client):
			print('[-] Listener(-l) and client(-c) are mandatory switches')
			sys.exit()
		else:
			if (':' not in options.listener):
				print('[-] Could not identify socket delimiter - :')
				sys.exit()			
			elif (':' not in options.client):
				print('[-] Could not identify socket delimiter - :')
				sys.exit()				
			else:
				listenhost, listenport = options.listener.split(':')
				clienthost, clientport = options.client.split(':')
				mode_client(listenhost, int(listenport), clienthost, int(clientport), options.passwd)
	else:
		sys.exit()