#####   Graduation Project Version 0.1  #####
# 1. Select device						#####
# 2. Packet Capture						#####
# 3. Packet Analiysis					#####
# 4. Save DB							#####
# 5. Compare White List					#####
#############################################

########## Kutuphaneler #####################################################
import dpkt
import socket
import datetime
import time
import pcapy
import pcap
import sys
import os
import signal
import curses
from time import sleep
from struct import *
#############################################################################

########## Global degiskenler ############################################### 
#selectDevice = ""
#pcapFile = ""
#pcapWriter = ""
#############################################################################

########## Interfaceleri getirir ve secer ###################################
def get_myDevices():
	try:
		myDevices = pcapy.findalldevs()
		print "Makinedeki interfaceler ;"
	
		i = 1
		for d in myDevices :
			print "%s).  %s" %(i,d)
			i += 1

		print "---------------------------"
		selectDevice = raw_input("Bir interface seciniz : ")
		if selectDevice in myDevices:
			print "Izlenecek cihaz : " + selectDevice
			return selectDevice
		else:
			print "Girmis oldugunuz " + selectDevice + " makinenizde mevcut degil."
			sys.exit()
	except:
		print "Interfaceler listelenirken hata olustu."
		sys.exit()
#############################################################################

########## Pcap dosyasi acar ################################################
def openPcapFile():
	try:
		pcapFile = open('myPcapFile.pcap','wb+')
		return pcapFile
	except:
		print "Pcap dosyasi acilamadi."
		sys.exit()
#############################################################################

########## Socket olusturur #################################################
def createSocket():
	try:
			#s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
			rawSock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) #/usr/include/linux/if_ether.h
			return rawSock
	except socket.error , msg:
    		print 'Socket olusturulamadi. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    		sys.exit()
#############################################################################

########## Pcap dosya yazici olusturur ######################################
def createPcapWriter(pcapFile):
	try:
		pcapWriter = dpkt.pcap.Writer(pcapFile)
		return pcapWriter
	except:
		print "Pcap yazici acilamadi."
		sys.exit()
#############################################################################

########## Pcap dosya okuyucu olusturur #####################################
def createPcapReader(pcapFile):
	try:
		pcapReader = dpkt.pcap.Reader(pcapFile)
		return pcapReader
	except:
		print "Pcap okuyucu acilamadi."
		sys.exit()
#############################################################################

########## Sinyal olusturur #################################################
def signal_handler(signal, frame):
	time.sleep(1)
	global interrupted
	interrupted = True

signal.signal(signal.SIGINT, signal_handler)
interrupted = False
#############################################################################
def sigHandle(self, signum, frm): # Signal handler
    
        print "\n[!!!] Closing capture socket and shutting down [!!!]\n"
        sleep(1)
########## Paket yakalama ###################################################
def packetCapture(mySocket, myPcapFile):
	myPcapWriter = createPcapWriter(myPcapFile)

	#try:
	while True:
		writePcapFile(myPcapWriter)
		
		if interrupted:
			readPcapFile(myPcapFile)

	#except Exception as e:
	#	print "Paket yakalanirken hata olustu. Hata : %s" %str(e)
#############################################################################

########## Pcap dosyasina yaz ###############################################
def writePcapFile(myPcapWriter):
	mySocket = createSocket()
	try:
		myPacket = mySocket.recvfrom(65536)
		myPacket = myPacket[0]
		myPcapWriter.writepkt(myPacket)
	except:
		myPacket.close()
		print "soket hatasi"
#############################################################################

########## Pcap dosyasini oku ###############################################
def readPcapFile(myPcapFile):
    	print "safa"
	myPcapFile = open('myPcapFile.pcap','r')
	myPcapReader = dpkt.pcap.Reader(myPcapFile)
	http_ports = [80, 8080]
	urls = [ ]
	
	for timestamp, buf in myPcapReader:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data

		if tcp.__class__.__name__ == 'TCP':
			if tcp.dport in http_ports and len(tcp.data) > 0:
				try:
					http = dpkt.http.Request(tcp.data)
					urls.append('ip address : '  + socket.inet_ntoa(ip.dst) + 
								'\nhost name : ' + http.headers['host'] + 
								'\nuri : ' 	     + http.uri + 
								'\nmethod : '    + http.method + 
								'\n**********************************************************\n')
				except Exception as e:
					print("[-] Some error occured. - %s" % str(e))
					break
	myPcapFile.close()

	print("[+] URLs extracted from PCAP file are:\n")
	for url in urls:
		print url
#############################################################################


#############################################################################
def main(argv):
	mySocket = createSocket()
	myPcapFile = openPcapFile()
	packetCapture(mySocket, myPcapFile)
	signal.signal(signal.SIGINT, viewPkt.sigHandle)
#############################################################################

#############################################################################
if __name__ == "__main__":
  main(sys.argv)
#############################################################################