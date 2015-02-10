import SocketServer
import json
import ipaddress
import pickle
import threading
import cherrypy
import socket
from struct import *
import struct
import dpkt
import traceback
import sys
import os
import urlparse

try:
    from http_parser.parser import HttpParser
except ImportError:
	print "Falling back to normal parser"
	from http_parser.pyparser import HttpParser



#monitored_apps = ["com.fitnesskeeper.runkeeper.pro"]
#monitored_apps = ["com.Seriously.BestFiends"]

monitored_apps = ["com.fitnesskeeper.runkeeper.pro",
	"com.Seriously.BestFiends",
	"de.heise.android.ct.magazin"]



class Constants(object):
    MSG_SHALL_MONITOR = 1
    MSG_CONNECT = 2
    MSG_DISCONNECT = 3
    MSG_PLAIN_READ = 4
    MSG_PLAIN_WRITE = 5
    MSG_TLS_READ = 6
    MSG_TLS_WRITE = 7

class ConnectionInfo(object):
    def __init__(self):
        self.pid = -1
        self.tid = -1
        self.uid = -1
        self.fd = -1
        self.package_names = []
        self.dst = ""

    def __str__(self):
        ret = "pkgs: " + `self.package_names` + "\n"
        ret += "Pid: " + `self.pid` + " Tid: " + `self.tid` + " Uid: " + `self.uid` + "\n"
        ret += "FD: " + `self.fd` + " dst: " + self.dst
        return ret;

def readAll(socket, l):
    ret = ""
    while len(ret) < l:
        ret += socket.recv(l - len(ret))

    return ret;


def readOneInt(request):
    rec = readAll(request, 4)
    res = unpack('!i', rec)[0]
    return res

def readString(request):
    l = readOneInt(request)
    if (l > 0):
        return readAll(request, l);        
    return ""

def readConnectionInfo(request):
    c = ConnectionInfo()
    c.pid = readOneInt(request)
    c.tid = readOneInt(request)
    c.uid = readOneInt(request)
    c.fd = readOneInt(request)

    num_package_names = readOneInt(request)
    #print 'num ppacks ', num_package_names
    for i in xrange(num_package_names):
        c.package_names.append(readString(request))
    #print 'going to read request dest'
    c.dst = readString(request)
    #print 'dst', c.dst
    return c;

def handle_monitoring_request(req, c):
    #print 'Will return 1'
    if len(monitored_apps) == 0:
    	return struct.pack('!i', 1)
    for a in c.package_names:
        if a in monitored_apps:
            print "Monitored app found!!"
            print c.package_names
            return struct.pack('!i', 1)
    print "App", c.package_names, "not monitored"
    return struct.pack('!i', 0);            

connection_maps = {}


def handle_connect(c):
	if not c.pid in connection_maps.keys():
		connection_maps[c.pid] = {}

	connection_maps[c.pid][c.fd] = [(HttpParser(2,True),[]), (HttpParser(2,True),[])]

def handle_disconnect(c):
	if not c.pid in connection_maps.keys():
		connection_maps[c.pid] = {}

	if c.fd in connection_maps[c.pid]:
		del connection_maps[c.pid][c.fd]

def feedDataToParser(parser, body, data, c, direction, encrypted):

	total_len = len(data)
	fed_len = 0
	#print "Feeding data"
	while fed_len < total_len:
		#print "Loop", fed_len, total_len
		remaining_len = total_len - fed_len;	
		consumed = parser.execute(data[fed_len:], remaining_len)
		# sometimes stupid keep alives are not accepted by the parser :(
		if consumed == 0:
			print "Failed to parse!"
			print "------"
			print data[fed_len:]
			print "------"
			return (HttpParser(2, True), [])

		if parser.is_partial_body():
			body.append(parser.recv_body())

		if parser.is_message_complete():
			print "\n\n\n"
			print "Message " + direction + " tls: " + `encrypted`
			print "App:", c.package_names
			print "FD:", c.fd, "dst:", c.dst
			#url = parser.get_url()
			#if len(url) > 0:
			#	print "Url:", url
			path = parser.get_path()
			if len(path) > 0:
				print "PATH:", path
			query_string = parser.get_query_string()
			if len(query_string) > 0:
				print "QUERY:", urlparse.parse_qsl(query_string, True)

			method = parser.get_method()
			if len(method) > 0:
				print "METHOD:", method
			
			
			h = parser.get_headers()
			for k, v in h.iteritems():
				print k,":",v

			if len(body) < 1000:
				print "Body:", body
			else:
				print "Body:", len(body), "bytes and thus skipped"
			sys.stdout.flush()

			body = [] 
			parser = HttpParser(2,True) 

		fed_len += consumed

	return (parser, body)

def handle_read(c, data, tls):
	try:
		if not c.pid in connection_maps or not c.fd in connection_maps[c.pid]:
			return
		(p, body) = connection_maps[c.pid][c.fd][0]	
		connection_maps[c.pid][c.fd][0] = feedDataToParser(p, body, data, c, "received", tls)

	except Exception as e:
		print "Exception in read handling", e

def handle_write(c, data, tls):
	try:
		if not c.pid in connection_maps or not c.fd in connection_maps[c.pid]:
			return
		(p, body) = connection_maps[c.pid][c.fd][1]	
		connection_maps[c.pid][c.fd][1] = feedDataToParser(p, body, data, c, "sent", tls)

	except Exception as e:
		print "Exception in write handling", e


class MyTCPServer(SocketServer.TCPServer):
    allow_reuse_address = True

class MyTCPServerHandler(SocketServer.BaseRequestHandler):


    def handle(self):        
        try:

            num_reqs = readOneInt(self.request)

            for id in xrange(num_reqs):

                request_type = readOneInt(self.request)

                c = readConnectionInfo(self.request)

                if request_type == Constants.MSG_SHALL_MONITOR:
                    self.request.sendall(handle_monitoring_request(self.request, c))
                    continue


                data_len = readOneInt(self.request)
                data = "";
                if data_len > 0: 
                    data = readAll(self.request,data_len)

                if request_type == Constants.MSG_CONNECT:
                	handle_connect(c)
                	continue

                if request_type == Constants.MSG_DISCONNECT:
                	handle_disconnect(c)
                	continue

                if request_type == Constants.MSG_PLAIN_READ or request_type == Constants.MSG_TLS_READ:
                	handle_read(c, data, request_type == Constants.MSG_TLS_READ)
                	continue

                if request_type == Constants.MSG_PLAIN_WRITE or request_type == Constants.MSG_TLS_WRITE:
                	handle_write(c, data, request_type == Constants.MSG_TLS_WRITE)
                	continue

                continue;


        except Exception as e:
            #print("Exception wile processing message: ", e, "request_type", request_type, "c", c.__str__())
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)
            print e

class Mapper():

    def run(self):
        server = MyTCPServer(('0.0.0.0', 13374), MyTCPServerHandler)
        server.serve_forever()

mt = Mapper()
print "Starting SocketServer"
mt.run()
