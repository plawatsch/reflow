import SocketServer
import json
import ipaddress
import pickle
import threading
import cherrypy
import socket


lock = threading.Lock()
known_hosts = {}
known_addresses = {}
known_victim_addresses = {}
known_victim_hosts = {}
offset = 10


def handleDNSQuery(client_name, client_addr, hostname):
    global offset
    # if we already know what to do, then just return that for performance sake
    ret = {"result" : "ok"}
    if hostname in known_hosts:
        ret["address"] = known_hosts[hostname]
        return ret

    # see if we have anything special to do
    try:
        original_addr = socket.gethostbyname(hostname)
    except Exception as e:
        print ("Error resolving hostname " + hostname)
        return {"result" : "fail", "reason" : "NX"}

    offset = offset+1
    new_addr = "10.8." + `int(offset/256)` + "." + `int(offset%256)`;

    known_hosts[hostname] = new_addr
    known_addresses[new_addr] = original_addr
    if client_addr not in known_victim_addresses:
        known_victim_addresses[client_addr] = {}

    if client_addr not in known_victim_hosts:
        known_victim_hosts[client_addr] = {}

    known_victim_addresses[client_addr][new_addr] = original_addr
    known_victim_hosts[client_addr][new_addr] = hostname

    ret["address"] = new_addr
    return ret

registered_proxy_flows = {}



def handleGetFlowRule(source_address, source_port, fake_dest_address, fake_dest_port):
    if fake_dest_address in known_addresses:

        dummy = "192.168.100.2"

        # see if we want to tproxy this thing 
        #print known_victim_addresses[dummy][fake_dest_address]
        #print known_victim_hosts[dummy][fake_dest_address]

        real_dest_address = known_victim_addresses[dummy][fake_dest_address]


        do_proxy = True
        if source_port == "-1":
            do_proxy = False

        proxy_ip = "192.168.1.55"
        proxy_port = "8080"
        #proxy_port = "9090"
        if do_proxy:
            flow_rule_in_forward = (source_address, source_port, fake_dest_address, fake_dest_port)
            flow_rule_out_forward = (fake_dest_address, source_port, proxy_ip, proxy_port)

            flow_rule_in_backward = (proxy_ip, proxy_port, fake_dest_address, source_port)
            flow_rule_out_backward = (fake_dest_address, fake_dest_port, source_address, source_port)

            registered_proxy_flows[(fake_dest_address,source_port)] = (real_dest_address, fake_dest_port)
            
        else:          
            flow_rule_in_forward = (source_address, source_port, fake_dest_address, fake_dest_port)
            flow_rule_out_forward = (fake_dest_address, source_port, real_dest_address, fake_dest_port)

            flow_rule_in_backward = (real_dest_address, fake_dest_port, fake_dest_address, source_port)
            flow_rule_out_backward = (fake_dest_address, fake_dest_port, source_address, source_port)

        ret = {}
        ret["result"] = "ok"
        ret["forward"] = (flow_rule_in_forward,flow_rule_out_forward)
        ret["backward"] = (flow_rule_in_backward,flow_rule_out_backward)
        return ret

        #return {"result": "ok", "address":known_addresses[fake_dest_address], "port" : fake_dest_port}

    return {"result": "fail", "reason" : "Unknown Address"}

def handleGetProxyMapping(source_address, source_port):
    connection = (source_address, source_port)
    #print "Trying to find connection " + `connection`
    if connection in registered_proxy_flows:
        ret = {}
        ret["result"] = "ok"
        ret["address"] = registered_proxy_flows[connection][0]
        ret["port"] = registered_proxy_flows[connection][1]
        #print "Returning to proxy: " + `ret`
        return ret
    return {"result": "fail", "reason" : "Unknown Mapping"}

def handleAppHint(pkgname, dst_addr, dst_port):
    print "Handling app hint", pkgname, dst_addr, dst_port
    return None

class MyTCPServer(SocketServer.ThreadingTCPServer):
    allow_reuse_address = True

class MyTCPServerHandler(SocketServer.BaseRequestHandler):

    def process(self, request_data):
        with lock:
            try:
                if "request" in request_data:
                    r = request_data["request"]
                    if r == "dnsquery":
                        return handleDNSQuery(request_data["clientname"], request_data["clientaddr"], request_data["hostname"])
                    elif r == "getflowrule":
                        return handleGetFlowRule(request_data["src_address"], request_data["src_port"], \
                            request_data["dst_address"], request_data["dst_port"])
                    elif r == "getproxymapping":
                        return handleGetProxyMapping(request_data["src_address"], request_data["src_port"])
                    elif r == "apphint":
                        return handleAppHint(request_data["pkgname"], request_data["dst_addr"], request_data["dst_port"])
            except Exception as e:
                return {"result" : "fail", "reason" : `e`}

        return {"result" : "fail"}

    def handle(self):
        ret = {"result" : "fail"}
        try:
            rec = self.request.recv(1024)
            #print ("Unpickled = \"" + rec + "\"")
            data = pickle.loads(rec)
            #print ("Processing query " + `data`)
            ret = self.process(data)

        except Exception as e:
            print("Exception wile processing message: ", e, "rec:", rec)

        try:
            #print ("Returning " + `ret`)
            self.request.sendall(pickle.dumps(ret));
        except Exception as e:
            print("Exception wile sending return message, thats rather unfortunate: ", e)


class Mapper():

    def run(self):
        server = MyTCPServer(('0.0.0.0', 13373), MyTCPServerHandler)
        server.serve_forever()

mt = Mapper()
print "Starting known name mapping server"
mt.run()
