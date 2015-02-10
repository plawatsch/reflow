# re/flow

## WARNING, this is not for the faint of heart.
## Some python as well as advanced networking knowledge is required to work with re/flow at the moment!

This project consists of two main parts:

* re/flow itself 
* streamgrabber


### re/flow



The main idea is to supply fake dns responses to some target hosts in order to redirect them to a fake / pseudo tun device which will in turn mangle the packets to allow for some fun routing / hijacking tricks.

Config is hard coded in various places in the source code, make sure to have a look at _everything_ before you start anything!


Requirements:
* Unbound
* dpkt/dnet
* pytun

Usage:
Start tunnelator to set up the fake / pseudo tun device.

Adapt map-server to fit your needs and start it.

If you care about delivering different fake dns responses to different hosts then start one unbound instance per victim host, otherwise one global unbound instance will do fine too. Unbound has to be compiled with support for python2 plugins. Sample config (and plugin) is provided in the unbound-plugin subdir.

Inside map-server.py adapt handleGetFlowRule to your needs.
The current example provided will simply forward all traffic through a local proxy at 192.168.1.55:8080. An example proxy that will query the mapping server for the real / intended destination is provided in the streamforwarder subdirectory.

A mitmproxy patch that will work with this pseudo transparent proxy mode is also provided.


### streamgrabber

Consists of an xposed module that will selectively exfiltrate all sent/received traffic for specific android packages as well as a receiver / command module that runs on a PC.
The xposed module will grab both plain as well as tls traffic sent using the standard android libraries. Should be easily adaptable to other libraries if your target uses something different.


Requirements:
* dpkt/dnet


Usage:

Adapt the streamreceiver.py file to fit your needs (eg change the names of the monitored packages, or do something different with received data).

Adapt, compile and activate the xposed module on your device.


The example streamreceiver provided will simply run the traffic through HttpParser and print it to stdout



