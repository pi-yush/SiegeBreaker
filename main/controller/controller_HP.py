import logging
import numbers
import socket
import struct
import json
import sys
import seccure

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.lib import addrconv
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import packet_base
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flag = False

    # Gets called when any new switch joins the network
    # Controller sends initial configuration and adds a default rule in table 0
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
	print 'Initializing switch'
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Adding default rules in table 100
    def add_table_100_redirection(self, dp, buffer_id):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match1 = parser.OFPMatch()
            
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        msg = parser.OFPFlowMod(datapath=dp, buffer_id = buffer_id, table_id = 100, priority = 2, match=match1, instructions=inst)
        dp.send_msg(msg)
        print 'pushing table 200 rules'    
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions, table_id=200)

    def add_icmp_redirection(self, dp, buffer_id):
	#hardware match i.e. tabel 100 for all ICMP packets
	print 'pushing ICMP redirection rules'
	ofproto = dp.ofproto
        parser = dp.ofproto_parser
	match1 = parser.OFPMatch(eth_type=0x0800 , ip_proto = 1)
	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        msg = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id, table_id=100, priority=30000, match=match1, instructions=inst)
        dp.send_msg(msg) 


    def add_redirection_flows(self, dp, buffer_id,srcport,dstip,timeout,srcip):
        overt_ip = '192.168.2.4'
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        
        # FOR TRAFFIC FROM CLIENT TO OD
        # matches in hardware (Table 100)

	match1 = parser.OFPMatch(eth_type = 0x0800, ipv4_src = srcip, ipv4_dst = overt_ip)#, tcp_src = int(srcport) )
        #actions = [parser.OFPActionSetField(eth_dst=cd_mac_usb), parser.OFPActionOutput(6)]
	actions = [parser.OFPActionOutput(6)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        msg = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id, table_id=100, priority=20000, match=match1, instructions = inst)
        dp.send_msg(msg)


    # Function to add normal routing/switching flows apart from DR flows
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=100, redirect_table=False, src_ip="", dst_ip=""):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print 'adding flow', match, redirect_table, datapath, actions

        if redirect_table:
            inst = []
            match1 = parser.OFPMatch(ipv4_src=src_ip, ipv4_dst=dst_ip)
            inst.append(parser.OFPInstructionGotoTable(200))
            msg = parser.OFPFlowMod(datapath=datapath, table_id=100, priority=3, match=match1, instructions=inst) # more priority than the controller, but less than the decoy flows
            datapath.send_msg(msg)
            #print 'sending_redirect_table'
            table_id = 200

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            #print match, table_id
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    # Callback function for every packet coming in from a rgistered SDN switch
    # All packets coming to the controller would hit this function
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg                               
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        #Parsing various headers
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv = pkt.get_protocols(ipv4.ipv4)
	pkt_icmp = pkt.get_protocols(icmp.icmp)

	if pkt_icmp:
	    encicmpdata = str(pkt.protocols[-1].data.data)
	    srcip = pkt.protocols[1].src

	    # Try to decrypt the ICMP payload, and check if it is a Decoy routing request
	    try:
            	icmpData = seccure.decrypt(encicmpdata, b'my private key')
            except AssertionError:
            	#self.logger.info('Send ICMP echo reply to [%s].', srcip, extra=self.sw_id)
		print "ICMP not of concern"
            	return

            if "Siege" in icmpData:
		print "Got a Decoy Routing PING"
            	timeout = 0 #in case client doesn't supply one, we will use OVS default
            	timeoutString = icmpData[icmpData.find('Siege')+5: icmpData.find('@')]
            	dstip = ip_addr_ntoa(icmpData[icmpData.find('@')+1: icmpData.find('#')])
		#dstip="192.168.2.4"
            	srcport = icmpData[icmpData.find('#')+1: icmpData.find('$')]
            	if timeoutString is not '':
                	timeout = int(timeoutString)
                	#self.logger.info("Timeout value received: %s", timeout, extra=self.sw_id)
		print timeout
		# If all the fields are extracted add redirection rules
	    	self.add_redirection_flows(datapath, msg.buffer_id,srcport,dstip,timeout,srcip)

        if ipv:
            ipv = ipv[0]
            src = ipv.src
            dst = ipv.dst
            print src, dst

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
 
        #install decoy routing flows if not already done
        if self.flag is False:
                #self.add_redirection_flows(datapath, msg.buffer_id)
                self.add_table_100_redirection(datapath, msg.buffer_id)
		self.add_icmp_redirection(datapath, msg.buffer_id)
                self.flag = True

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 2, match, actions, msg.buffer_id, table_id=200, redirect_table=False)
                if ipv is not None:
                        #print "Adding IP flow for this"
                        self.add_flow(datapath, 2, match, actions, msg.buffer_id, table_id=200, redirect_table=True, src_ip = ipv.src_ip, dst_ip=ipv.dst_ip)
            else:
                #print "adding flow2"
                self.add_flow(datapath, 2, match, actions, table_id=200, redirect_table=False)#,  src_ip = ipv.src_ip, dst_ip=ipv.dst_ip)
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


















