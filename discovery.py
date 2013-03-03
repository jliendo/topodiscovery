"""
Copyright (c) 2013, Javier Liendo All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list
of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


from pox.core import core
from pox.lib.revent import *
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import networkx as nx
import matplotlib.pyplot as plt
import time
import threading
from util import *
from scapy.all import *

log = core.getLogger()

class Discovery( EventMixin ):

    def __init__(self):
        # networkx representation of the topology
        self.topo = nx.Graph()
        # global mac-address-table (dpid, port, mac, ip)
        self.gmat = []

        # XXX super temporal...avoid ARP discovering while troubleshooting
        # assumes mininet started with '--mac' option and topo has to mandatory
        # have only 7 nodes
        self.gmat = [dict(ip='10.0.0.1',mac='00:00:00:00:00:01',dpid=1,port=1),
                     dict(ip='10.0.0.2',mac='00:00:00:00:00:02',dpid=2,port=1),
                     dict(ip='10.0.0.3',mac='00:00:00:00:00:03',dpid=3,port=1),
                     dict(ip='10.0.0.4',mac='00:00:00:00:00:04',dpid=4,port=1),
                     dict(ip='10.0.0.5',mac='00:00:00:00:00:05',dpid=5,port=1),
                     dict(ip='10.0.0.6',mac='00:00:00:00:00:06',dpid=6,port=1),
                     dict(ip='10.0.0.7',mac='00:00:00:00:00:07',dpid=7,port=1)]
        # list of switches already scheduled w/sendLLDP
        self.scheduled_switches = []
        # send lldp every ldp ttl seconds
        self.lldp_ttl = 1
        # listen to all pox/openflow events
        core.openflow.addListeners(self)


        # XXX what should be the link_collector (checking for "freshness" of links
        # between nodes) interval???
        Timer(self.lldp_ttl * 3, self.link_collector, recurring = True)
        log.info('Discovery link collector started')


    def _handle_ConnectionUp(self, event):

        # XXX while debugging del all flows from switches
        msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
        conn = core.openflow.getConnection(event.dpid)
        conn.send(msg)
        log.debug('DISCOVERY: Clearing all flows from %s' % event.dpid)

        # install flow for all LLDP packets to be forward to controller
        msg = of.ofp_flow_mod()
        # LLDP Ether type
        msg.match.dl_type = 0x88cc
        # LLDP dest addr '01:80:c2:00:00:0e'
        msg.match.dl_dst = '\x01\x80\xc2\x00\x00\x0e'
        # LLDPs to controller
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.debug('LLDP flow-mod configuration sent. Switch: %s' % event.dpid)
        # if dpid no scheduled, then do it!
        if not event.dpid in self.scheduled_switches:
            Timer(self.lldp_ttl, self.send_LLDP, args = [event], recurring = True)
            self.scheduled_switches.append(event.dpid)

        # install flow for al ARP packets to be forwarded to controller
        msg = of.ofp_flow_mod()
        # ARP Ether type
        msg.match.dl_type = 0x0806
        msg.match.dl_dst = '\xff\xff\xff\xff\xff\xff'
        # ARPs to controller
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.debug('ARP flow-mod configuration sent. Switch: %s' % event.dpid)

    
    def _handle_ConnectionDown(self, event):
        n1 = event.dpid
        if n1 in self.topo.nodes():
            log.info("Switch %s is DOWN" % n1)
            neighboring_nodes = [n for i, (p, n) in enumerate(self.topo.node[n1]['link_to'])]
            for n in neighboring_nodes:
                delete_edge(self.topo, n1, n)
            # remove node from topological view
            self.topo.remove_node(n1)
            # remove switch from LLDP send scheduled dpids
            self.scheduled_switches.remove(n1)


    def _handle_PortStatus(self, event):
        # is port config down or port link down?
        if event.ofp.desc.config == 1 or event.ofp.desc.config == 1:
            # convenience variables
            n1 = event.dpid
            p1 = event.port
            #log.debug('*** trying to bring Switch %s Port %s DOWN' % (n1, p1))
            (n2, p2) = get_remote_links(self.topo, n1, p1)
            # remove edge only if it exists, duh!
            # if edge does not exists, n2 is going to be to None
            if n1 and n2:
                delete_edge(self.topo, n1, n2)
                log.info('PORT STATUS: Link between switch %s and %s is down. Link removed from topo' % (n1, n2))
        # XXX code to handle when port comes up?


    def _handle_PacketIn(self, event):
        """rocess incoming packets."""
        # scapy-fy packet
        pkt = Ether(event.data)

        # if pkt is LLDP then use it to manage topology view 
        if pkt.type == 0x88cc: 
            self.manage_topology(pkt, event.dpid, event.port)

        # if arp discover host
        if pkt.type == 0x0806:
            self.manage_hosts(pkt, event.dpid, event.port)


    def link_collector(self):
        """
        Checks for link "freshness" and if expired, then deletes it fron the topology
        """
        now = time.time()
        for n1, n2, d in self.topo.edges(data = True):
            # if link older than 3*lldp_ttl, then remove it
            if d['timestamp'] < (now - 3 * self.lldp_ttl):
                # from both nodes remove port info
                delete_edge(self.topo, n1, n2)


    def manage_topology(self, pkt, l_dpid, l_port):
        """
        Creates/Updates the topology acording to what it "hears" from LLDP
        """
        # is it a well formed LLDP packet?
        if pkt.type == 0x88cc and \
            LLDPChassisId in pkt and \
            LLDPPortId in pkt and \
            LLDPTTL in pkt and \
            LLDPDUEnd in pkt:
               # comodity/documentation variables
               r_dpid = int(pkt['LLDPChassisId'].value)
               r_port = int(pkt['LLDPPortId'].value)
               #log.debug('Got LLDP packet [Switch: %s Port %s] from switch %s port %s' \

               # 1) if "seen" nodes are new, add them to the topology view
               if not r_dpid in self.topo.nodes():
                   self.topo.add_node(r_dpid, {'link_to':[]})
               if not l_dpid in self.topo.nodes():
                   self.topo.add_node(l_dpid, {'link_to':[]})
               # 2) is edge new? is so, add it and timestampt it
               if not ((l_dpid, r_dpid) in self.topo.edges() or (r_dpid,l_dpid) in self.topo.edges()):
                   self.topo.add_edge(l_dpid, r_dpid, {'timestamp':time.time()})
               # it not new, refresh timestamp
               else:
                   self.topo.edge[l_dpid][r_dpid]['timestamp'] = time.time()
               # 3) keep track of ports usage in l_dpid...l_port in l_dpid links to r_dpid 
               if l_dpid in self.topo.nodes():
                   if (l_port, r_dpid) not in self.topo.node[l_dpid]['link_to']:
                       self.topo.node[l_dpid]['link_to'].append((l_port,r_dpid))


    def manage_hosts(self, pkt, dpid, port):
        """
        Manages the global mac-address-table
        """
        # XXX one mac/ip per port?
        if pkt.type == 0x0806 and ARP in pkt and pkt[ARP].op in [1,2]:
            if not(dict(dpid = dpid, port = port, mac = pkt.hwsrc, ip = pkt.psrc) in self.gmat):
                self.gmat.append(dict(dpid = dpid, port = port, mac = pkt.hwsrc, ip = pkt.psrc))
                log.debug('New host: %s at %s' % (pkt.psrc, pkt.hwsrc))

    def send_LLDP(self, event):
        """
        Creates a LLDP packet and sends it to all dpid's ports.
        This packet is sent to all of dpid's ports every 
        self.lldp_ttl seconds
        """
        # note-to-self: event.ofp is of ofp_features_reply type
        # note-to-self: event.ofp.ports has all the port inventory in this dpid
        # LLDP destination address
        dst = '01:80:c2:00:00:0e'
        # LLDP ethertype
        type = 0x88cc
        # note-to-self: ofp.ports == port inventory for dpid
        for p in event.ofp.ports:
            if p.port_no < of.OFPP_MAX:
                chassis_id = event.dpid
                src = str(p.hw_addr)
                port = p.port_no
                lldp_p = Ether(src = src, dst = dst, type = type)/\
                        LLDPChassisId(subtype = 7, macaddr = '00:00:ca:fe:ba:be', value = chassis_id)/\
                        LLDPPortId(subtype = 7, macaddr = src, value = port)/\
                        LLDPTTL(seconds = self.lldp_ttl)/\
                        LLDPDUEnd()
                # send LLDP packet
                pkt = of.ofp_packet_out(action = of.ofp_action_output(port = port))
                pkt.data = bytes(lldp_p)
                event.connection.send(pkt)


    def graph(self, tree=False):
        """
        Draws the current view of the topology. No hosts, just switches
        """
        plt.ion()
        if tree:
            pos = nx.graphviz_layout(self.topo, prog='dot')
            offset = 10
        else:
            pos = nx.circular_layout(self.topo)
            offset = 0.05
        nx.draw(self.topo, pos)
        node_labels = dict([(n,d['link_to']) for n,d in self.topo.nodes(data=True)])

        
        pos_labels = {}
        keys = pos.keys()
        for key in keys:
            x,y = pos[key]
            pos_labels[key] = (x, y + offset)

        nx.draw_networkx_labels(self.topo, pos=pos_labels, labels=node_labels, font_size=8)
        plt.show()

def launch():
    core.register('discovery', Discovery())
    log.info('Discovery registered')
