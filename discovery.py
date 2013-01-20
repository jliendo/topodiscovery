from pox.core import core
from pox.lib.revent import *
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import networkx as nx
import matplotlib.pyplot as plt
import time
from scapy.all import *

log = core.getLogger()

class Discovery( EventMixin ):

    def __init__(self):
        # networkx representation of the topology
        self.topo = nx.Graph()
        # list of switches already scheduled w/sendLLDP
        self.scheduled_switches = []
        # send lldp every ldp ttl seconds
        self.lldp_ttl = 1
        core.openflow.addListeners(self)


    def _handle_ConnectionUp(self, event):
        # install flow for all LLDP packets forward to controller
        msg = of.ofp_flow_mod()
        # LLDP Ether type
        msg.match.dl_type = 0x88cc
        # LLDP dest addr '01:80:c2:00:00:0e'
        msg.match.dl_dst = '\x01\x80\xc2\x00\x00\x0e'
        # LLDPs to controller
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.debug('LLDP flow configuration sent. Switch: %s' % event.dpid)
        # if dpid no scheduled, then do it!
        if not event.dpid in self.scheduled_switches:
            Timer(self.lldp_ttl, self.send_LLDP, args = [event], recurring = True)
            self.scheduled_switches.append(event.dpid)


    def _handle_ConnectionDown(self, event):
        #XXX delete switch from list of scheduled switch
        log.debug("Switch %s is DOWN" % event.dpid)


    def _handle_PortStatus(self, event):
        #XXX what to do in case of ports going down/up
        pass


    def _handle_PacketIn(self, event):
        """rocess incoming packets."""
        # scapy-fy packet
        pkt = Ether(event.data)

        # if pkt is LLDP then use it to manage topology view 
        if pkt.type == 0x88cc: 
            self.manage_topology(pkt, event.dpid, event.port)
        

    def manage_topology(self, pkt, l_dpid, l_port):
        """Creates/Updates the topology acording to what it "hears" from LLDP"""
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

               # 2) is edge new?
               if not ((l_dpid, r_dpid) in self.topo.edges() or (r_dpid,l_dpid) in self.topo.edges()):
                   self.topo.add_edge(l_dpid, r_dpid)

               # 3) keep track of ports usage in l_dpid...l_port in l_dpid links to r_dpid 
               if l_dpid in self.topo.nodes():
                   if (l_port, r_dpid) not in self.topo.node[l_dpid]['link_to']:
                       self.topo.node[l_dpid]['link_to'].append((l_port,r_dpid))



    def send_LLDP(self, event):
        """creates a LLDP packet and sends it through all dpid's ports.
        This packet is sent through all of dpid's ports every 
        self.lldp_ttl seconds"""
        # note-to-self: event.ofp is of ofp_features_reply type
        # note-to-self: event.ofp.ports has all the ports defined in this dpid
        # LLDP destination address
        dst = '01:80:c2:00:00:0e'
        # LLDP ethertype
        type = 0x88cc
        # note-to-self: ofp.ports == all ports in the dpid
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
                #log.debug("dpid: %d port_no: %s hw_addr: %s" % (event.dpid, p.port_no, p.hw_addr))
                # send LLDP packet
                pkt = of.ofp_packet_out(action = of.ofp_action_output(port = port))
                pkt.data = bytes(lldp_p)
                event.connection.send(pkt)

    def graph(self):
        """
        Draws the current view of the topology. No hosts, just switches
        """
        pos = nx.circular_layout(self.topo)
        nx.draw(self.topo, pos)
        node_labels = dict([(n,d['link_to']) for n,d in self.topo.nodes(data=True)])

        
        offset = 0.05
        pos_labels = {}
        keys = pos.keys()
        for key in keys:
            x,y = pos[key]
            pos_labels[key] = (x, y + offset)

        nx.draw_networkx_labels(self.topo, pos=pos_labels, labels=node_labels, font_size=8)
        plt.show()


def launch():
    core.register('discovery', Discovery())
    log.debug('Discovery registered')
