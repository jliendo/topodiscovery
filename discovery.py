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
        # XXX what should be the link_collector interval???
        Timer(self.lldp_ttl * 3, self.link_collector, recurring = True)
        log.debug('Link collector started')


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
        # is port config down or port link down?
        if event.ofp.desc.config == 1 or event.ofp.desc.config == 1:
            n1 = event.dpid
            p1 = event.port
            n2 = None
            # find node linking to n1 via p1
            for i in self.topo.node[n1]['link_to']:
                p, n = i
                if p1 == p:
                    n2 = n
            if n1 and n2:
                self.delete_linking_ports(n1, n2)
                log.debug('PORT STATUS: Link between switch %s and %s is down. Link removed from topo' % (n1, n2))


    def _handle_PacketIn(self, event):
        """rocess incoming packets."""
        # scapy-fy packet
        pkt = Ether(event.data)

        # if pkt is LLDP then use it to manage topology view 
        if pkt.type == 0x88cc: 
            self.manage_topology(pkt, event.dpid, event.port)


    def find_linking_ports(self, n1, n2):
        """
        returns the port numbers that links node1 and node2 in edge.
        edge is a tuple, it may have attributes
        """
        p1, p2 = (None, None)
        # XXX There has to be a better way to find the linking ports...
        # works on node1
        for i in self.topo.node[n1]['link_to']:
            p, n = i
            if n == n2: 
                p1 = p
                break
        # works on node2
        for i in self.topo.node[n2]['link_to']:
            p, n = i
            if n == n1: 
                p2 = p
                break
        # found ports
        return (p1,p2)

    def delete_linking_ports(self, n1, n2):
        """
        deletes the information between two nodes and removes edge from topo
        """
        # search for the ports that links n1 and n2
        p1, p2 = self.find_linking_ports(n1, n2)

        if not (p1 and p2):
            log.debug('ERROR: Could not find ports linking switch %s and %s. Could not delete' % (n1, n2))
            return

        # update n1's list of "links_to"
        for i in self.topo.node[n1]['link_to']:
            p, n = i
            if n == n2 and p == p1:
                if i in self.topo.node[n1]['link_to']:
                    self.topo.node[n1]['link_to'].remove(i)
                    log.debug('Link in Switch %s Port %s expired. Removed from topo' % (n1,p1))
                break
        # update n2's list of "links_to"
        for i in self.topo.node[n2]['link_to']:
            p, n = i
            if n == n1 and p == p2:
                if i in self.topo.node[n2]['link_to']:
                    self.topo.node[n2]['link_to'].remove(i)
                    log.debug('Link in Switch %s Port %s expired. Removed from topo' % (n2,p2))
                break
        # remove edge from topo
        self.topo.remove_edge(n1,n2)


    def link_collector(self):
        """
        Checks for link "freshness" and if expired, then deletes it fron the topology
        """
        now = time.time()
        for n1,n2,d in self.topo.edges(data=True):
            # if link older than 3*lldp_ttl, then remove it
            if d['timestamp'] < (now - 3 * self.lldp_ttl):
                # from both nodes remove port info
                self.delete_linking_ports(n1, n2)
                log.debug('COLLECTOR: Edge between switch %s and %s expired. Removed from topo' % (n1,n2))
        

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

    def graph(self, tree):
        """
        Draws the current view of the topology. No hosts, just switches
        """
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
    plt.ion()
    core.register('discovery', Discovery())
    log.debug('Discovery registered')
