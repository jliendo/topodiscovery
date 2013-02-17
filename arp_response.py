from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from scapy.all import *

"""
We want to ARP response all ARP requests with our own IP/mac.  The idea is to
test an algorithm in which there is no need to broadcast ARP requests through
the network to locate dpid/port of an IP address

ARP is an IP location services (dpid/port). All that there is to ARP is to
provide the host with a valid mac-address to where to send the IP packet. The
idea is to have the controller be this L2 "default-gateway" and let other
controller componentes (i.e. routing) to sort out where to send the host's IP
packets. As soon as the controller figures out where in the network is the IP
address located, then it does install flows to have bi-directional data-flowing.
Only then the controller gets out of the way of the flowing of data between
host-1 and host-2.
"""

log = core.getLogger()

class ArpResponse( EventMixin ):

    def __init__(self):
        # listen to all events from core
        core.openflow.addListeners(self)
        # mac address of the controller
        # XXX how do we assign a MAC to the controller?
        self.controller_mac = '00:00:ca:fe:ba:be'
        # XXX do we have to preemptively install a flow so all ARP packets are sent to
        # the controller???

    def _handle_PacketIn(self, event):
        pkt = Ether(event.data)
        # if not an ARP packet then nothing to see, move along...
        if not pkt[Ether].type == 0x0806:
            return
        # type is ARP, but do we really have an ARP packet?
        if not ARP in pkt:
            return
        # is it an ARP request?
        if pkt[ARP].op == 1:
            log.debug('ARP_RESPONSE: got ARP Request packet')
            # XXX Have to check if the src hwaddr and paddr are already in the
            # gmat, if not, then add it?
            src = self.controller_mac
            dst = pkt[Ether].src
            type = pkt[Ether].type
            # we are proxy'ing for the pdst
            hwsrc = self.controller_mac
            psrc = pkt[ARP].pdst
            hwdst = pkt[ARP].hwsrc
            pdst =pkt[ARP].psrc
            # arp-reply
            op = 2
            arp_reply = Ether(src=src, dst=dst, type=type)/\
                        ARP(hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst, op=op)
            # create openflow message
            msg = of.ofp_packet_out()
            # send the arp reply from the same port the request was received
            msg.actions.append(of.ofp_action_output(port = event.port))
            msg.data = bytes(arp_reply)
            event.connection.send(msg)
        if pkt[ARP].op == 2:
            # XXX got arp-response packet, refresh gmat?
            log.debug('ARP_RESPONSE: got ARP Reply packet')


def launch():
    component = ArpResponse()
    core.register('arp_response', component)
    log.debug("ARP_RESPONSE: arp_response component registered")
