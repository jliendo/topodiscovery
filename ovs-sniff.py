import os
import sys
import re
import datetime
import argparse
import subprocess
import multiprocessing
import threading
import Queue
from sets import Set
from pcapy import *
from scapy.all import *

class OVSSniff():

    def __init__(self, br_name, filter):
        # create dummy interfaces
        index = re.search('\d+$', br_name).group()
        dummy_name = "dummy%s" % index
        try:
            subprocess.check_call(['ip','link','set','up', dummy_name])
        except:
            print "error: could not create dummy interface %s" % dummy_name
            return None
        # create mirrors
        mirror_name = "mirror%s" % index
        try:
            subprocess.check_call(['ovs-vsctl','--','--may-exist','add-port', br_name, dummy_name])
            subprocess.check_call(['ovs-vsctl','--','--id=@p','get','port', dummy_name,\
                                               '--','--id=@m','create','mirror','name=%s' % mirror_name,\
                                               '--','add','bridge', br_name,'mirrors','@m',\
                                               '--','set','mirror', mirror_name,'output_port=@p'])
            subprocess.check_call(['ovs-vsctl','set','mirror', mirror_name, 'select_all=1'])
        except:
            print "error: could not create mirror for switch %s" % br_name
            return None
        # sniffing object's state
        self.br_name = br_name
        self.dummy = dummy_name
        self.mirror = mirror_name
        self.reader = open_live(dummy_name, 255, 1, 100)
        self.reader.setfilter(filter)

    def _sniffing_callback(self, hdr, data):
        self.packet_header = hdr
        self.packet = data

    def get_packet(self):
        if not self.reader.dispatch(1, self._sniffing_callback):
            return None, None, None, None
        return datetime.datetime.now(), self.br_name, self.packet_header, self.packet


def do_sniffing(br_name, filter, running, q):
    # create sniffing object from OVS switch
    s = OVSSniff(br_name, filter)
    if not s: 
        print "could not create sniffing object for switch %s" % br_name
        return
    while running.is_set():
        (time, b, hdr, data) = s.get_packet()
        pkt = Ether(data)
        if IP in pkt:
            print "%s @ %s %s -> %s (%s)" % (time, b, pkt[IP].src, pkt[IP].dst, pkt[ICMP].seq)
            q.put(b)



def get_bridges():
    # XXX use absolute path
    return subprocess.check_output(['ovs-vsctl', 'list-br']).split()

def list_bridges():
    for i in get_bridges():
        print i


def main():
    # running as root?
    if not os.getuid() == 0:
        sys.exit("not running as root. exiting...")

    # process command-line
    parser = argparse.ArgumentParser()
    parser.add_argument('-b','--bridge', dest = 'bridges', nargs = '+', default = 'all', \
                         help = 'OVS Switch to sniff to. Defaults to "all" OVS switches running.')
    parser.add_argument('-f','--filter', dest = 'filter', default = 'ip', \
                         help = 'pcap style filter. Defaults to "ip".')
    parser.add_argument('--list-br', dest = 'list_bridges', action = 'store_true', \
                         help = 'Get a list of OVS switches running.')
    args = parser.parse_args()

    # print list of running OVS bridges and exit
    if args.list_bridges:
        list_bridges()
        sys.exit()

    # if sniffing on all bridges, create python list
    if 'all' in args.bridges:
        print "running sniffer on all bridges..."
        args.bridges = get_bridges()
    else:
        # validate list of bridges given by the user
        l = get_bridges()
        for i in args.bridges:
            if not i in l:
                print "switch %s not a valid OVS switch or switch not running. exiting..." % i
                sys.exit()

    # dummy loaded?
    if 'dummy' in subprocess.check_output('lsmod'):
        print "found dummy/unknow number of dummies. unloading it..."
        subprocess.call(['rmmod','dummy'])

    # find largest referenced switch
    max = 0
    for i in args.bridges:
        c = re.search('\d+$', i).group()
        if int(c) >= max:
            max = int(c)
    numdummies = max+1
    try:
        subprocess.check_call(['/sbin/modprobe', 'dummy','numdummies=%s' % numdummies])
    except:
        print "could not load dummy. exiting..."
        sys.exit()
    print "dummy module loaded. numdummies=%s" % numdummies

    # at this point we have a valid list of OVS swicthes

    # pre-emptive cleaning of mirrors
    print "cleaning previous mirrors..."
    for b in args.bridges:
        subprocess.call(['ovs-vsctl','clear','Bridge', b,'mirrors'])

    print "about to create sniffers for ", args.bridges
    jobs = []
    q = Queue.Queue()
    running = threading.Event()
    running.set()
    for b in args.bridges:
        p = threading.Thread(target = do_sniffing, args = (b, args.filter, running, q))
        jobs.append(p)
        p.start()
    try:
        while True:
            pass
    except:
        print "switch SET for the flow %s" % args.filter
        trace = Set()
        while not q.empty():
            trace.add(q.get())
        print trace
        print "cleaning mirrors..."
        for b in args.bridges:
            subprocess.call(['ovs-vsctl','clear','Bridge', b,'mirrors'])
        print "trying to shutdown sniffers...."
        running.clear()
        for j in jobs:
            j.join()
        print "sniffers are shutdown...."

if __name__ == "__main__":
    main()

