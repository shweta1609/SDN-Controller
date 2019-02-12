#!/usr/bin/python

#Copyright (c) 2016 Enrique Saurez

#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from mininet.cli import CLI
from mininet.log import setLogLevel, info, warn
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
import time
import json
import ast
from collections import defaultdict


def get_link_config():
    # configure link parameters
    default_link_opts = dict(bw=100, delay="2ms")
    link_config = defaultdict(lambda: defaultdict(lambda: dict(default_link_opts)))
    with open("/home/ubuntu/mininet/examples/link_config") as f:
        for line in f:
            try:
                config = ast.literal_eval(line)
                print "config:", config
            except:
                continue
            link_config[config["input_port"]][config["output_port"]] = dict(bw=config["bandwidth"], delay=config["latency"])

    return link_config

host_link_config = dict(bw=100, delay="2ms")
link_config = get_link_config()


class customTopo(Topo):
    """create topology with numCore core switches
    numEdge edge switches, hostsPerEdge, bw bandwidth, delay"""

    def __init__(self):
        "Create custom loop topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')

        # add host to switch links
        self.addLink(s1, h1, 1, **host_link_config)
        self.addLink(s2, h2, 1, **host_link_config)
        self.addLink(s3, h3, 1, **host_link_config)
        self.addLink(s4, h4, 1, **host_link_config)
        self.addLink(s5, h5, 1, **host_link_config)
        self.addLink(s6, h6, 1, **host_link_config)
        self.addLink(s7, h7, 1, **host_link_config)

        # add switch to switch links
        self.addLink(s1, s2, 2, 2, **link_config[2][2])
        self.addLink(s2, s3, 3, 2, **link_config[3][2])
        # self.addLink(s3, s4, 3, 4, **link_config[3][4])
        self.addLink(s4, s5, 3, 2, **link_config[3][2])
        self.addLink(s6, s5, 2, 4, **link_config[2][4])
        self.addLink(s1, s6, 3, 3, **link_config[3][3])
        self.addLink(s1, s7, 4, 2, **link_config[4][2])
        self.addLink(s5, s7, 3, 3, **link_config[3][3])
        self.addLink(s6, s7, 4, 4, **link_config[4][4])
        self.addLink(s3, s8, 3, 1, **link_config[3][1])
        self.addLink(s8, s4, 2, 4, **link_config[2][4])        

      

def test():
    topo = customTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    

    print "start RYU controller"
    raw_input()

    net.addController('rmController', controller=RemoteController,
                      ip='127.0.0.1', port=6633)
    net.start()
    #time.sleep(40)

    # print "Testing network connectivity"
    # net.pingAll()
    # #dumpNodeConnections(net.hosts)
    # print "Testing bandwidth between h1 and h4"
    # h1, h4 = net.get('h1', 'h4')
    # net.iperf((h1, h4))
    CLI(net)
    net.stop()
    

if __name__ == '__main__':
    setLogLevel('info')
    test()

topos = {'customTopo':(lambda:customTopo()) }
