import re
import sys
import subprocess
import os

from sys import exit  # pylint: disable=redefined-builtin

from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.topo import MinimalTopo, Topo
from mininet.util import quietRun
from mininet.node import Node


def checkIntf( intf ):
    "Make sure intf exists and is not configured."
    config = quietRun( 'ifconfig %s 2>/dev/null' % intf, shell=True )
    if not config:
        error( 'Error:', intf, 'does not exist!\n' )
        exit( 1 )
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', config )
    if ips:
        error( 'Error:', intf, 'has an IP address,'
               'and is probably in use!\n' )
        exit( 1 )

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
        # self.cmd('sysctl net.ipv4.conf.all.proxy_arp=1')  # this doesnt work

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        # self.cmd('sysctl net.ipv4.conf.all.proxy_arp=0')  # this doesnt work
        super(LinuxRouter, self).terminate()


setLogLevel( 'info' )

subprocess.run(['sudo', 'ip', '-all', 'netns', 'delete'])

info( '*** Creating network\n' )
net = Mininet( topo=Topo(), waitConnected=True)

r1 = net.addHost('r1', cls=LinuxRouter)
r1.cmd("sysctl net.ipv4.conf.all.proxy_arp=1")

# host1 = net.hosts[0]
# host2 = net.hosts[1]

host1 = net.addHost('h1', defaultRoute='via 192.168.1.1')
host2 = net.addHost('h2', defaultRoute='via 192.168.2.1')

net.addLink('h1', 'r1', intfName2='r1-eth0', params2={ 'ip' : '192.168.1.1/24' })
net.addLink('h2', 'r1', intfName2='r1-eth1', params2={ 'ip' : '192.168.2.1/24' })

# net.staticArp()

host1.setIP(intf='h1-eth0', ip='192.168.1.2')
host2.setIP(intf='h2-eth0', ip='192.168.2.2')

# r1.setIP(intf='r1-eth0', ip='192.168.1.1')
# r1.setIP(intf='r1-eth1', ip='192.168.2.1')
# r1.setIP(intf='r1-eth1', ip='10.0.0.3')

# # create tap interfaces
# subprocess.run(['bash', '-c', 'sudo tunctl -t tapa -u $SAVED_USER -g $SAVED_GROUP && sudo ip link set dev tapa up'])

subprocess.run(['bash', '-c', 'ip link add veth1 type veth peer name veth2 && ip addr add 10.0.3.1 dev veth1 && ip link set veth1 up'])

# info( '*** Checking', 'tapa', '\n' )
# checkIntf( 'tapa' )

info( '*** Adding hardware interface', 'veth2', 'to host',
      r1.name, '\n' )
_intf = Intf( 'veth2', node=r1, ip='192.168.3.1/24' )

# info( '*** Note: you may need to reconfigure the interfaces for '
#       'the Mininet hosts:\n', net.hosts, '\n' )

# pid1 = net.hosts[0].pid
# pid2 = net.hosts[1].pid
# pid = r1.pid
# cmd = f"sudo ip netns attach r1 {pid}"
# print("cmd", cmd)
# subprocess.run(['bash', '-c', str(cmd)])

# cmd1 = """sudo ip netns attach host1 """ + str(pid1)
# cmd2 = """sudo ip netns attach host2 """ + str(pid2)

# subprocess.run(['bash', '-c', str(cmd1)])
# subprocess.run(['bash', '-c', str(cmd2)])

net.start()

# uncomment to run wireshark on host
# host1.cmd("wireshark -i tapa -k &")
#host2.cmd("wireshark -i tapb -k &")

# r2.cmd("ip route del 10.0.0.0/24")
# r2.cmd("ip route del 10.0.0.0/24")
# r2.cmd("ip route del 10.0.0.0/30")
# r2.cmd("ip route del 10.0.0.0/8")
# r2.cmd("ip route del 10.0.1.0/28")
# r2.cmd("ip route del 10.0.1.0/28")
# r2.cmd("ip route add 10.0.0.6 dev tapb")
# r2.cmd("ip route add 10.0.0.2 dev tapa")
# r2.cmd("ip route add 10.0.1.0/24 dev r2-eth0")

# r2.cmd("ip route add 10.0.1.1 dev tapb")
# r2.cmd("ip route add 10.0.1.2 dev tapa")
# r2.cmd("ip route add 10.0.0.0/24 dev r2-eth0")

# r1.cmd("ip route del 192.0.0.0/8")
# r1.cmd("ip route del 192.0.0.0/8")
# r1.cmd("ip route del 192.168.3.0/24")

# r1.cmd("ip route add 192.168.1.0/24 via 192.168.1.1 dev r1-eth0")
# r1.cmd("ip route add 192.168.2.0/24 via 192.168.2.1 dev r1-eth1")
# r1.cmd("ip route add default dev tapa")
# r1.cmd("ip route add 10.0.1.0/24 dev tapa")
# # r1.cmd("ip route add 10.0.0.0/24 dev r1-eth0")
# r1.cmd("ip route add 10.0.0.6 dev r1-eth1")
# r1.cmd("ip route add 10.0.0.5 dev r1-eth0")
# r1.cmd("ip route add 10.0.1.0 dev r1-eth0")
# r1.cmd("ip route add 10.0.0.0 dev r1-eth0 metric 100")

r1.cmd("ip route add default via 192.168.3.1 dev veth2")
host1.cmd("ip route add default dev h1-eth0")
host2.cmd("ip route add default dev h2-eth0")

user = os.getenv('SAVED_USER')
group = os.getenv('SAVED_GROUP')
saved_path = os.getenv('SAVED_PATH')
saved_env = os.environ.copy()
saved_env["PATH"] = saved_path

# start inet
subprocess.run(['inet -f omnetpp.ini -c General &'], user=user, group=group, env=saved_env, shell=True)

# host1.cmd("ip route add 192.168.3.20 dev tapa")
# host2.cmd("ip route add 192.168.2.20 dev tapb")

# host1.cmd("xterm -e iperf -s &")
# host2.cmd("xterm -e iperf -c 192.168.2.20 &")

CLI( net )

subprocess.run(['sudo', 'ip', '-all', 'netns', 'delete'])

net.stop()
