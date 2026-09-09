#!/usr/bin/env python3
import os
import argparse
from time import sleep
from mininet.net import Containernet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from customs import orchestrate


def create_nodes(net):
    nodes_dict = {}

    info('*** Adding Network Nodes (Switches and Docker Containers)\n')
    
    nodes_dict['s1'] = net.addDocker('s1', dimage='inetrm-bmv2', ip="10.0.0.253", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['h1'] = net.addDocker('h1', dimage='inetrm-client', ip='10.0.0.1', mac="00:00:00:00:00:01", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['h2'] = net.addDocker('h2', dimage='inetrm-client', ip='10.0.0.2', mac="00:00:00:00:00:02", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['h3'] = net.addDocker('h3', dimage='inetrm-client', ip='10.0.0.3', mac="00:00:00:00:00:03", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['h4'] = net.addDocker('h4', dimage='inetrm-client', ip='10.0.0.4', mac="00:00:00:00:00:04", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['srv'] = net.addDocker('srv', dimage='inetrm-server', ip='10.0.0.254', mac="00:00:00:00:02:54", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['a1'] = net.addDocker('a1', dimage='inetrm-attacker', ip='10.0.0.11', mac="00:00:00:00:00:11", network_mode='none', volumes=["/tmp:/tmp"])
    nodes_dict['a2'] = net.addDocker('a2', dimage='inetrm-attacker', ip='10.0.0.12', mac="00:00:00:00:00:12", network_mode='none', volumes=["/tmp:/tmp"])

    return nodes_dict

def create_links(net, nodes_dict):
    info('*** Linking topology\n')
    net.addLink(nodes_dict['s1'], nodes_dict['h1'], addr1="00:00:01:00:00:01")
    net.addLink(nodes_dict['s1'], nodes_dict['h2'], addr1="00:00:01:00:00:02")
    net.addLink(nodes_dict['s1'], nodes_dict['h3'], addr1="00:00:01:00:00:03")
    net.addLink(nodes_dict['s1'], nodes_dict['h4'], addr1="00:00:01:00:00:04")
    net.addLink(nodes_dict['s1'], nodes_dict['srv'], addr1="00:00:01:00:02:54")
    net.addLink(nodes_dict['s1'], nodes_dict['a1'], addr1="00:00:01:00:00:11")
    net.addLink(nodes_dict['s1'], nodes_dict['a2'], addr1="00:00:01:00:00:12")

def post_init(nodes_dict):
    info('*** Compiling P4, starting simple_switch in BMv2 nodes and orchestrating via custom scripts\n')
    
    bmv2_node = nodes_dict['s1']
    
    p4_source = "/tmp/compile/decision_tree.p4"
    json_output = "decision_tree.json"
    
    info('--> Compiling P4 for s1...\n')
    bmv2_node.cmd(f'p4c --target bmv2 --arch v1model {p4_source}')
    
    interfaces = [intf for intf in bmv2_node.intfNames() if intf != 'lo']
    
    if_args = " ".join([f"-i {idx}@{intf}" for idx, intf in enumerate(interfaces)])
    
    info('--> Starting simple_switch for s1...\n')
    bmv2_node.cmd(f'simple_switch {if_args} {json_output} &')
    

    orchestrate(nodes_dict, duration)
    return

def parse_arguments():
    parser = argparse.ArgumentParser(description="Containernet Topology")
    parser.add_argument('-t', '--time', type=int, default=60, help="Duration of monitoring")
    return parser.parse_args()

def main():
    args = parse_arguments()
    global duration 
    duration = args.time

    net = Containernet(controller=Controller)

    info('*** Adding Controller\n')
    net.addController('c0')

    nodes_dict = create_nodes(net)
    
    create_links(net, nodes_dict)

    info('*** Starting the network\n')
    net.start()    

    post_init(nodes_dict)

    info('*** Starting Mininet CLI\n')
    CLI(net)
    sleep(duration)

    info('*** Stopping the network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
