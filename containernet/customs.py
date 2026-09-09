from time import sleep,time


def orchestrate(nodes_dict, duration):
    """ 
    Insert custom orchestration here.
    Nodes are called via nodes_dict['node_name']. Use the .cmd method to call bash commands.
    e.g.: nodes_dict['h1'].cmd(f"bash -c 'scripts/custom-script.sh {duration}'")
    """
    h1, h2, h3, h4 = nodes_dict['h1'], nodes_dict['h2'], nodes_dict['h3'], nodes_dict['h4']
    srv = nodes_dict['srv']
    a1, a2 = nodes_dict['a1'], nodes_dict['a2']

    # ARP
    h1.cmd("arp -s 10.0.0.254 00:00:01:00:00:01")
    h2.cmd("arp -s 10.0.0.254 00:00:01:00:00:02")
    h3.cmd("arp -s 10.0.0.254 00:00:01:00:00:03")
    h4.cmd("arp -s 10.0.0.254 00:00:01:00:00:04")
    a1.cmd("arp -s 10.0.0.254 00:00:01:00:00:11")
    a2.cmd("arp -s 10.0.0.254 00:00:01:00:00:12")

    srv.cmd("arp -s 10.0.0.1 00:00:01:00:02:54")
    srv.cmd("arp -s 10.0.0.2 00:00:01:00:02:54")
    srv.cmd("arp -s 10.0.0.3 00:00:01:00:02:54")
    srv.cmd("arp -s 10.0.0.4 00:00:01:00:02:54")
    srv.cmd("arp -s 10.0.0.11 00:00:01:00:02:54")
    srv.cmd("arp -s 10.0.0.12 00:00:01:00:02:54")

    # For using with BMv2
    s1 = nodes_dict['s1']
    s1.cmd("ip link set s1-eth0 up")
    s1.cmd("ip link set s1-eth1 up")
    s1.cmd("ip link set s1-eth2 up")
    s1.cmd("ip link set s1-eth3 up")
    s1.cmd("ip link set s1-eth4 up")
    s1.cmd("ip link set s1-eth5 up")
    s1.cmd("ip link set s1-eth6 up")
    s1.cmd("cat /tmp/compile/ipv4lpm.txt | simple_switch_CLI >/tmp/cli.out 2>&1")
    s1.cmd('echo -e "\n\nSPACING\n\n" >> /tmp/cli.out')
    s1.cmd("cat /tmp/compile/table.txt | simple_switch_CLI >> /tmp/cli.out 2>&1")

    h1.cmd("ethtool -K h1-eth0 tx off rx off")
    h2.cmd("ethtool -K h2-eth0 tx off rx off")
    h3.cmd("ethtool -K h3-eth0 tx off rx off")
    h4.cmd("ethtool -K h4-eth0 tx off rx off")

    srv.cmd("ethtool -K srv-eth0 tx off rx off")

    a1.cmd("ethtool -K a1-eth0 tx off rx off")
    a2.cmd("ethtool -K a2-eth0 tx off rx off")


    srv.cmd("tc qdisc add dev srv-eth0 root tbf rate 1mbit burst 32kbit latency 30ms 2> /tmp/tc.err")

    srv.cmd("nginx -g 'daemon off;' &")
    #srv.cmd("tcpdump -i srv-eth0 -s0 -w /tmp/dump-$(date +'%Y%m%d_%H%M%S').pcap 2>/tmp/dump.err >/tmp/dump.log &")
    h1.cmd("tcpdump -i h1-eth0 -s0 -w /tmp/dump-h1.pcap 2>/tmp/dump.err >/tmp/dump.log &")
    h2.cmd("tcpdump -i h2-eth0 -s0 -w /tmp/dump-h2.pcap 2>/tmp/dump.err >/tmp/dump.log &")
    h3.cmd("tcpdump -i h3-eth0 -s0 -w /tmp/dump-h3.pcap 2>/tmp/dump.err >/tmp/dump.log &")
    h4.cmd("tcpdump -i h4-eth0 -s0 -w /tmp/dump-h4.pcap 2>/tmp/dump.err >/tmp/dump.log &")
    srv.cmd("tcpdump -i srv-eth0 -s0 -w /tmp/dump-srv.pcap 2>/tmp/dump.err >/tmp/dump.log &")
    a1.cmd("tcpdump -i a1-eth0 -s0 -w /tmp/dump-a1.pcap 2>/tmp/dump.err >/tmp/dump.log &")
    a2.cmd("tcpdump -i a2-eth0 -s0 -w /tmp/dump-a2.pcap 2>/tmp/dump.err >/tmp/dump.log &")

    ts = int(time())

    # srv.cmd(f"/scripts/m-system.sh {duration} 2>/tmp/m-system.err >/tmp/m-system.log &")
    h1.cmd(f"mkdir -p /tmp/web-{ts}")
    h1.cmd(f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>/tmp/consume.err >/tmp/consume.log &")
    h2.cmd(f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>/tmp/consume.err >/tmp/consume.log &")
    h3.cmd(f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>/tmp/consume.err >/tmp/consume.log &")
    h4.cmd(f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>/tmp/consume.err >/tmp/consume.log &")

    sleep(duration*0.2)

    a1.cmd(f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.254 --iface a1-eth0 --ipi 0 2>/tmp/attacker.err >/tmp/attacker.log &")
    a2.cmd(f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.254 --iface a2-eth0 --ipi 0 &")

    sleep(duration*0.8)

    h1.cmd(f"python3 /scripts/plot.py --logdir /tmp/web-{ts} --attacker-log /tmp/attacker.log --out /tmp/web-{ts}/results.png 2>/tmp/plot.err >/tmp/plot.log")

    s1.cmd('echo "counter_read MyIngress.resultCounter 0" | simple_switch_CLI > /tmp/class')
    s1.cmd('echo "counter_read MyIngress.resultCounter 1" | simple_switch_CLI >> /tmp/class')

    return
