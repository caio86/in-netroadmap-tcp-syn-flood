from time import sleep


def orchestrate(nodes_dict, duration):
    """ 
    Insert custom orchestration here.
    Nodes are called via nodes_dict['node_name']. Use the .cmd method to call bash commands.
    e.g.: nodes_dict['h1'].cmd(f"bash -c 'scripts/custom-script.sh {duration}'")
    """
    h1, h2, h3 = nodes_dict['h1'], nodes_dict['h2'], nodes_dict['h3']

    h1.cmd("ethtool -K h1-eth0 tx off rx off")
    h2.cmd("ethtool -K h2-eth0 tx off rx off")
    h3.cmd("ethtool -K h3-eth0 tx off rx off")

    h2.cmd("tc qdisc add dev h2-eth0 root tbf rate 1mbit burst 32kbit latency 30ms 2> /tmp/tc.err")

    h2.cmd("nginx -g 'daemon off;' &")
    h2.cmd("tcpdump -i h2-eth0 -s0 -w /tmp/dump-$(date +'%Y%m%d_%H%M%S').pcap 2>/tmp/dump.err >/tmp/dump.log &")

    # h2.cmd(f"/scripts/m-system.sh {duration} 2>/tmp/m-system.err >/tmp/m-system.log &")
    h1.cmd(f"/scripts/consume.sh {duration} 10.0.0.2 2>/tmp/consume.err >/tmp/consume.log &")

    sleep(duration*0.2)

    h3.cmd(f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.2 --iface h3-eth0 --ipi 0 2>/tmp/attacker.err >/tmp/attacker.log")

    return
