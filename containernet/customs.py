from time import sleep, time


def start_bg(node, command, log_file, pid_file):
    node.cmd(f"{command} > {log_file} 2>&1 & echo $! > {pid_file}")


def stop_bg(node, pid_file, signal="TERM"):
    node.cmd(
        f"if [ -s {pid_file} ]; then "
        f"kill -{signal} $(cat {pid_file}) 2>/dev/null || true; "
        f"fi"
    )


def orchestrate(nodes_dict, duration):
    """
    Insert custom orchestration here.
    Nodes are called via nodes_dict['node_name']. Use the .cmd method to call bash commands.
    e.g.: nodes_dict['h1'].cmd(f"bash -c 'scripts/custom-script.sh {duration}'")
    """
    sleep(1)
    h1, h2, h3, h4 = (
        nodes_dict["h1"],
        nodes_dict["h2"],
        nodes_dict["h3"],
        nodes_dict["h4"],
    )
    srv = nodes_dict["srv"]
    a1, a2 = nodes_dict["a1"], nodes_dict["a2"]
    s1 = nodes_dict["s1"]

    ts = int(time())

    run_dir = f"/tmp/experiments/{ts}"
    web_dir = f"{run_dir}/web"

    s1.cmd(
        f"mkdir -p "
        f"{run_dir}/switch "
        f"{run_dir}/server "
        f"{run_dir}/clients/h1 "
        f"{run_dir}/clients/h2 "
        f"{run_dir}/clients/h3 "
        f"{run_dir}/clients/h4 "
        f"{run_dir}/attackers/a1 "
        f"{run_dir}/attackers/a2 "
        f"{run_dir}/reports "
        f"{web_dir}"
    )

    ###########
    ### ARP ###
    ###########

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

    ###########
    ### ARP ###
    ###########

    ############
    ### BMv2 ###
    ############

    s1.cmd("ip link set s1-eth0 up")
    s1.cmd("ip link set s1-eth1 up")
    s1.cmd("ip link set s1-eth2 up")
    s1.cmd("ip link set s1-eth3 up")
    s1.cmd("ip link set s1-eth4 up")
    s1.cmd("ip link set s1-eth5 up")
    s1.cmd("ip link set s1-eth6 up")

    s1.cmd(
        f"cat /tmp/compile/ipv4lpm.txt | simple_switch_CLI > {run_dir}/switch/cli.log 2>&1"
    )
    s1.cmd(f'echo -e "\n\nSPACING\n\n" >> {run_dir}/switch/cli.log')
    s1.cmd(
        f"cat /tmp/compile/table.txt | simple_switch_CLI >> {run_dir}/switch/cli.log 2>&1"
    )

    ############
    ### BMv2 ###
    ############

    ##################
    ### INTERFACES ###
    ##################

    s1.cmd("ethtool -K s1-eth0 tx off rx off")
    s1.cmd("ethtool -K s1-eth1 tx off rx off")
    s1.cmd("ethtool -K s1-eth2 tx off rx off")
    s1.cmd("ethtool -K s1-eth3 tx off rx off")
    s1.cmd("ethtool -K s1-eth4 tx off rx off")
    s1.cmd("ethtool -K s1-eth5 tx off rx off")
    s1.cmd("ethtool -K s1-eth6 tx off rx off")

    h1.cmd("ethtool -K h1-eth0 tx off rx off")
    h2.cmd("ethtool -K h2-eth0 tx off rx off")
    h3.cmd("ethtool -K h3-eth0 tx off rx off")
    h4.cmd("ethtool -K h4-eth0 tx off rx off")

    srv.cmd("ethtool -K srv-eth0 tx off rx off")

    a1.cmd("ethtool -K a1-eth0 tx off rx off")
    a2.cmd("ethtool -K a2-eth0 tx off rx off")

    srv.cmd(
        f"tc qdisc add dev srv-eth0 root tbf rate 100mbit burst 32kbit latency 30ms 2> {run_dir}/server/tc.err"
    )

    ##################
    ### INTERFACES ###
    ##################

    ########################
    ### EXPERIMENT START ###
    ########################

    start_bg(
        srv,
        f"python3 /scripts/receive.py -i srv-eth0 -o {run_dir}/server/int.csv",
        f"{run_dir}/server/receive.log",
        f"{run_dir}/server/receive.pid",
    )

    start_bg(
        h1,
        "python3 /scripts/send.py -i h1-eth0 10.0.0.254",
        f"{run_dir}/clients/h1/send.log",
        f"{run_dir}/clients/h1/send.pid",
    )

    start_bg(
        srv,
        "nginx -g 'daemon off;'",
        f"{run_dir}/server/nginx.log",
        f"{run_dir}/server/nginx.pid",
    )

    capture_nodes = [
        ("h1", h1, "h1-eth0"),
        ("h2", h2, "h2-eth0"),
        ("h3", h3, "h3-eth0"),
        ("h4", h4, "h4-eth0"),
        ("srv", srv, "srv-eth0"),
        ("a1", a1, "a1-eth0"),
        ("a2", a2, "a2-eth0"),
    ]

    for name, node, ifname in capture_nodes:
        if name == "srv":
            capture_dir = f"{run_dir}/server"
        elif name.startswith("h"):
            capture_dir = f"{run_dir}/clients/{name}"
        else:
            capture_dir = f"{run_dir}/attackers/{name}"

        start_bg(
            node,
            f"tcpdump -i {ifname} -s0 -w {capture_dir}/traffic.pcap",
            f"{capture_dir}/tcpdump.log",
            f"{capture_dir}/tcpdump.pid",
        )

    # h1.cmd("tcpdump -i h1-eth0 -s0 -w /tmp/dump-h1.pcap &> /tmp/dump.out &")
    # h2.cmd("tcpdump -i h2-eth0 -s0 -w /tmp/dump-h2.pcap &>> /tmp/dump.out &")
    # h3.cmd("tcpdump -i h3-eth0 -s0 -w /tmp/dump-h3.pcap &>> /tmp/dump.out &")
    # h4.cmd("tcpdump -i h4-eth0 -s0 -w /tmp/dump-h4.pcap &>> /tmp/dump.out &")
    # srv.cmd("tcpdump -i srv-eth0 -s0 -w /tmp/dump-srv.pcap &>> /tmp/dump.out &")
    # a1.cmd("tcpdump -i a1-eth0 -s0 -w /tmp/dump-a1.pcap &>> /tmp/dump.out &")
    # a2.cmd("tcpdump -i a2-eth0 -s0 -w /tmp/dump-a2.pcap &>> /tmp/dump.out &")

    # srv.cmd(f"/scripts/m-system.sh {duration} 2>/tmp/m-system.err >/tmp/m-system.log &")

    client_nodes = [
        ("h1", h1),
        ("h2", h2),
        ("h3", h3),
        ("h4", h4),
    ]

    for name, node in client_nodes:
        start_bg(
            node,
            f"LOG_DIR={web_dir}/ /scripts/consume.sh {duration} 10.0.0.254",
            f"{run_dir}/clients/{name}/consume.log",
            f"{run_dir}/clients/{name}/consume.pid",
        )

    # h1.cmd(
    #     f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>/tmp/consume.err >/tmp/consume.log &"
    # )
    # h2.cmd(
    #     f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>>/tmp/consume.err >>/tmp/consume.log &"
    # )
    # h3.cmd(
    #     f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>>/tmp/consume.err >>/tmp/consume.log &"
    # )
    # h4.cmd(
    #     f"LOG_DIR=/tmp/web-{ts}/ /scripts/consume.sh {duration} 10.0.0.254 2>>/tmp/consume.err >>/tmp/consume.log &"
    # )

    sleep(duration * 0.2)

    a1_pps = 2500
    a2_pps = 2000

    start_bg(
        a1,
        f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.254 --iface a1-eth0 --pps {a1_pps}",
        f"{run_dir}/attackers/a1/attacker.log",
        f"{run_dir}/attackers/a1/attacker.pid",
    )

    start_bg(
        a2,
        f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.254 --iface a2-eth0 --pps {a2_pps}",
        f"{run_dir}/attackers/a2/attacker.log",
        f"{run_dir}/attackers/a2/attacker.pid",
    )

    # a1.cmd(f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.254 --iface a1-eth0 --pps {a1_pps} 2>/tmp/attacker.err >/tmp/attacker.log &")
    # a2.cmd(f"python3 /scripts/synflood.py --duration {duration} --target 10.0.0.254 --iface a2-eth0 --pps {a2_pps} &")

    # ts_at = int(time())
    # a1.cmd(f"echo '[synflood] Start,{ts_at}' > {run_dir}/attackers/a1/attacker.log")
    #
    # start_bg(
    #     a1,
    #     "slowloris -p 80 10.0.0.254",
    #     f"{run_dir}/attackers/a1/slowloris.log",
    #     f"{run_dir}/attackers/a1/slowloris.pid",
    # )
    # start_bg(
    #     a2,
    #     "slowloris -p 80 10.0.0.254",
    #     f"{run_dir}/attackers/a2/slowloris.log",
    #     f"{run_dir}/attackers/a2/slowloris.pid",
    # )
    # a1.cmd("slowloris -p 80 10.0.0.254 >> /tmp/attacker.log 2>/tmp/attacker.err &")
    # a2.cmd("slowloris -p 80 10.0.0.254 &")

    sleep(duration * 0.8)

    ######################
    ### EXPERIMENT END ###
    ######################

    h1.cmd(
        f"python3 /scripts/plot.py --logdir {web_dir} --attacker-log {run_dir}/attackers/a1/attacker.log --out {run_dir}/reports/results.png > {run_dir}/reports/plot.log 2>&1"
    )

    s1.cmd(
        f'echo "table_dump MyIngress.ipv4_lpm" | simple_switch_CLI > {run_dir}/switch/table_dump'
    )
    s1.cmd(
        f'(echo "counter_read MyIngress.resultCounter 0"; '
        f'echo "counter_read MyIngress.resultCounter 1") | '
        f"simple_switch_CLI > {run_dir}/switch/classification.txt 2>&1"
    )

    return
