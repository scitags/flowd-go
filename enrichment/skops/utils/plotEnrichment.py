import argparse, pathlib, json

import matplotlib
# Use the non-interactive backend
matplotlib.use('Agg')

import matplotlib.pyplot as plt

def parseIperf3():
    pass

def main():
    netlinkData = json.loads(pathlib.Path("fireflies.json").read_text())["netlink"]
    ebpfData = json.loads(pathlib.Path("fireflies.json").read_text())["ebpfTcpInfo"]
    iperfData = json.loads(pathlib.Path("iperf3.json").read_text())

    print(f"number of netlink snapshots taken: {len(netlinkData)}")
    print(f"number of ebpf snapshots taken: {len(ebpfData)}")

    # for k, v in firefly['netlink'][0].items():
    #     print(f"\tk: {k}:")

    #     if v is None:
    #         print("\t\tv: None")
    #         continue

    #     for kk, vv in v.items():
    #         print(f"\t\tkk: {kk}")

    for i, snapshot in enumerate(netlinkData):
        print(f"{snapshot['tcpInfo']['rtt']} -- {iperfData['intervals'][i]['streams'][0]['rtt']}")
        print(f"{snapshot['tcpInfo']['rttVar']} -- {iperfData['intervals'][i]['streams'][0]['rttvar']}")
        print(f"{snapshot['tcpInfo']['pMtu']} -- {iperfData['intervals'][i]['streams'][0]['pmtu']}")
        print(f"{snapshot['tcpInfo']['sndCwnd'] * snapshot['tcpInfo']['sndMss']} -- {iperfData['intervals'][i]['streams'][0]['snd_cwnd']}")
        print(f"{snapshot['tcpInfo']['bytesSent']} -- {iperfData['intervals'][i]['streams'][0]['bytes']}")

    fig = plt.figure(num=1, clear=True)
    ax = fig.add_subplot()
    ax.plot([snapshot['tcpInfo']['rtt'] for snapshot in netlinkData], '-b', label = 'netlink')
    ax.plot([iperfData['intervals'][i]['streams'][0]['rtt'] for i in range(len(netlinkData))], '-g', label = 'iperf3')
    ax.plot([snapshot['tcpInfo']['rtt'] for snapshot in ebpfData], '-r', label = 'eBPF')
    plt.legend(loc="upper left")
    plt.title("RTT")
    ax.set_xlabel('Time [s]')
    ax.set_ylabel('RTT [us]')
    fig.savefig("rtt.png")

    fig = plt.figure(num=1, clear=True)
    ax = fig.add_subplot()
    ax.plot([snapshot['tcpInfo']['rttVar'] for snapshot in netlinkData], '-b', label = 'netlink')
    ax.plot([iperfData['intervals'][i]['streams'][0]['rttvar'] for i in range(len(netlinkData))], '-g', label = 'iperf3')
    ax.plot([snapshot['tcpInfo']['rttVar'] for snapshot in ebpfData], '-r', label = 'eBPF')
    plt.legend(loc="upper left")
    plt.title("RTT Variance")
    ax.set_xlabel('Time [s]')
    ax.set_ylabel('RTT Var [us]')
    fig.savefig("rttVar.png")

    fig = plt.figure(num=1, clear=True)
    ax = fig.add_subplot()
    ax.plot([snapshot['tcpInfo']['sndCwnd'] * snapshot['tcpInfo']['sndMss'] / 2 ** 20 for snapshot in netlinkData], '-b', label = 'netlink')
    ax.plot([iperfData['intervals'][i]['streams'][0]['snd_cwnd'] / 2 ** 20 for i in range(len(netlinkData))], '-g', label = 'iperf3')
    ax.plot([snapshot['tcpInfo']['sndCwnd'] * snapshot['tcpInfo']['sndMss'] / 2 ** 20 for snapshot in ebpfData], '-r', label = 'eBPF')
    plt.legend(loc="upper left")
    plt.title("Sender's Congestion Window")
    ax.set_xlabel('Time [s]')
    ax.set_ylabel('Congesiton Window [MiB]')
    fig.savefig("sndCwnd.png")

    fig = plt.figure(num=1, clear=True)
    ax = fig.add_subplot()
    ax.plot([snapshot['tcpInfo']['pMtu'] for snapshot in netlinkData], '-b', label = 'netlink')
    ax.plot([iperfData['intervals'][i]['streams'][0]['pmtu'] for i in range(len(netlinkData))], '-g', label = 'iperf3')
    ax.plot([snapshot['tcpInfo']['pMtu'] for snapshot in ebpfData], '-r', label = 'eBPF')
    plt.legend(loc="upper left")
    plt.title("PMTU")
    ax.set_xlabel('Time [s]')
    ax.set_ylabel('PMTU [bytes]')
    fig.savefig("pmtu.png")

    iperfSentBytes = []
    for i in range(len(netlinkData)):
        iperfSentBytes.append(iperfData['intervals'][i]['streams'][0]['bytes'])

    fig = plt.figure(num=1, clear=True)
    ax = fig.add_subplot()
    ax.plot([snapshot['tcpInfo']['bytesSent'] / 2 ** 20 for snapshot in netlinkData], '-b', label = "netlink")
    ax.plot([sum(iperfSentBytes[0:i]) / 2 ** 20 for i in range(len(netlinkData))], '-g', label = "iperf3")
    ax.plot([snapshot['tcpInfo']['bytesSent'] / 2 ** 20 for snapshot in ebpfData], '-r', label = "eBPF")
    plt.legend(loc="upper left")
    plt.title("Sent Bytes")
    ax.set_xlabel('Time [s]')
    ax.set_ylabel('Data [MiB]')
    fig.savefig("bytes.png")

if __name__ == "__main__":
    main()
