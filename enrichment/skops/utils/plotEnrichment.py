import argparse, pathlib, json, logging, sys

import matplotlib
import matplotlib.pyplot as plt

# Use the non-interactive backend and disable logging
matplotlib.use('Agg')
plt.set_loglevel(level = "warning")

def parseArgs():
    parser = argparse.ArgumentParser()

    parser.add_argument("--debug",        help = "enable debugging output", action = "store_true")
    parser.add_argument("--firefly-path", help = "path to the JSON file containing the fireflies", type = str, default = "fireflies.json")
    parser.add_argument("--iperf3-path",  help = "path to the JSON file containing the iperf3 traffic data", type = str, default = "iperf3.json")

    return parser.parse_args()

def loadData(fireflyPath: str, iperf3Path: str) -> dict:
    data = {}
    try:

        firefly = json.loads(pathlib.Path(fireflyPath).read_text())

        try:
            data["netlink"] = firefly["netlink"]
            data["ebpf"] = firefly["ebpfTcpInfo"]
        except KeyError as err:
            logging.error(f"error accessing firefly data: {err}")
            sys.exit(-1)

        data["iperf3Raw"] = json.loads(pathlib.Path(iperf3Path).read_text())

        # Parse the iperf3 data as it's a bit unwieldy...
        data["iperf3"] = [interval['streams'][0] for interval in data["iperf3Raw"]["intervals"]]

        # Bytes sent are reported per slot and not accumulated in iperf3
        acc = 0
        for sample in data["iperf3"]:
            acc += sample["bytes"]
            sample["bytessent"] = acc

    except FileNotFoundError as err:
        logging.error(f"couldn't load the data: {err}")
        sys.exit(-1)

    logging.debug(f"loaded data: {data}")

    return data

netlinkToIperf3Mapping = {
    "sndcwnd": "snd_cwnd"
}

def getFactor(sample, variable):
    if variable == "sndCwnd":
        return sample["tcpInfo"]["sndMss"]
    return 1

def plot(data: dict, variable: str, title: str, yLabel: str, scale: float = 1.0):
    fig = plt.figure(num = 1, clear = True)
    ax = fig.add_subplot()

    ax.plot([sample['tcpInfo'][variable] * getFactor(sample, variable) / scale for sample in data['netlink']], '-b', label = 'netlink')
    ax.plot([sample['tcpInfo'][variable] * getFactor(sample, variable) / scale for sample in data['ebpf']], '-r', label = 'eBPF')
    ax.plot([sample[netlinkToIperf3Mapping.get(variable.lower(), variable.lower())] / scale for sample in data['iperf3']], '-g', label = 'iperf3')

    plt.legend(loc="upper left")
    plt.title(title)
    ax.set_xlabel('Time [s]')
    ax.set_ylabel(yLabel)

    fig.savefig(f"./plots/{variable}.png")

def main():
    args = parseArgs()

    if args.debug:
        logging.basicConfig(level = logging.DEBUG)

    data = loadData(args.firefly_path, args.iperf3_path)

    for k in data.keys():
        logging.info(f"loaded {len(data[k])} {k} data samples")

    plot(data, "rtt", "RTT", "RTT [us]")
    plot(data, "rttVar", "RTT Variance", "RTT Var [us]")
    plot(data, "sndCwnd", "Sender's Congestion Window", "Congestion Window [MiB]", scale = 2 ** 20)
    plot(data, "pMtu", "Path MTU", "PMTU [bytes]")
    plot(data, "bytesSent", "Sent Bytes", "Data [MiB]", scale = 2 ** 20)

if __name__ == "__main__":
    main()
