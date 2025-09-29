import argparse, pathlib, json, logging, sys, datetime

import matplotlib
import matplotlib.pyplot as plt

# Use the non-interactive backend and disable logging
matplotlib.use('Agg')
plt.set_loglevel(level = "warning")

def parseArgs():
    parser = argparse.ArgumentParser()

    parser.add_argument("--debug",
        help = "enable debugging output",
        action = "store_true"
    )

    parser.add_argument("--firefly-path",
        help = "path to the JSON file containing the fireflies (default: fireflies.jsonl)",
        type = str,
        default = "fireflies.jsonl"
    )

    parser.add_argument("--iperf3-path",
        help = "path to the JSON file containing the iperf3 traffic data (default: iperf3.json)",
        type = str,
        default = "iperf3.json"
    )

    parser.add_argument("--prefix",
        help = "prefix to append to generated graphs (default: plots/def-)",
        type = str,
        default = "plots/def-"
    )

    parser.add_argument("--cong-alg",
        help = "congestion algorithm (default: none)",
        type = str,
        default = "none"
    )

    return parser.parse_args()

# Simply round us to ms to be compliant with ISO 8601
def processTimeStamp(ts: str):
    us = ts.split(":")[-2].split("+")[0].split(".")[-1]

    # Extend us so that is has at least three digits!
    if len(us) < 3:
        usExt = us + '0' * (3 - len(us))
    else:
        usExt = us

    return ts.replace(us, usExt[:3])

def loadFireflyData(lines: list[str]):
    netlinkDataPoints = []
    ebpfDataPoints = []

    for i, line in enumerate(lines):
        # logging.debug(f"line {i}: {line}")

        rawJson = json.loads(line)

        if rawJson["flow-lifecycle"]["state"] != "ongoing":
            continue

        if "netlink" in rawJson:
            netlinkDataPoints.append({
                "ts": datetime.datetime.fromisoformat(processTimeStamp(rawJson["flow-lifecycle"]["current-time"])),
                "data": rawJson["netlink"]["tcpInfo"]
            })

        if "skOps" in rawJson:
            ebpfDataPoints.append({
                "ts": datetime.datetime.fromisoformat(processTimeStamp(rawJson["flow-lifecycle"]["current-time"])),
                "data": rawJson["skOps"]["tcpInfo"]
            })

    return netlinkDataPoints, ebpfDataPoints

def loadData(fireflyPath: str, iperf3Path: str) -> dict:
    data = {}
    try:

        try:
            netlinkData, ebpfData = loadFireflyData(pathlib.Path(fireflyPath).read_text().splitlines())
        except KeyError as err:
            logging.error(f"error accessing firefly data: {err}")
            sys.exit(-1)

        data["netlink"] = netlinkData
        data["ebpf"] = ebpfData

        data["iperf3Raw"] = json.loads(pathlib.Path(iperf3Path).read_text())

        # Parse the iperf3 data as it's a bit unwieldy...
        currentTime = datetime.datetime.strptime(
            data["iperf3Raw"]["start"]["timestamp"]["time"], "%a, %d %b %Y %H:%M:%S GMT"
        ).replace(tzinfo = datetime.timezone.utc)

        data["iperf3"] = []
        for interval in data["iperf3Raw"]["intervals"]:
            currentTime += datetime.timedelta(0, interval['streams'][0]["seconds"])

            data["iperf3"].append({
                "ts": currentTime,
                "data": interval['streams'][0]
            })

        # Bytes sent are reported per slot and not accumulated in iperf3
        acc = 0
        for sample in data["iperf3"]:
            acc += sample["data"]["bytes"]
            sample["data"]["bytessent"] = acc

    except FileNotFoundError as err:
        logging.error(f"couldn't load the data: {err}")
        sys.exit(-1)

    logging.debug(f"loaded data: {data}")

    # Reference all timestamps to the earliest one
    firstTs = min(data["iperf3"][0]["ts"], data["netlink"][0]["ts"], data["ebpf"][0]["ts"])

    for k, samples in data.items():
        if k == "iperf3Raw":
            continue

        for sample in samples:
            print(f"{k} - {sample}")
            sample["ts"] =  (sample["ts"] - firstTs).total_seconds()

    return data

netlinkToIperf3Mapping = {
    "sndcwnd": "snd_cwnd"
}

def getFactor(sample, variable):
    if variable == "sndCwnd":
        return sample["data"]["sndMss"]
    return 1

def plot(prefix: str, data: dict, variable: str, title: str, yLabel: str, scale: float = 1.0):
    fig = plt.figure(num = 1, clear = True, figsize = (12, 6), dpi = 300)
    ax = fig.add_subplot()

    ax.plot(
        [sample["ts"] for sample in data['netlink']],
        [sample["data"][variable] * getFactor(sample, variable) / scale for sample in data['netlink']],
        '-b', label = 'netlink'
    )

    ax.plot(
        [sample["ts"] for sample in data['ebpf']],
        [sample["data"][variable] * getFactor(sample, variable) / scale for sample in data['ebpf']],
        '-r', label = 'skops'
    )

    ax.plot(
        [sample["ts"] for sample in data['iperf3']],
        [sample["data"][netlinkToIperf3Mapping.get(variable.lower(), variable.lower())] / scale for sample in data['iperf3']],
        '-g', label = 'iperf3'
    )

    plt.legend(loc="upper left")
    plt.title(title)
    ax.set_xlabel('Time [s]')
    ax.set_ylabel(yLabel)

    fig.savefig(f"./{prefix}{variable}.png")

def genTitle(title: str, congAlg: str) -> str:
    if congAlg != "":
        return f"{title} - {congAlg.upper()}"
    return title

def main():
    args = parseArgs()

    if args.debug:
        logging.basicConfig(level = logging.DEBUG)

    data = loadData(args.firefly_path, args.iperf3_path)

    for k in data.keys():
        logging.info(f"loaded {len(data[k])} {k} data samples")

    logging.debug(f"loaded iperf3 data: {data['iperf3']}")

    plot(args.prefix, data, "rtt", genTitle("RTT", args.cong_alg), "RTT [us]")
    plot(args.prefix, data, "rttVar", genTitle("RTT Variance", args.cong_alg), "RTT Var [us]")
    plot(args.prefix, data, "sndCwnd", genTitle("Sender's Congestion Window", args.cong_alg), "Congestion Window [MiB]", scale = 2 ** 20)
    plot(args.prefix, data, "pMtu", genTitle("Path MTU", args.cong_alg), "PMTU [bytes]")
    plot(args.prefix, data, "bytesSent", genTitle("Sent Bytes", args.cong_alg), "Data [MiB]", scale = 2 ** 20)

if __name__ == "__main__":
    main()
