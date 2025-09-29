# iperf3 plugin
This plugin detects TCP flows started on the machine, optionally filtering them based on provided source and destination
port ranges. The activity and experiment IDs that'll be used for marking are read either sequentially and cyclically or
from randomly from the provided list.

## Use
The plugin expects the port ranges defining the flows to be sensitive to as well as the experiment and activity IDs
to leverage. If any port bound is set to `0` it'll be effectively disabled. This means that setting all the port
boundaries to `0` will trigger a flow for every TCP connection in the system.

## Configuration
Please refer to the Markdown-formatted documentation at the repository's root for more information on available
options. The following replicates the default configuration:

```yaml
plugins:
    iperf3:
        minSourcePort: 0
        maxSourcePort: 0

        minDestinationPort: 0
        maxDestinationPort: 0

        cgroupPath: /sys/fs/cgroup
        programPath: ""

        debugMode: false

        randomIDs: false
        activityIds: [0, 1, 2]
        experimentIds: [0, 1, 2]
```
