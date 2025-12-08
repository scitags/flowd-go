flowd-go 1 "September 2025" flowd-go "General Commands Manual"
==============================================================

# NAME
flowd-go - SciTags Flowd-go Daemon

# SYNOPSIS
`flowd-go [-h | --help] [--conf CONFIG_FILE_PATH] [--log-level=info] [--log-time] [run | version | help]`

# DESCRIPTION
The flowd-go daemon will listen for flow events through its various plugins and exert the actions as defined in its several
backends. For instance, if a new flow is defined the marker backend will modify the IPv6 flow label of datagrams until that
same flow is stopped.

In the context of flowd-go a *flow* is usually represented as a 5-tuple including the source and destination IPv{4,6} addresses and
ports together with the transport (i.e. L4) protocol. Through *flow events* one can instruct flowd-go to either keep track or
ignore these flows.

Given their complexity, explaining the internals of the different plugins and backends is out of the scope of this manpage.
A simple overview of each of them will be presented and the reader is encouraged to query the implementation along with the
accompanying documentation files presented as Markdown (i.e. `*.md`) documents.

Given flowd-go's purpose, it is intended to be a long-running service (i.e. a *daemon*). This explains why this service can
be managed through SystemD by interacting with the `flowd-go` unit by means of `systemctl(1)`.

The implementation can be found at https://github.com/scitags/flowd-go.

# OPTIONS
`-h, --help`

:   Show the help message and exit.

`--conf CONFIG_FILE_PATH`

:   Provides the path of the configuration file. If left unspecified, it will default to `/etc/flowd-go/conf.yaml`.
    The syntax of the configuration file is explained in the **CONFIGURATION** section.

`--log-level=info`

:   Controls the logging verbosity. By default only messages with a verbosity of `info` and higher will be printed.
    This option must be one of `debug`, `info`, `warn` or `error`. If a wrong level is specified the default of
    `info` will be used.

`--log-time`

:   Controls whether timestamps are included in the log entries or not. If this option is set, the first entry in
    each log line will be a timestamp. Otherwise, this timestamp will not be shown. This option is useful when
    running flowd-go standalone as other facilities such as SystemD's `systemd-journald(8)` include their own
    timestamps by default.

# COMMANDS
`help`

:   Show the help message and exit.

`version`

:   Show the hash of the built commit and exit.

`run`

:   Run the flowd-go daemon.

`marker`

:   A command hosting several marker-related subcommands. These allow for handling details about the
    underlying eBPF machinery.

`stun`

:   A command hosting several STUN-related subcommands. These allow to test how STUN or HTTP-based resolution
    is carried out when mapping private to public addresses.

## Marker SUBCOMMANDS
`clean`

:   Clean up the backing eBPF infrastructure including qdisc, hooks and programs. This is particularly useful
    if flowd-go terminates abruptly, even though it should be able to handle leftover hooks and qdiscs.

## Stun SUBCOMMANDS
`sample`

:   Run private-to-public address mapping logic mimicking what would be done when running with STUN enabled.

# PLUGINS
This section lists the configuration options available for each of the provided plugins. For a deeper explanation please
refer to the documentation accompanying the implementation, which can be found on the URL provided in the DESCRIPTION. The
setting's value type is enclosed in brackets (`[]`) and its default value is enclosed in braces (`{}`).

## namedPipe
The **named pipe** plugin will create a FIFO through a call to `mkfifo(3)` on which it will listen for flow events. Available
settings are:

- **maxReaders [int] {5}**: Size of the notification channel's buffer so that a high rate of writes to the named pipe doesn't
  cause the loss of events. Unless the named pipe plugin is intended to be subject to a high load
  this value should be okay.

- **buffSize [int] {1000}**: The size of the buffer (in bytes) writes to the named pipe are read into. The default value should
  be more than enough, but if flow events are extremely large increasing this value could help.

- **pipePath [string] {"/var/run/flowd-go/np"}**: The path on which to create the named pipe.

## api
The **API** plugin will create an HTTP server providing a REST API through which one can send flow events. Please refer to the
documentation provided with the implementation for information on how to interact with the provided API endpoints.

- **bindAddress [string] {"127.0.0.1"}**: The address to bind the server to. As usual `"0.0.0.0"` will make the server listen on
  every available interface configured with an IPv4 address. You can also provide an IPv6 address.

- **bindPort [int] {7777}**: The port to bind the server to. Bear in mind this value **MUST** be equal to o lower than `65535` as ports are
  represented with 16-bit unsigned integers.

## firefly
The **Firefly** backend expects to receive UDP fireflies to parse them and generate flow events based on its contents. A typical use case
for this plugin is the enrichment of fireflies with information from the `netlink(7)` subsystem where flowd-go behaves as a firefly
relay. Be sure to check the documentation on the firelfy backend for more information.

- **bindAddress [string] {"127.0.0.1"}**: The address to bind the UDP socket to. As usual `"0.0.0.0"` will make the server listen on
  every available interface configured with an IPv4 address. You can also provide an IPv6 address.

- **bindPort [int] {10514}**: The port to bind the UDP socket to. Bear in mind this value **MUST** be equal to o lower than `65535` as ports are
  represented with 16-bit unsigned integers.

- **bufferSize [int] {4096}**: The size of the buffer data arriving on the UDP socket will be written into in bytes. If you're expecting large
  fireflies you should consider increasing this number. Bear in mind that this value **MUST** be larger than `2048` or else flowd-go will refuse
  to start after printing an error.

- **deadline [int] {0}**: The deadline (in seconds) to apply to the UDP socket. If set to `0` then no deadline is applied. Please bear in mind this
  is a fine-tuning parameter that shouldn't usually be tampered with. Configure a different value at your own risk!

- **hasSyslogHeader [bool] {false}**: Whether the incoming fireflies contain the syslog header or not.

## perfsonar
The **perfSONAR** plugin will simply mark **all outgoing traffic** with the provided activity and experiment IDs. If the `matchAll` option of
the `marker` backend is not set to `true`, this plugin will overwrite the setting, emitting a warning in the process. This plugin is devised
to work hand in hand with the `marker` backend.

- **activityId [int] {0}**: The activity ID to leverage for marking traffic.

- **experimentId [int] {0}**: The experiment ID to leverage for marking traffic.

## iperf3
The **iperf3** plugin detects TCP flows started on the machine, optionally filtering them based on provided source and destination
port ranges. Activity and experiment IDs are read from the provided lists.

- **minSourcePort [int] {0}**: The lowest source port (inclusive) to be sensitive to.

- **maxSourcePort [int] {0}**: The highest source port (inclusive) to be sensitive to.

- **minDestinationPort [int] {0}**: The lowest destination port (inclusive) to be sensitive to.

- **maxDestinationPort [int] {0}**: The highest destination port (inclusive) to be sensitive to.

- **cgroupPath [string] {/sys/fs/cgroup}**: The cgroup path to attach the backing eBPF program to.

- **programPath [string] {""}**: The path to an eBPF program to load instead of the one embedded into flowd-go. This program should have been compiled
  in a particular way as the loading into the kernel won't work otherwise. Please refer to the eBPF documentation bundled with the implementation
  to take a look at how the embedded program is compiled.

- **debugMode [bool] {false}**: Whether to load an eBPF program compiled with debug support. This option **should be false on production** environments.
  The many calls to `bpf_printk` preset if compiled with debugging support can have an effect on performance. You have been warned!

- **randomIDs [bool] {false}**: Whether to read experiment and activity IDs sequentially (default) or randomly. The generated index will be leveraged for
  recovering both IDs.

- **experimentIDs [array of int] {[0, 1, 2]}**: The experiment IDs to leverage for marking traffic. Bear in mind that both `experimentIDs` and `activityIDs`
  should have the same length.

- **activityIDs [array of int] {[0, 1, 2]}**: The activity IDs to leverage for marking traffic. Bear in mind that both `experimentIDs` and `activityIDs`
  should have the same length.

# BACKENDS
This section lists the configuration options available for each of the provided backends. For a deeper explanation please
refer to the documentation accompanying the implementation, which can be found on the URL provided in the DESCRIPTION. The
setting's value type is enclosed in brackets (`[]`) and its default value is enclosed in braces (`{}`).

## marker
The **marker** plugin will mark IPv6 datagrams by setting the value of the *flow label* in its header. This plugin relies on an eBPF program
hooked on a *clsact qdisc* which only deals with egress datagrams. The loading and communication with the eBPF program is managed with
`cilium`. There are many more (interesting) details in the backend's documentation.

- **targetInterfaces [array of string] {["lo"]}**: The interfaces to hook the eBPF program on. These interfaces should normally include
  the outbound interface of the machine (i.e. the one pointed to by the default route as given by `ip-route(8)`). The provided interface
  names should be the values presented by `ip-link(8)`.

- **discoverInterfaces [bool] {false}**: Whether to automatically discover the Network Interface Cards (NICs) to attach the eBPF program to.
  If set to true, the criteria would be to attach the eBPF program to **any** interface with an associated public IPv6 address. These public
  IPv6 addresses are defined by a compendium of RFCs: we encourage the reader to take a look at the source to find the list against which
  the IPv6 addresses are matched. Please be advised that if this setting is set to true the list of interfaces provided through `targetInterfaces`
  will be ignored and a log message reflecting that will be issued.

- **removeQdisc [bool] {true}**: Whether to remove the qdisc (see `tc(8)`) implicitly created to hook the eBPF program. Unless you have a very
  good reason to, don't reconfigure this value as doing so might leave the system in a 'dirty' state after flowd-go exits. In order to remove
  the qdisc manually you can run:

        $ tc qdisc del dev <targetInterface> clsact

  Where `targetInterface` is the one configured with the previous option.

- **programPath [string] {""}**: The path to an eBPF program to load instead of the one embedded into flowd-go. This program should have been compiled
  in a particular way as the loading into the kernel won't work otherwise. Please refer to the eBPF documentation bundled with the implementation
  to take a look at how the embedded program is compiled.

- **markingStrategy [string] {"label"}**: The marking strategy to leverage on the eBPF program. This option must be one of the following if
  configured, otherwise flowd-go will refuse to start. Available marking strategies are:

    - `"label"`: The eBPF program embeds the flow information in the IPv6 header's *Flow Label* field as defined in SciTags' technical specification.
    - `"hopByHop"`: The eBPF programs adds a *Hop-by-Hop Options* extension header encoding the flow information.
    - `"destination"`: The eBPF program adds a *Destination Options* extension header encoding the flow information.
    - `"hopByHopDestination"`: The eBPF programs adds a *Hop-by-Hop Options* and a *Destination Options* extension header encoding the flow information.

- **matchAll [bool] {false}**: The eBPF program will only mark datagrams belonging to a given flow as defined by the source and destination IPv6 and port.
  this option allows for the removal of these checks within the eBPF program, hence enabling marking on every outgoing datagram. Bear in mind the mark
  will be the same for **every datagram**. This mode is deemed useful when working together with perfSONAR instances.

- **debugMode [bool] {false}**: Whether to load an eBPF program compiled with debug support. This option **should be false on production** environments.
  The many calls to `bpf_printk` preset if compiled with debugging support can have an effect on performance. You have been warned!

## firefly
The **Firefly** backend will send UDP fireflies as defined in https://www.scitags.org. These are basically UDP datagrams including a JSON-formatted
payload including flow information.

- **destinationPort [int] {10514}**: The destination port of the UDP fireflies. Bear in mind this value should be equal to or lower than
  `65535` as ports are represented with 16-bit unsigned integers.

- **prependSyslog [bool] {true}**: The technical specification states that an initial bit of information containing syslog-parsable information should
  be prepended to the JSON payload. When developing and debugging these payloads the header 'gets in the way' and so one can turn it off. However,
  in a production scenario this setting should be `true`.

- **sendToCollector [bool] {false}**: Fireflies are sent to a transfer's destination address by default. In some scenarios it might be worthwhile to also
  send them to a so called *collector* (usually deployed by National Research and Education Networks) for backbone-level information gathering. It set to
  `true`, this option causes the firefly backend to also send the generated fireflies to the collector specified by the following two settings.

- **collectorAddress [string] {"127.0.0.1"}**: The address of the collector to send fireflies to. At the moment a single address might be specified, but
  in future implementations this option may turn into an array of strings.

- **collectorPort [int] {10514}**: The port the collector is listening on for incoming fireflies.

- **enrich [bool] {false}**: Whether to send periodic fireflies containing TCP flow information.

- **enrichmentMode [string] {"lean"}**: How to encode the enrichment information. This option must be one of:

    - `"lean"`: Include a subset of TCP information and the congestion algorithm.
    - `"compatible"`: Generate flowd-compatible fireflies.
    - `""`: If explicitly empty, all the information will be included. Beware, the amount of information is quite large...

- **stun [object]**: The configuration for private-public address mapping. Bear in mind that, despite it's name, the logic controlled
  through this option leverages both STUN-based and HTTP-based methods (favouring the latter) to resolve private interface addresses
  to public ones. Please note that only the private address of the default interface (as given by the default route) will be automatically
  mapped. You can leverage the `manualMapping` option to override this behaviour by providing a manual list of private-public address
  pairs. As implied by this setting belonging to the firefly backend's configuration, these remappings will only be applied to outbound
  fireflies.

    - **manualMapping [object of string keys and string values] {{}}**: A list of private address (keys) and the associated public ones (values).
    Bear in mind that, despite the name, you can map public addresses to other public or private addresses. The backend indexes the keys with
    the flow's source address and rewrites the source address to the associated value.

    - **stunServers [array of string] {["stun.l.google.com:3478", "stun{1,2,3,4}.l.google.com:3478"]}**: Additional STUN servers to leverage for,
    well, STUN-based public address discovery.

## prometheus
The **prometheus** backend will export flow information gathered by ENRICHERS as prometheus-compatible metrics. These can then be acquired by an
existing prometheus deployment for monitoring and further analysis. Note how two ports are supported so that we can publish data acquired through
both netlink and skops.

- **log [bool] {true}**: Whether to include log messages emitted by the backend in the overall log.

- **bindAddress [string] {"127.0.0.1"}**: The address in which to bind the backing HTTP servers to.

- **netlinkPort [int] {8080}**: The port to bind the netlink registry to. Flow information acquired through netlink will be exported as a series
  of metrics here. If `0`, netlink metrics will not be exported.

- **skopsPort [int] {8081}**: The port to bind the netlink registry to. Flow information acquired through netlink will be exported as a series
  of metrics here. If `0`, skops metrics will not be exported.

# ENRICHERS
TCP connections can be monitored to gain a deeper insight into their evolution. In flowd-go this information is extracted through *enrichers*.
The gathered information is relayed to every backend so that they can handle and embed the data as they see fit. How this data is
extracted is configured in the `enrichers` section of the configuration detailed below. For a deeper explanation please
refer to the documentation accompanying the implementation, which can be found on the URL provided in the DESCRIPTION. The
setting's value type is enclosed in brackets (`[]`) and its default value is enclosed in braces (`{}`).

- **period [int] {1000}**: Period with which to extract information, in milliseconds. Note this period will be applied to **every** enricher.

- **netlink [object]**: The configuration of the netlink enrichment source:

    - **protocol [int] {6}**: The transport protocol (either TCP or UDP) to query. The value is either `IPPROTO_TCP` (6) or
    `IPPROTO_UDP` (17) as defined in `include/uapi/linux/in.h`.

    - **ext [int] {255}**: The requested information from `sock_daig(7)`. This value is derived from `INET_DIAG_*` constants
    as defined in `include/uapi/linux/inet_diag.h`.

    - **state [int] {3071}**: The TCP states to retrieve information from. This value is derived from `TCP_*` constants
    as defined in `include/net/tcp_states.h`.

- **skops [object]**: The configuration of the skops enrichment source:

    - **cgroupPath [string] {"/sys/fs/cgroup"}**: The path of the `cgroups(7)` to be sensitive to. The 'shallower' the path, the
      more sockets we'll be sensitive to. Making the path 'deeper' reduces 'noise' at the expense of not being sensitive to
      some sockets. Only alter this setting of you know what you're doing...

    - **programPath [string] {""}**: The path to an eBPF program to load instead of the one embedded into flowd-go. This program should have been compiled
      in a particular way as the loading into the kernel won't work otherwise. Please refer to the eBPF documentation bundled with the implementation
      to take a look at how the embedded program is compiled.

    - **debugMode [bool] {false}**: Whether to load an eBPF program compiled with debug support. This option **should be false on production** environments.
      The many calls to `bpf_printk` preset if compiled with debugging support can have an effect on performance. You have been warned!

    - **strategy [string] {"poll"}**: How to acquire information from the sockets:

        - `"poll"`: Poll sockets every `period` seconds as configured in the firefly backend.
        - `"transition"`: Only acquire information when the associated TCP state transitions. This strategy is much leaner than the
          polling in the sense that the number of times data is gathered is independent of the duration of connections.

# CONFIGURATION
Flowd-go's configuration is defined through a YAML file which by default will be `/etc/flowd-go/conf.yaml`. A different
path can be specified through the `--conf` option.

Please note **every** configuration parameter is optional. The configuration parsing logic can tell wether an option
has been configured and, if not, a default value is applied. Bear in mind plugins and backends **MUST** be included in the
configuration file, but their associated options can be an empty object (i.e. `{}`). The following are examples of
valid configurations:

    # Use default settings for everything, but do instantiate an api plugin and the marker and firefly backends
    plugins:
        api: {}

    backends:
        marker: {}
        firefly: {}

If setting `--log-level=debug` you will get a glimpse of what is actually parsed so that you can check whether it's what
you expect or not.

The following details the available configuration options. The setting's value type is enclosed in brackets (`[]`) and
its default value is enclosed in braces (`{}`).

**pidPath [string] {"/var/run/flowd-go.pid"}**

:   The path where the main process' PID will be written.

**workDir [string] {"/var/cache/flowd-go"}**

:   The directory where flowd-go will drop cache's and otherwise persistent files.

**plugins [object]**

:   This object defines the plugins to instantiate as well as their configuration. The object's keys **MUST**
    be the identifier of the desired plugin and the associated values are objects representing each plugin's
    particular configuration. The details of these per-plugin configurations can be found on the PLUGINS
    section. If key specifying a non-existent plugin is included, flowd-go will refuse to start and print
    a (hopefully) informative error indicating the problem.

**backends [object]**

:   This object defines the backends to instantiate as well as their configuration. The object's keys **MUST**
    be the identifier of the desired backend and the associated values are objects representing each backend's
    particular configuration. The details of these per-backend configurations can be found on the BACKENDS
    section. If key specifying a non-existent backend is included, flowd-go will refuse to start and print
    a (hopefully) informative error indicating the problem.

# AUTHORS
- Tristan Sullivan (CERN)
- Marian Babik (CERN)
- Pablo Collado Soto <pablo.collado@uam.es> (Universidad Autónoma de Madrid)
