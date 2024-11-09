# Named pipe plugin
This plugin provides named pipe for the creation of *flow events*. This named pipe will be created when `flowd-go` is
executed and deleted upon its exit.

## Use
Interaction with this plugin is carried out by writing to a named pipe (created by a call to `makfifo(3)`). Concurrent
writes to the pipe should be safe.

The expected format for the definition of flow events is:

    state protocol sourceIP sourcePort destinationIP destinationPort experimentID activityID

Where:

- `state` is one of `start` or `end` (case insensitive).
- `protocol` is one of `tcp` or `udp` (case insensitive).
- `sourceIP` is a valid IPv4 or IPv6 address.
- `sourcePort` is an integer equal to or below `65535`.
- `destinationIP` is a valid IPv4 or IPv6 address.
- `destinationPort` is an integer equal to or below `65535`.
- `experimentID` is a positive integer.
- `activityID` is a positive integer.

For example, the following will start and end a flow, respectively:

    # Start an IPv4 flow
    echo "start tcp 192.168.0.1 2345 127.0.0.1 5777 1 2" > np

    # End an IPv4 flow
    echo "end tcp   192.168.0.1 2345 127.0.0.1 5777 1 2" > np

    # Start an IPv6 flow
    echo "start tcp         ::1 2345       ::1 5777 1 2" > np

    # End an IPv6 flow
    echo "end tcp           ::1 2345       ::1 5777 1 2" > np

Note how the amount of whitespace is arbitrary: it'll be completely trimmed.

## Configuration
Please refer to the Markdown-formatted documentation at the repository's root for more information on available
options. The following replicates the default configuration:

```json
{
    "plugins": {
        "np": {
            "maxReaders": 5,
            "buffSize": 1000,
            "pipePath": "np"
        }
    }
}
