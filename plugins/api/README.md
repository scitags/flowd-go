# API plugin
This plugin provides a REST API allowing for the creation of *flow events*.

## Use
Interaction with this plugin is carried out through HTTP requests to particular URLs we refer to as endpoints.
The currently available endpoints (as defined in `endpoints.go`) are detailed below. Please note there is an
ongoing effort to adhere to the [OpenAPI](https://spec.openapis.org) specification.

### `GET /`
Returns  JSON-formatted object detailing the available endpoints.

    $ curl http://127.0.0.1:7777
    {
        "ApiRoutes": [
            {
                "method": "GET",
                "path": "/",
                "name": "github.com/scitags/flowd/plugins/api.handleRoot"
            },
            {
                "method": "GET",
                "path": "/dummy/start",
                "name": "github.com/scitags/flowd/plugins/api.handleDummyStartFlow"
            },
            {
                "method": "GET",
                "path": "/dummy/end",
                "name": "github.com/scitags/flowd/plugins/api.handleDummyEndFlow"
            }
        ]
    }

### `GET /dummy/start`
Creates a *flow start event* with hardcoded information. The created flow event is returned as a JSON object.

    $ curl http://127.0.0.1:7777/dummy/start
    {
        "State": 0,
        "Protocol": 0,
        "Src": {
            "IP": "::1",
            "Port": 2345
        },
        "Dst": {
            "IP": "::1",
            "Port": 5777
        },
        "Experiment": 65535,
        "Activity": 65535,
        "StartTs": "2024-11-07T12:22:05.571768742+01:00",
        "EndTs": "0001-01-01T00:00:00Z",
        "NetLink": ""
    }

### `GET /dummy/end`
Creates a *flow end event* with hardcoded information. The created flow event is returned as a JSON object.

    $ curl http://127.0.0.1:7777/dummy/end
    {
        "State": 1,
        "Protocol": 0,
        "Src": {
            "IP": "::1",
            "Port": 2345
        },
        "Dst": {
            "IP": "::1",
            "Port": 5777
        },
        "Experiment": 65535,
        "Activity": 65535,
        "StartTs": "0001-01-01T00:00:00Z",
        "EndTs": "2024-11-07T12:22:27.150587581+01:00",
        "NetLink": ""
    }

## Configuration
Please refer to the Markdown-formatted documentation at the repository's root for more information on available
options. The following replicates the default configuration:

```json
{
    "plugins": {
        "api": {
            "bindAddress": "127.0.0.1",
            "bindPort": 7777
        }
    }
}
