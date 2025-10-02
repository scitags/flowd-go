# Prometheus backend
This backend exports flow information as Prometheus-compatible metrics.

The exported metrics can be gleamed from the initialisation of a `metric` struct as
seen on `metrics.go`.

## Configuration
Please refer to the Markdown-formatted documentation at the repository's root for more information on available
options. The following replicates the default configuration:

```yaml
backends:
    prometheus:
      log:         true
      bindAddress: "127.0.0.1"
      netlinkPort: 8080
      skopsPort:   8081
```
