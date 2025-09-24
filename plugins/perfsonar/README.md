# perfSONAR plugin
This plugin provides a convenient way to mark **all traffic** egressing from a machine. It's name stems from the fact that it
was initially designed for deployment on [perfSONAR](https://www.perfsonar.net) machines.

## Use
The plugin expects no interaction whatsoever: one need only specify its configuration and that's that. Please bear in mind
that the plugin will **override** the selected eBPF marking strategy and set it to `"flowLabelMatchAll"`. If this strategy
wasn't the configured one, a message with level `WARN` will be shown on the log.

## Configuration
Please refer to the Markdown-formatted documentation at the repository's root for more information on available
options. The following replicates the default configuration:

```yaml
plugins:
    perfsonar:
        activityId: 0
        experimentId: 0
```
