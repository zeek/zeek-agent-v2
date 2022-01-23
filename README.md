# Zeek Agent v2

This is a prototype of a new Zeek Agent implementation that applies
some lessons learned. The goal is to come to a minimal, portable agent
that's easy to deploy and scale, and focuses on what helps Zeek the
most while keeping runtime overhead as low as possible.

For the time being, this new version remains unstable and WIP, with some
functionality still missing.

Stay tuned for updates and some documentation.

## Table Reference

<!-- begin table reference -->
<details>
<summary><tt>files_lines:</tt> Report lines of text files matching glob pattern, with leading and trailing whitespace stripped.</summary>

| Column | Type | Description
| --- | --- | --- |
| `path` | text |  |
| `line` | int |  |
| `data` | blob |  |
</details>

<details>
<summary><tt>files_list:</tt> List files matching glob pattern</summary>

| Column | Type | Description
| --- | --- | --- |
| `path` | text |  |
| `type` | text |  |
| `uid` | int |  |
| `gid` | int |  |
| `mode` | text |  |
| `mtime` | int |  |
| `size` | int |  |
</details>

<details>
<summary><tt>processes:</tt> List of current system processes</summary>

| Column | Type | Description
| --- | --- | --- |
| `name` | text | name of process |
| `pid` | int | process ID |
| `uid` | int | user ID |
| `gid` | int | group ID |
| `ppid` | int | parent's process ID |
| `priority` | int | process priority |
| `startup` | int | time process started |
| `vsize` | int | virtual memory size |
| `rsize` | int | resident memory size |
| `utime` | int | user CPU time |
| `stime` | int | system CPU time |
</details>

<details>
<summary><tt>sockets:</tt> List of sockets open on system</summary>

| Column | Type | Description
| --- | --- | --- |
| `pid` | int |  |
| `process` | text |  |
| `family` | text |  |
| `protocol` | int |  |
| `local_port` | int |  |
| `remote_port` | int |  |
| `local_addr` | text |  |
| `remote_addr` | text |  |
| `state` | text |  |
</details>

<details>
<summary><tt>system_logs_events:</tt> Logs recorded by the operating system</summary>

| Column | Type | Description
| --- | --- | --- |
| `time` | int | unix timestamp |
| `process` | text |  |
| `level` | text |  |
| `message` | text |  |
</details>

<details>
<summary><tt>users:</tt> List of users on system</summary>

| Column | Type | Description
| --- | --- | --- |
| `name` | text |  |
| `full_name` | text |  |
| `is_admin` | int |  |
| `is_system` | int |  |
| `uid` | int |  |
| `gid` | int |  |
| `home` | text |  |
| `shell` | text |  |
| `email` | text |  |
</details>

<details>
<summary><tt>zeek_agent:</tt> Information about the current Zeek Agent process</summary>

| Column | Type | Description
| --- | --- | --- |
| `id` | text | unique agent ID |
| `instance` | text | unique ID for agent process instance |
| `hostname` | text |  |
| `address` | text |  |
| `platform` | text |  |
| `os_name` | text |  |
| `kernel_name` | text |  |
| `kernel_version` | text |  |
| `kernel_arch` | text |  |
| `agent_version` | int | agent version |
| `broker` | text | agent version |
| `uptime` | int | process uptime in seconds |
</details>

<!-- end table reference -->
