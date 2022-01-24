# Zeek Agent README

The Zeek Agent sends host-level information from endpoints to
[Zeek](http://zeek.org), the open-source network security monitor.
Inside Zeek, the activity will show up inside scripts as events, just
as network activity does. A Zeek-side [Zeek Agent
packages](https://github.com/zeek-packages/zeek-agent-v2) provides
scripts with an API access to Zeek Agents. It also adds a number of
new Zeek log files recording endpoint information to disk.

This version supersedes a couple of older implementations (see the
[history](#history)), but remains experimental at this point.

<!-- begin table of contents -->

#### Table of Contents

- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Zeek Package](#zeek-package)
    - [Usage](#usage)
- [Zeek API](#zeek-api)
- [Table Reference](#table-reference)
- [Caveats](#caveats)
- [Versioning](#versioning)
- [License](#license)
- [History](#history)

<!-- end table of contents -->

## Getting Started

### Prerequisites

- The agent currently supports Linux and macOS; Windows support is
  planned. There are no hard dependencies on the endpoints beyond
  standard system libraries. (Individual tables may not be available
  if they don't find what they need.)

- The agent’s script framework requires Zeek 4.0 or newer.

### Installation

- Linux: We are providing a static binary that should run on most
  reasonably modern Linux distributions.
    - [Download](#) `zeek-agent` for Linux.

- macOS: We are providing a binary that works on macOS 11 (Big Sur) and macOS 12 (Monterey).
    - [Download](#) `zeek-agent` for macOS.

You can alternatively compile the agent from source yourself:

```c
# git clone --recursive https://github.com/zeek/zeek-agent-v2
# cd https://github.com/zeek/zeek-agent-v2
# ./configure && make && make test && make install
```

### Zeek Package

```c
# zkg install zeek-agent-v2
```

### Usage

- Start Zeek as normal. The agent package will be activated by
  default.

- On the endpoints, run `zeek-agent -z <address-of-system-running-Zeek>`.

- There will be a new `zeek-agent.log` tracking endpoint connectivity.
  In addition, you will see the follow new log files tracking endpoint
  activity:

    -`zeek-agent-users.log`: Users available on endpoints.
    -`zeek-agent-processes.log`: Processes running on endpoints.

## Zeek API

See [the package](https://github.com/zeek-packages/zeek-agent-v2) for
more information on the API available to scripts inside Zeek.

## Table Reference

<!-- begin table reference -->
<details>
<summary>`files_lines`: Report lines of text files matching glob pattern, with leading and trailing whitespace stripped. (Linux, macOS)</summary>

| Column | Type | Description
| --- | --- | --- |
| `path` | text |  |
| `line` | int |  |
| `data` | blob |  |
</details>

<details>
<summary>`files_list`: List files matching glob pattern (Linux, macOS)</summary>

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
<summary>`processes`: List of current system processes (Linux, macOS)</summary>

| Column | Type | Description
| --- | --- | --- |
| `name` | text | name of process |
| `pid` | int | process ID |
| `ppid` | int | parent's process ID |
| `uid` | int | effective user ID |
| `gid` | int | effective group ID |
| `ruid` | int | real user ID |
| `rgid` | int | real group ID |
| `priority` | int | process priority (higher is more) |
| `startup` | int | time process started |
| `vsize` | int | virtual memory size |
| `rsize` | int | resident memory size |
| `utime` | int | user CPU time |
| `stime` | int | system CPU time |
</details>

<details>
<summary>`sockets`: List of sockets open on system (Linux, macOS)</summary>

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
<summary>`system_logs_events`: Logs recorded by the operating system (Linux, macOS)</summary>

| Column | Type | Description
| --- | --- | --- |
| `time` | int | unix timestamp |
| `process` | text |  |
| `level` | text |  |
| `message` | text |  |
</details>

<details>
<summary>`users`: List of users on system (Linux, macOS)</summary>

| Column | Type | Description
| --- | --- | --- |
| `name` | text | short name |
| `full_name` | text | full name |
| `is_admin` | int | 1 if user has adminstrative privileges |
| `is_system` | int | 1 if user correponds to OS service |
| `uid` | int | user ID |
| `gid` | int | group ID |
| `home` | text | path to home directory |
| `shell` | text | path to default shell |
| `email` | text | email address |
</details>

<details>
<summary>`zeek_agent`: Information about the current Zeek Agent process (Linux, macOS)</summary>

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
| `tables` | text | tables available to queries |
</details>

<!-- end table reference -->

## Caveats

- The supply of tables is currently limited; we are planning to add
  more in the future.

- Currently, most data is collected in regular intervals only, meaning
  that short-lived activity happening between the agent’s regular
  snapshots might be missed (e.g., a process terminating quickly after
  startup). The agent’s internal infrastructure supports “event
  tables” that don’t have that limitation, and we plan to make more
  use of that in the future. (Doing so typically requires usage of
  OS-specific APIs, which is more complex to implement).

## Versioning

We do not provide stable/tagged releases yet, there’s just a `main`
branch in Git; binaries are cut from there. APIs and table schemas are
still evolving, and may break without much notice for the time being.

## License

The Zeek Agent is open source and released under a BSD license, which
allows for pretty much unrestricted use as long as you leave the
license header in place.

## History

This Zeek Agent supersedes an older, [1st-generation
implementation](https://github.com/zeek/zeek-agent) that is no longer
maintained. The new version retains the original table-based approach,
but reduces the complexity of deployment and code. It no longer
supports interfacing to osquery. Both Zeek Agent versions supersede
[an earlier osquery extension](https://github.com/zeek/zeek-osquery)
for Zeek that focused on providing osquery's tables to Zeek.
