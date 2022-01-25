# Zeek Agent README

The Zeek Agent sends host information from endpoints to
[Zeek](http://zeek.org) for central monitoring. Inside Zeek's
scripting language, the host activity shows up as events, just as
network activity does. A Zeek-side [Zeek Agent
package](https://github.com/zeek-packages/zeek-agent-v2) provides
scripts with an API to control agents and process their information.
That package also adds new log files to Zeek that records host
activity to disk.

This is a new version of the Zeek Agent that supersedes a couple of
older implementations (see the [history](#history)). It remains
experimental and in development for now, but we're working on making
it stable. We are interested in any feedback you may have.

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
- [Getting in Touch](#getting-in-touch)
- [License](#license)
- [History](#history)

<!-- end table of contents -->

## Getting Started

### Prerequisites

- The agent currently supports Linux and macOS; Windows support is
  planned. There are no hard dependencies on the endpoints beyond
  standard system libraries. (Individual tables may not be available
  if they don't find what they need.)

- The agent’s Zeek package requires Zeek 4.0 or newer.

### Installation

- Linux: We are providing a static binary that should run on most
  distributions:

    - Download [zeek-agent for
      Linux](https://nightly.link/zeek/zeek-agent-v2/workflows/main/main/zeek-agent-2.0.0-pre-linux-x86_64.tar.gz.zip).

- macOS: We are providing a binary that works on Big Sur and newer:

    - Download [zeek-agent for macOS](https://nightly.link/zeek/zeek-agent-v2/workflows/main/main/zeek-agent-2.0.0-pre-macos11.dmg.zip).

    - We don't sign the binaries yet, so you may need to remove the
      quarantine bit after downloading before you can run it: `xattr
      -r -d com.apple.quarantine bin/zeek-agent`.

You can alternatively compile the agent from source yourself:

```
# git clone --recursive https://github.com/zeek/zeek-agent-v2
# cd zeek-agent-v2
# ./configure [<options>] && make -j 4 && make test && make install
```

Selected `configure` options:

- `--prefix=<path>`: installation prefix
- `--with-openssl=<path>`: path to OpenSSL installation.

On macOS with Homebrew, use `--with-openssl={/usr/local,/opt/homebrew}/opt/openssl@1.1`

### Zeek Package

```
# zkg refresh
# zkg install zeek-agent-v2
```

Make sure you have Zeek configured to use the `zkg` package manager.
You may need to run `eval $(zkg env)` to set up environment variables
correctly. See the package manager's [Quickstart
Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
for more.

### Usage


Start Zeek:

```
# zeek zeek-agent-v2
```

On all endpoints, run as `root`:

```
# zeek-agent -z <hostname-where-zeek-runs>
```

You should now see new log files recording endpoint activity:

- `zeek-agent-users.log`: Users available on endpoints.
- `zeek-agent-processes.log`: Processes running on endpoints.
- [more to come]

You will also find a new `zeek-agent.log` tracking agent connectivity.

## Zeek API

[More to come here.]

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

- The supply of tables and Zeek logs is currently limited; we are
  planning to add more in the future.

- Currently, most data is collected in regular intervals only, meaning
  that short-lived activity happening between the agent’s regular
  snapshots might be missed (e.g., a process terminating quickly after
  it started up). The agent’s internal infrastructure supports “event
  tables” that don’t have that limitation, and we plan to make more
  use of that in the future. Doing so typically requires usage of
  OS-specific APIs, which makes these tables more complex to
  implement.

## Versioning

We do not provide stable/tagged releases yet, there’s just a `main`
branch in Git; binaries are cut from there. We also still commit
directly to `main`, so things may occasionally break for a little
while. APIs and table schemas are still evolving as well and may
change without much notice.

We will move to more stable processes as the agent matures.

## Getting in Touch

Having trouble using the agent? Have ideas how to make the agent
better? We'd like to hear from you!

- Report problems on the [GitHub issue
  tracker](https://github.com/zeek/zeek-agent-v2/issues).

- Ask the `#zeek-agent` channel [on Zeek's
  Slack](https://zeek.org/connect).

## License

The Zeek Agent is open source and released under a BSD license, which
allows for pretty much unrestricted use as long as you leave the
license header in place.

## History

This Zeek Agent supersedes an older, [1st-generation
implementation](https://github.com/zeek/zeek-agent) that is no longer
maintained. The new version retains the original, table-based
approach, but reduces the complexity of deployment and code base. It
no longer supports interfacing to osquery (because that was a main
source of complexity). Both versions of the Zeek Agent also supersede
[an earlier osquery extension](https://github.com/zeek/zeek-osquery)
for Zeek that focused just on providing osquery's tables to Zeek.
