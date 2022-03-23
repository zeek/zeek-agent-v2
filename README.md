# Zeek Agent

![Zeek Agent deployment overview](/auxil/zeek-agent.png)
![Zeek Agent log example](/auxil/log-example.png)

The *Zeek Agent* is an endpoint agent that sends host information to
[Zeek](http://zeek.org) for central monitoring. Inside Zeek, the host
activity—such as current processes, open sockets, or the list of users
on the system—shows up as script-layer events, just as network
activity does. Zeek and its agents communicate through
[Broker](https://docs.zeek.org/projects/broker), Zeek's standard
communication library.

We provide a [script package for
Zeek](https://github.com/zeek-packages/zeek-agent-v2) that adds a
number of new log files to Zeek recording endpoint information
received from agents. The package also provides an API to custom
scripts for controlling agents and processing the events they send.

This is a new version of the Zeek Agent that supersedes a couple of
older implementations (see the [history](#history)). It remains
experimental and in development for now, but we're working on making
it stable. We are interested in any feedback you may have.

#### Contents
<!-- begin table of contents -->
- [Getting Started](#getting-started)
    - [Zeek Agent](#zeek-agent)
    - [Zeek Package](#zeek-package)
- [Zeek API](#zeek-api)
- [Interactive Usage](#interactive-usage)
- [Table Reference](#table-reference)
- [Status](#status)
- [Getting in Touch](#getting-in-touch)
- [License](#license)
- [History](#history)
<!-- end table of contents -->

## Getting Started

### Zeek Agent

#### Prerequisites

- The agent currently supports Linux and macOS systems; Windows
  support is planned.

- There are no hard dependencies on the endpoints beyond standard
  system libraries. (Individual tables may not be available if they
  don't find on the system what they need.)


#### Download & Installation

On our [releases
page](https://github.com/zeek/zeek-agent-v2/releases), you will find
pre-built agent versions for:

- **Linux**: We are providing static binaries that work on all recent
  x86_64 systems.

- **macOS**: We are providing signed binaries that work on Big Sur and newer.

To build the agent yourself, download the source distribution for the
current release, or clone the code directly from git (make sure to include
submodules through `--recursive`). Then run:

    # ./configure [<options>] && make -j 4 && make test && make install

Selected `configure` options (see `--help` for more):

- `--prefix=<path>`: installation prefix
- `--with-openssl=<path>`: path to OpenSSL installation.

On macOS with Homebrew, use `--with-openssl={/usr/local,/opt/homebrew}/opt/openssl@1.1`

#### Usage

On all endpoints, run as `root`:

```
# zeek-agent -z <hostname-of-you-Zeek-system>
```

### Zeek Package

#### Prerequisites

- The agent's Zeek package requires Zeek 4.0 or newer.

- For a standard installation, make sure you have the Zeek package
  manager available and configured. You may need to run `eval $(zkg
  env)` to set up environment variables correctly. See the package
  manager's [Quickstart
  Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
  for more.

#### Installation

```
# zkg refresh
# zkg install zeek-agent-v2
```

#### Usage

Run Zeek:

```
# zeek zeek-agent-v2
```

You should now see new log files recording endpoint activity:

- `zeek-agent-files.log`: Records changes to list of files existing on endpoints.
- `zeek-agent-processes.log:` Records changes to processes running on endpoints.
- `zeek-agent-sockets.log:` Records changes to network sockets open on endpoints.
- `zeek-agent-ssh-authorized-keys.log`: Records changes to users' `authorized_keys` installed for SSH on endpoints.
- `zeek-agent-ssh-configs.log`: Records changes to `sshd` configuration options.
- `zeek-agent-system-logs.log:` Records messages recorded by operating systems.
- `zeek-agent-users.log:`: Records changes to users available on endpoints.

You will also find a new `zeek-agent.log` tracking agent connectivity.

## Zeek API

[More to come here.]

## Interactive Usage

The Zeek Agent provides an interactive console to explore the data it
provides through SQL queries:

```
# zeek-agent -i

Welcome to Zeek Agent v2.

Enter query or command to execute. Type `.help` for help, and `.quit` for exit.

> .tables
       Name                          Description
------------------  ----------------------------------------------
   files_lines               line of selected ASCII files
    files_list           file system paths matching a pattern
    processes                     current processes
     sockets                     open network sockets
system_logs_events  log messages recorded by the operating systems
      users                         user accounts
    zeek_agent                  Zeek Agent information

> SELECT * FROM sockets WHERE process = "zeek"
 pid   process  family  protocol  local_port  remote_port   local_addr    remote_addr  state
-----  -------  ------  --------  ----------  -----------  -------------  -----------  ------
72892   zeek     IPv4      17       65059         53       192.168.7.212    1.1.1.2    (null)
72892   zeek     IPv6      6         9999          0            ::            ::       LISTEN
```

The output of such SQL queries is what gets sent to Zeek as events.
More documentation on that forthcoming.

## Table Reference

<!-- begin table reference -->
<details>
<summary><tt>files_columns:</tt> columns extracted from selected ASCII files [Linux, macOS]</summary><br />

The table returns columns extracted from selected ASCII files
as a Zeek record of correspoding field values. At the time of
query, the table reads in all relevant files line by line. It
then splits each line into columns based on a delimiter string
and returns the columns of interest.

The files to read are specified through the 1st table parameter, which
is a glob matching all relevant paths.

The columns to extract from each line are specified through the 2nd
table parameter, which is a string containing a comma-separated list
of tuples `$<N>:<type>`, where `<N>` is a column number (`$1` being
the 1st column, `$2` the 2nd, etc.); and `<type>` is the type as which
the value in that column will be parsed. Types can be: `blob`,
`count`, int`, `real`, `text`. (As a special case, the column `$0`
refers to whole line, without any processing.)

The column separator is specified by the 3rd table parameter. It can
be either left empty for splitting on white-space, or a string to
search for. If empty (which is the default), any whitespace at the
beginning and end of a line is ignored as well.

Finally, a 4th table parameter specifies a regular expression matching
lines that are to be ignored. By default, this is set to lines
starting with common comment prefixes (`#`, `;`). If this parameter is
set to an empty string, no lines will be ignored.

In the query result, `columns` will contain a JSON array with the
selected values for each line. On the Zeek-side, this array will roll
out into a Zeek `record`.

Here's an example: `SELECT columns from files_columns("/etc/passwd",
"$1:text,$3:count", ":")` splits `/etc/passwd` into its parts, and
extracts the user name and ID for each line.

| Parameter | Type | Description | Default
| --- | --- | --- | --- |
| `pattern` | text | glob matching all files of interest |  |
| `columns` | text | specification of columns to extract |  |
| `separator` | text | separator string to split columns; empty for whitespace | `""` |
| `ignore` | text | regular expression matching lines to ignore; empty to disable | `^[ \t]*([#;]|$)` |

| Column | Type | Description
| --- | --- | --- |
| `path` | text | absolute path |
| `number` | count | line number in source file |
| `columns` | record | extracted columns |
</details>

<details>
<summary><tt>files_lines:</tt> lines extracted from selected ASCII files [Linux, macOS]</summary><br />

The table returns lines from selected ASCII files as table
rows. The files of interest get specified through a mandatory
table parameter. At the time of query, the table reads in all
matching files and returns one row per line, with any
leading/trailing whitespace stripped. For example, `SELECT *
FROM files_lines("/home/*/.ssh/authorized_keys")`, will return
any SSH keys that users have authorized to access their
accounts.`

| Parameter | Type | Description | Default
| --- | --- | --- | --- |
| `pattern` | text | glob matching all files of interest |  |

| Column | Type | Description
| --- | --- | --- |
| `path` | text | absolute path |
| `number` | count | line number |
| `content` | blob | content of line |
</details>

<details>
<summary><tt>files_list:</tt> file system paths matching a pattern [Linux, macOS]</summary><br />

The table provides a list of all files on the endpoint's file
system that match a custom glob pattern. The pattern gets
specified through a mandatory table parameter. For example, on
a traditional Linux system, `SELECT * from
files_list("/etc/init.d/*")` will fill the table with all files
inside that directory. If you then watch for changes to that
list, you'll be notified for any changes in system services.

The list of files is generated at query time. The `pattern` glob needs
to match on absolute file paths.

| Parameter | Type | Description | Default
| --- | --- | --- | --- |
| `pattern` | text | glob matching all files of interest |  |

| Column | Type | Description
| --- | --- | --- |
| `path` | text | full path |
| `type` | text | textual description of the path's type (e.g., `file`, `dir`, `socket`) |
| `uid` | count | ID of user owning file |
| `gid` | count | ID if group owning file |
| `mode` | text | octal permission mode |
| `mtime` | time | time of last modification |
| `size` | count | file size in bytes |
</details>

<details>
<summary><tt>processes:</tt> current processes [Linux, macOS]</summary><br />

The table provides a list of all processes that are running on
the endpoint at the time of the query.

| Column | Type | Description
| --- | --- | --- |
| `name` | text | name of process |
| `pid` | count | process ID |
| `ppid` | count | parent's process ID |
| `uid` | count | effective user ID |
| `gid` | count | effective group ID |
| `ruid` | count | real user ID |
| `rgid` | count | real group ID |
| `priority` | int | process priority (higher is more) |
| `startup` | interval | time process started |
| `vsize` | count | virtual memory size |
| `rsize` | count | resident memory size |
| `utime` | interval | user CPU time |
| `stime` | interval | system CPU time |
</details>

<details>
<summary><tt>sockets:</tt> open network sockets [Linux, macOS]</summary><br />

The table provides a list of all IP sockets that are open on
the endpoint at the time of the query.

| Column | Type | Description
| --- | --- | --- |
| `pid` | count | ID of process holding socket |
| `process` | text | name of process holding socket |
| `family` | text | `IPv4` or `IPv6` |
| `protocol` | count | transport protocol |
| `local_addr` | address | local IP address |
| `local_port` | count | local port number |
| `remote_addr` | address | remote IP address |
| `remote_port` | count | remote port number |
| `state` | text | state of socket |
</details>

<details>
<summary><tt>system_logs_events:</tt> log messages recorded by the operating systems [Linux, macOS]</summary><br />

The table provides access to log messages recorded by the
operating system.

On Linux, the table requires `systemd` and hooks into its journal.

On macOS, the tables hooks into the unified logging system (`OSLog`).

This is an evented table that captures log messages as they appear.
New messages will be returned with the next query.

| Column | Type | Description
| --- | --- | --- |
| `time` | time | timestamp |
| `process` | text | process name |
| `level` | text | severity level |
| `message` | text | log message |
</details>

<details>
<summary><tt>users:</tt> user accounts [Linux, macOS]</summary><br />

The table provides a list of all user accounts that exist on
the endpoint, retrieved at the time of the query from the
operating system.

| Column | Type | Description
| --- | --- | --- |
| `name` | text | short name |
| `full_name` | text | full name |
| `is_admin` | bool | 1 if user has adminstrative privileges |
| `is_system` | bool | 1 if user correponds to OS service |
| `uid` | count | user ID |
| `gid` | count | group ID |
| `home` | text | path to home directory |
| `shell` | text | path to default shell |
| `email` | text | email address |
</details>

<details>
<summary><tt>zeek_agent:</tt> Zeek Agent information [Linux, macOS]</summary><br />

An internal table providing information about the Zeek
Agent process and the endpoint it's running on.

| Column | Type | Description
| --- | --- | --- |
| `id` | text | unique agent ID (stable across restarts) |
| `instance` | text | unique ID for agent process (reset on restart) |
| `hostname` | text | name of endpoint |
| `addresses` | set | IP addresses of endpoint's primary network connection |
| `platform` | text | `Darwin` or `Linux` |
| `os_name` | text | name of operating system |
| `kernel_name` | text | name of OS kernel |
| `kernel_version` | text | version of OS kernel |
| `kernel_arch` | text | build architecture |
| `agent_version` | count | agent version |
| `broker` | text | Broker version |
| `uptime` | interval | agent uptime |
| `tables` | set | tables available to queries |
</details>

<!-- end table reference -->

## Status

- The agent remains experimental for now, and APIs and table schemas
  are still evolving. Specifics may still change without much notice.

- The supply of tables and Zeek logs is still limited; we are
  planning to add more in the future (contributions welcome!).

- Currently, most data is collected in regular intervals only, meaning
  that short-lived activity happening between the agent’s regular
  snapshots might be missed (e.g., a process terminating quickly after
  it started up). The agent’s internal infrastructure already supports
  “event tables” that don’t have that limitation, and we plan to make
  more use of that in the future. Doing so typically requires usage of
  OS-specific APIs, which makes these tables more complex to
  implement.

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
