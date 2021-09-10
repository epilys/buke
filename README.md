# `buke` full text search manpages

- `cargo run --release -- --build` builds an sqlite3 database out of all manpages in your `$MANPATH`
- `cargo run --release -- "query"` searches for "query" in the index

The `sqlite3` C bindings were generated with `bindgen`. The sqlite3 database is gzipped with a custom [`VFS` layer](https://sqlite.org/vfs.html) extension located in [`src/db/vfs.rs`](./src/db/vfs.rs).

The gzip version is 38MiB compared to 117MiB uncompressed.

```shell
% ./target/release/buke socket
systemd-socket-proxyd.8         - systemd-socket-proxyd - Bidirectionally proxy local soc
socket.7                        - socket - Linux socket interface
systemd.socket.5                - systemd.socket - Socket unit configuration
systemd-socket-activate.1       - systemd-socket-activate - Test socket activation of dae
socketcall.2                    - socketcall - socket system calls
socket.2                        - socket - create an endpoint for communication
dbus-cleanup-sockets.1          - dbus-cleanup-sockets - clean up leftover sockets in a d
socketpair.2                    - socketpair - create a pair of connected sockets
modbus_set_socket.3             - modbus_set_socket - set socket of the context
tipc-socket.8                   - tipc-socket - show TIPC socket (port) information
modbus_get_socket.3             - modbus_get_socket - get the current socket of the conte
socketmap_table.5               - socketmap_table - Postfix socketmap table lookup client
systemd-journald.socket.8       - systemd-journald.service, systemd-journald.socket, syst
systemd-journald@.socket.8      - systemd-journald.service, systemd-journald.socket, syst
systemd-journald-audit.socket.8 - systemd-journald.service, systemd-journald.socket, syst

content matches:
packet.7    - packet - packet interface on device level
unix.7      - unix - sockets for local interprocess communication
raw.7       - raw - Linux IPv4 raw sockets
connect.2   - connect - initiate a connection on a socket
ss.8        - ss - another utility to investigate sockets
udp.7       - udp - User Datagram Protocol for IPv4
netstat.8   - netstat - Print network connections, routing tables, in
sock_diag.7 - sock_diag - obtaining information about sockets
vsock.7     - vsock - Linux VSOCK address family
```

Regular expression match if build with `re` feature (default) or if your sqlite3 version includes a `REGEXP` implementation:

```shell
% target/release/buke -r 'system_[^_]*_types'
system_data_types.7 - system_data_types - overview of system data types

content matches:
FILE.3      - system_data_types - overview of system data types
time_t.3    - system_data_types - overview of system data types
fenv_t.3    - system_data_types - overview of system data types
uint64_t.3  - system_data_types - overview of system data types
va_list.3   - system_data_types - overview of system data types
dev_t.3     - system_data_types - overview of system data types
size_t.3    - system_data_types - overview of system data types
float_t.3   - system_data_types - overview of system data types
uintN_t.3   - system_data_types - overview of system data types
ptrdiff_t.3 - system_data_types - overview of system data types
int16_t.3   - system_data_types - overview of system data types
ftm.7       - feature_test_macros - feature test macros
clockid_t.3 - system_data_types - overview of system data types
off_t.3     - system_data_types - overview of system data types
div_t.3     - system_data_types - overview of system data types
```
