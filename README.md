# dbgor

This is an interactive tool to help with debugging connectivity issues on the Tor network.
It consists of an RPC server which runs an Arti Tor client,
and an RPC client to run commands on the Arti client.

This is a work-in-progress and still has many rough edges.
It was written for my own personal use,
but maybe other people will find it useful.
Feel free to open issues for bugs or feature requests,
but this is a personal project and is not actively maintained.

### Installation

You must have a recent [rust/cargo][rust] toolchain installed.

This is published to [crates.io][crates-io] mainly to prevent a malicious package
from masquerading as this one while using the same name.
It's recommended to build or install from the latest development version instead.

```bash
# install the latest release from crates.io
cargo install dbgor

# install the latest development version
git clone https://github.com/stevenengler/dbgor.git
cargo install --path dbgor
```

[rust]: https://www.rust-lang.org/tools/install
[crates-io]: https://crates.io/

### Examples

```bash
# Start the server.
dbgor server

# Build a circuit with one hop to a relay with the nickname "foo".
dbgor circ-new name:foo

# Build a circuit with multiple hops.
dbgor circ-new name:foo addr:192.0.2.10:5001

# Build a circuit to the relay with the given RSA identity.
dbgor circ-new rsa:4EBB385C80A2CA5D671E16F1C722FBFB5F176891

# Build a "RELAY_FAST" circuit to a relay which might not be in the consensus.
dbgor circ-new fast:192.0.2.20:443,rsa:0A9B1B207FD13A6F117F95CAFA358EEE2234F19A

# Build an "ntor" circuit to a relay which might not be in the consensus.
dbgor circ-new complete:192.0.2.30:9001,ed25519:qpL/LxLYVEXghU76iG3LsSI/UW7MBpIROZK0AB18560,QeRbF/o8G6udG72u/OJiSXW7eW6HzfYZpu8tQFyqVUE

# Extend circuit "c1" by one hop to a relay with the nickname "foo".
dbgor circ-extend c1 name:foo

# Extend circuit "c1" by multiple hops.
dbgor circ-extend c1 name:foo addr:192.0.2.10:5001

# Show information about circuit "c1".
dbgor circ-info c1

# Resolve hostname "torproject.org" by the last hop of circuit "c1".
dbgor circ-resolve c1 torproject.org

# Make an HTTP request to example.com over circuit "c1".
dbgor circ-bind c1 127.0.0.1:9070 example.com 80
curl --header 'Host: example.com' 127.0.0.1:9070

# Release circuit "c1".
dbgor circ-release c1

# List all circuits.
dbgor circ-list
```
