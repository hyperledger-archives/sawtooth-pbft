# Sawtooth PBFT

This repository contains an implementation of the Practical Byzantine Fault
Tolerant (PBFT) consensus algorithm for Hyperledger Sawtooth.

## Status
This project is in a highly experimental stage - there is a *significant* amount
of work to be done before it is ready to be deployed in a production context.
**Please beware that this repository may change often.**

The proposal for its inclusion in Sawtooth is located in [the associated
RFC](https://github.com/bridger-herman/sawtooth-rfcs/blob/pbft-consensus/text/0000-pbft-consensus.md).


## About PBFT
[PBFT](https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html)
(Practical Byzantine Fault Tolerance) is a Byzantine
fault-tolerant consensus algorithm that was pioneered by Miguel Castro and
Barbara Liskov in 1999. PBFT is designed to tolerate nodes in a distributed
network failing, and sending incorrect messages to other nodes, as long as
fewer than one-third of the nodes are considered faulty. PBFT networks need a
minimum of four nodes to be Byzantine fault-tolerant.

This implementation is based around the algorithm described in that paper, and
adapted for use in Hyperledger Sawtooth. It uses the experimental Consensus
API that is loosely described by [this
RFC](https://github.com/aludvik/sawtooth-rfcs/blob/consensus/text/0000-consensus-api.md).

Note that this project uses the terms "primary" and "secondary" to refer to
the role of nodes in the network, which differs slightly from the terminology
used in the PBFT paper. "Primary" is synonymous with "leader," and "secondary"
is synonymous with "follower," and "backup." "Node" is synonymous with
"server" and "replica."

## Motivation
Sawtooth currently only supports PoET consensus (although other algorithms
like [Raft](https://github.com/hyperledger/sawtooth-raft) are currently under
development). PoET is only crash fault tolerant, so if any nodes in the
network exhibit [Byzantine
behaviour](https://en.wikipedia.org/wiki/Byzantine_fault_tolerance#Byzantine_Generals'_Problem),
it causes issues with consensus.


## Features
The following features have been implemented:

+ [x] **Normal case operation:** Handling transactions when the network is functioning normally
+ [x] **View changes:** When a primary node is considered faulty (crashed or
  malicious), the network changes views and a new primary is elected.
+ [x] **Log garbage collection:** Every so often, message logs should be garbage
  collected so as to not take up too much space.
+ [x] **Testing improvements:** Presently, a liveness test up to 55 blocks has
  been performed on a network of four nodes. Unit tests are also included for
  each individual component of the algorithm.

The following features are desired (not a comprehensive list):
+ [ ] **Allow network changes:** Right now, the network is assumed to be
  static. Peers are introduced through on-chain settings, and the peer list
  does not change during network operation.
+ [ ] **Persistent storage:** Nodes should be able to recover from crashes by
  saving their logs in persistent storage instead of keeping everything in
  memory
+ [ ] **Documentation:** Use existing Sawtooth doc generation to create
  documentation for this project

## Running PBFT

+ Clone this repo:
  `git clone https://github.com/bridger-herman/sawtooth-pbft.git`
  and checkout the branch you're interested in (probably `unit-tests`)
+ Run the following commands:

Use the following steps to start a four-node network and run a liveness
test:

1.  Clone the PBFT repo:
    `git clone https://github.com/bitwiseio/sawtooth-pbft.git`

2.  Run the following commands to connect to the `sawtooth-dev-pbft`
    interactive shell:

    ```
    cd sawtooth-pbft

    docker build . -f Dockerfile -t sawtooth-dev-pbft

    docker run -v $(pwd):/project/sawtooth-pbft -it sawtooth-dev-pbft bash

    # You can optionally use this to speed up your build times, if you have a cargo-registry Docker volume set up:
    docker run -v $(pwd):/project/sawtooth-pbft -v cargo-registry:/root/.cargo/registry -it sawtooth-dev-pbft bash
    ```

3.  Once you have the `sawtooth-dev-pbft` interactive shell up, run:

    ```
    cargo build
    ```

4.  Once the project finishes building, exit the interactive shell and
    run

    ```
    tests/pbft.sh
    ```

This script first builds a few docker images, then starts up a network of four
nodes and goes through a liveness test of 55 blocks (using the Docker Compose
file `test_liveness.yaml`). The default log level is `INFO`, so it prints out
quite a bit of information as the algorithm executes. All of the on-chain
settings (such as block duration and view change timeout) can be adjusted
inside of the file `tests/test_liveness.yaml`, as well as the log level for
each of the services in the network.

If you'd like to specify a different Docker Compose file to use (such as
`grafana.yaml`, `client.yaml`, or `pbft_unit_tests.yaml`), provide `pbft.sh`
with an additional argument:

```
tests/pbft.sh pbft_unit_tests
```

If you'd like to pass additional arguments to Docker Compose, they go
after the compose file you're using:

```
tests/pbft.sh client --abort-on-container-exit
```
