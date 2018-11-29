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
adapted for use in Hyperledger Sawtooth. It uses the Sawtooth Consensus API that
is described by [this
RFC](https://github.com/hyperledger/sawtooth-rfcs/blob/master/text/0000-consensus-api.md).

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
