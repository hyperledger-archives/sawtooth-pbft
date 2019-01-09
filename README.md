# Sawtooth PBFT

This repository contains an implementation of the Practical Byzantine Fault
Tolerant (PBFT) consensus algorithm for Hyperledger Sawtooth.

## Status
This project is in a highly experimental stage - there is a *significant* amount
of work to be done before it is ready to be deployed in a production context.
**Please be aware that this repository might change often.**

The proposal to include PBFT in Sawtooth is located in [Sawtooth RFC
0019-pbft-consensus.md](https://github.com/hyperledger/sawtooth-rfcs/blob/master/text/0019-pbft-consensus.md).

## About PBFT
The PBFT algorithm was pioneered by Miguel Castro and Barbara Liskov in 1999, as
described in their paper [Practical Byzantine Fault
Tolerance](https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html).
PBFT is designed to tolerate the failure of nodes in a distributed network, as
well as nodes sending incorrect messages to other nodes, as long as fewer than
one-third of the nodes are considered faulty. PBFT networks need a minimum of
four nodes to be Byzantine fault tolerant.

The Sawtooth PBFT implementation is based on the algorithm described in that
paper, and is adapted for use in Hyperledger Sawtooth. Sawtooth PBFT uses the
Sawtooth consensus API that is described by [Sawtooth RFC
0004-consensus-api.md](https://github.com/hyperledger/sawtooth-rfcs/blob/master/text/0004-consensus-api.md).

Note that this project uses the terms "primary" and "secondary" to refer to
the role of nodes in the network, which differs slightly from the terminology
used in the PBFT paper.

- "Primary" is synonymous with "leader"
- "Secondary" is synonymous with "follower" and "backup"
- "Node" is synonymous with "server" and "replica"

## Motivation
PBFT was chosen as an algorithm for the new Sawtooth consensus API in
order to provide Byzantine fault tolerant consensus for a system without a
Trusted Execution Environment (TEE).

Sawtooth initially supported only PoET consensus, and the Byzantine fault
tolerant version (PoET-SGX) requires a Trusted Execution Environment (TEE).
PoET simulator (for systems without a TEE) is only crash fault tolerant, so if
any nodes in the network exhibit [Byzantine
behaviour](https://en.wikipedia.org/wiki/Byzantine_fault_tolerance#Byzantine_Generals'_Problem),
it causes issues with consensus.

## Documentation

- [Current Sawtooth PBFT documentation](https://sawtooth.hyperledger.org/docs/#sawtooth-pbft)

- [Rustdocs for Sawtooth PBFT](https://sawtooth.hyperledger.org/docs/pbft/nightly/master/pbft_doc/pbft_engine/index.html)

## License

Hyperledger Sawtooth software is licensed under the Apache License Version 2.0
software license.
