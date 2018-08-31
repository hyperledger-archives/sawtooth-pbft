*****************************
Introduction to Sawtooth PBFT
*****************************

This guide describes a practical Byzantine fault tolerant (PBFT) consensus
algorithm for `Hyperledger Sawtooth
<https://github.com/hyperledger/sawtooth-core>`__.

The Sawtooth PBFT algorithm is a voting-based consensus mechanism with
Byzantine fault tolerance. This algorithm ensures `safety and liveness
<https://en.wikipedia.org/wiki/Liveness#Liveness_and_safety>`__ of a network,
provided at most :math:`\lfloor \frac{n - 1}{3} \rfloor` nodes are faulty, where
:math:`n` is the total number of nodes in the network. The Sawtooth PBFT
algorithm is also inherently crash fault tolerant. Another advantage of PBFT
is that blocks committed by nodes are final, so there are no forks in the
network. This is verified by a "Consensus Seal," which is appended to blocks
when they are finalized and checked upon receipt of a new block


About PBFT
==========

`Practical Byzantine Fault Tolerance
<https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html>`__,
a paper written in 1999 by Miguel Castro and Barbara Liskov, describes a
consensus algorithm that solves the `Byzantine Generals Problem
<https://en.wikipedia.org/wiki/Byzantine_fault_tolerance#Byzantine_Generals'_Problem>`__,
while still remaining computationally feasible. This implementation of PBFT
consensus for Hyperledger Sawtooth is based off the methodology described in
the 1999 paper, and adapted for use in a blockchain context.

PBFT is a *voting* consensus algorithm, meaning:

- Only a single node (the primary) can commit blocks to the chain at any given time
- One or more nodes in the network maintains a global view of the network
- Adding and removing nodes from the network is difficult
- There are many peer-to-peer messages passed in between nodes which
  specifically relate to consensus (see `Peer Messages
  <technical-information.html#peer-messages>`__)


PBFT extensively uses the concept of `state machine replication
<https://en.wikipedia.org/wiki/State_machine_replication>`__.  The generic
(non-blockchain-specific) algorithm works as follows:

1. A client sends a message (request) to all the nodes in the network
2. A series of messages is sent between nodes to determine if the request is
   valid, or has been tampered with.
3. Once a number of nodes agree that the request is valid, then the
   instructions (operations) in the request are executed, and a result (reply)
   is returned to the client.
4. The client waits for a number of replies that match, then accepts the
   result.


Sawtooth Consensus API
======================

Sawtooth PBFT uses the experimental `Consensus API
<https://github.com/aludvik/sawtooth-rfcs/blob/500b3688acfb0cd4834ea6451a8c5e000f7f5174/text/0000-consensus-api.md>`__.
The Consensus API abstracts out interactions with the validator, and only
provides the consensus engine information necessary to the consensus process.

See `Normal Mode Operation <algorithm-operation.html#normal-mode>`__ for more
details on how the actual algorithm works on the blockchain.

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
