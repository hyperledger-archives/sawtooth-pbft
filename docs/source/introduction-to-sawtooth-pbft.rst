************
Introduction
************

Sawtooth PBFT is a consensus engine for Hyperledger Sawtooth that provides
practical Byzantine fault tolerance.

PBFT is a voting-based consensus algorithm that is:

* Byzantine fault tolerant: Network `liveness and safety
  <https://en.wikipedia.org/wiki/Liveness#Liveness_and_safety>`__
  are guaranteed even when some nodes are faulty or malicious, as long as a
  minimum percentage of nodes are connected, working properly, and behaving
  honestly.

* Non-forking: Blocks committed by nodes are final, unlike lottery-style
  consensus algorithms such as Proof of Work (PoW) or Proof of Elapsed Time
  (PoET).

* Leader-based: A `primary node` is responsible for producing candidate blocks;
  `secondary nodes` vote on the blocks produced by the primary. The leader
  changes in a round-robin (circular) order.

* Communication-intensive: Nodes send many messages to reach consensus, commit
  blocks, and maintain a healthy leader node.

A Sawtooth PBFT network does not support open enrollment, but nodes can be added
and removed by an administrator. Full peering is required (all nodes must be
connected to all other nodes). In order to provide Byzantine fault tolerance, a
PBFT network must have a least four nodes.

Sawtooth PBFT is based on the methodology described in
`Practical Byzantine Fault Tolerance
<https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html>`__
by Miguel Castro and Barbara Liskov.
This implementation has been adapted for use in a blockchain context; it
includes extensions such as regular `view changes` (leader changes) and
a `consensus seal` to verify block finality.

.. note::

   Sawtooth PBFT uses the terms "primary" and "secondary" to refer to the role
   of nodes in the network, which differs slightly from the terminology used in
   the PBFT paper.

   - "Primary" is synonymous with "leader"
   - "Secondary" is synonymous with "follower" and "backup"
   - "Node" is synonymous with "server" and "replica"

For implementation details, see the `rustdoc for Sawtooth PBFT
<https://sawtooth.hyperledger.org/docs/pbft/nightly/master/pbft_doc/pbft_engine/index.html>`__.


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
