***********
Future Work
***********

While this implementation of PBFT is a functional prototype, there is still
work to be done before it can be considered production-ready. Most of the
production-readiness preparations involve changes within the PBFT algorithm,
but some modifications require new features to be added to `Sawtooth
<https://github.com/hyperledger/sawtooth-core>`__.


Consensus Seal
==============

One small item that still needs to be implemented is the block "consensus
seal." This contains a hash of all of the :math:`2f + 1` ``Commit`` messages a
node has received, and possibly more data relevant to consensus. The consensus
seal is attached to blocks by providing the Consensus API's
``finalize_block()`` method with the bytes of the hash described above. In the
source, this would get inserted in the ``try_publish()`` `method inside the
node
<https://github.com/bitwiseio/sawtooth-pbft/blob/master/src/node.rs#L455>`__.

Additionally, every time a ``BlockNew`` update is received, this consensus
seal must be checked to make sure it is consistent with the ``Commit``
messages this node received during the last iteration of the algorithm. If it
is inconsistent, then this means the primary is faulty, and a ``ViewChange``
must be performed. In the source, this check would occur inside the
``block_new()`` `method inside the node
<https://github.com/bitwiseio/sawtooth-pbft/blob/master/src/node.rs#L328>`__.


Batch-Level Consensus
=====================

Perhaps the most pressing of the production-readiness concerns is the fact
that in its current state, PBFT can only be Byzantine fault tolerant on a
block level. For most use cases, this is insufficient, because consensus on
the batches inside of the blocks matters as well. Presently, if a network
arrives at consensus on a block, there is no way to ensure that the
transactions inside of the block are actually in the correct order, thus
giving a faulty (malicious or malfunctioning) node the power to reorder
transactions as it pleases.

The root cause for this stems from a lack of information provided by the
Consensus API. In order to be truly Byzantine fault tolerant, PBFT must have
access to the ordering of batches inside of the block, not just the blocks
themselves. Currently, the Consensus API does not provide any visibility about
batches inside the blocks, so it can’t be confirmed that all blocks indeed
have the same batch list ordering.

One possible solution to this would be for the validator to package the batch
list inside the block it sends to the PBFT algorithm. It is likely that the
whole batch list is not necessary; a hash of it would probably be sufficient
to ensure that the ordering of batches inside blocks matches. If this is
indeed the case, then only two modifications need to be made:

- Add the batch list to the consensus blocks in the Sawtooth validator

- Add batch list verification to the PBFT algorithm (one more verification
  step after checking view and sequence number)


Message Signing
===============

Currently, PBFT-related peer messages are not encrypted or signed by the
consensus algorithm. This allows faulty nodes to easily send messages as
another node, simply by changing the sender field in the Protobuf message. In
order to ensure that messages originated from the node they say they did, it
will be necessary to have nodes sign each message before broadcasting it.


Concurrency
===========

In this PBFT implementation, consensus operates entirely serially. That is,
there is only one block undergoing consensus at any given time. If a
``BlockNew`` is received for a block greater than the next expected block, it
is pushed into a block backlog, to be processed later. One area for potential
improvement here is to perform speculative consensus:

- Receive ``BlockNew`` for block 1

- Start consensus process for block 1

- Receive ``BlockNew`` for block 2

- Start consensus process for block 2, while still performing consensus for
  block 1

- Block 1 passes consensus - commit block

- Block 2 passes consensus - commit block

If block 1 failed consensus, then block 2 consensus would be aborted, and also
fail. If block 2 passed consensus before block 1, then it would be pushed to a
committing backlog and wait until block 1 passes consensus.


Dynamic Networking
==================

Right now, only static consensus networks are supported. The public keys of
all validators on the network must be provided as a command line argument,
which is transferred into the on-chain setting
``sawtooth.consensus.pbft.peers``. This is certainly not ideal, because in a
production context, the network could change at any time. Fortunately, the
Consensus API has updates that are specifically made for handling network
changes: ``PeerConnected`` and ``PeerDisconnected``.

There is a prototype of a dynamic PBFT network on the branch
``dynamic-networking`` in the `PBFT repository
<https://github.com/bitwiseio/sawtooth-pbft/tree/dynamic-networking>`__. The
prototype uses the following procedures to handle connectivity changes:

**Adding a peer:**

- The first node on the network is the primary.

- Every node starts out in ``Connecting`` mode; no updates besides
  ``PeerConnected`` and ``PeerDisconnected`` are processed. When each
  connection message is received, every node starts a ``ViewChange`` timer.

- Once the primary node has enough peers to be Byzantine fault tolerant, then
  it broadcasts a tentative ``PbftNetworkChange`` message.  Other nodes
  receive this message, and verify that the peers contained in the message are
  the same as the ones in its peer list. Once this is verified, the node
  broadcasts a final ``PbftNetworkChange`` with that peer list.

- Upon receipt of :math:`2f + 1` ``PbftNetworkChange`` messages, the node
  accepts the peer list contained in the message, and updates its view, and
  sequence number based on those in the message information. It stops the
  ``ViewChange`` timer, and enters ``Normal`` execution mode.

- If this node’s chain head is behind the chain head from the message, then it
  begins the process of committing all the blocks between its head and the
  primary’s chain head. These blocks do not need to undergo consensus again;
  they’re on the chain, and thus are final.

**Removing a peer:** (see note below)

- Peer is removed from this node’s local peer list

- If this change makes the network no longer byzantine fault tolerant, then
  the node re-enters ``Connecting`` mode and waits for another connection. If
  the network is in the middle of a block consensus process, it is paused
  until the network has come to consensus on this network change.

- Primary sends out a tentative ``PbftNetworkChange``, and a similar process
  to **Adding a peer** is executed.

**Message type definition:**

.. code-block:: protobuf

   // Represents the current state of the network, including the active nodes,
   // and the current block.
   message PbftNetworkChange {
     // The peers in this network configuration
     repeated bytes peers = 1;

     // The current block that the network is on - used to help nodes catch back
     // up to the current chain head after they've been offline
     PbftBlock head = 2;

     // Does this message represent a tentative configuration, or a final
     // configuration?
     bool tentative = 3;

     bytes signer_id = 4;

     PbftMessageInfo info = 5;
   }

One thing to note about this prototype implementation is that only dynamic
network additions are supported, not network removals. This is primarily due
to the fact that the Sawtooth validator does not reliably provide information
about when nodes disconnect from the network. It is left up to the node
disconnecting to send its own ``PeerDisconnected`` update, but oftentimes if a
validator disconnects, it's due to a crash (so it doesn't send the update).

One possible solution to this problem is for each validator to keep track of
the last time that it heard from each node in the network. Validators already
do this, and send heartbeat pings if they haven't heard from a node in a
while. In this case, it would be possible for other nodes on the network to
send a ``PeerDisconnected`` update on the behalf of the node that died.

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
