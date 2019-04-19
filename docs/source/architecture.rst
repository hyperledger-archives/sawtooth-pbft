Architecture
************

The Sawtooth PBFT algorithm is a voting-based consensus algorithm with Byzantine
fault tolerance, which ensures `safety and liveness
<https://en.wikipedia.org/wiki/Liveness#Liveness_and_safety>`__.
The network can tolerate a certain number of "bad" nodes. As long as this number
is not exceeded, the network will work properly. In addition, blocks committed
by nodes are final, so there are no forks in the network.

The nodes on the network send many messages to reach consensus, commit blocks,
and maintain a healthy leader node, called a `primary node`. The network
switches to a new primary (called a `view change`) at regular intervals, as well
as when the current primary is faulty.

* The primary node builds and publishes blocks.

* The other nodes (called `secondary nodes`) vote on blocks and the health of
  the leader.

Sawtooth PBFT runs on each node in the network as a `consensus engine`, a
separate process that handles consensus-related functionality and communicates
with the validator through the consensus API.

The following sections describe Sawtooth PBFT architecture:

* :ref:`Network overview <network-overview-label>`: Describes PBFT fault
  tolerance, view changes, sequence numbers, and the information stored
  by each node

* :ref:`Consensus messages <consensus-messages-label>`: Explains consensus
  message structures and message types

* :ref:`Sawtooth PBFT operation <pbft-operation-label>`: Shows how the
  algorithm handles initialization, normal mode (block processing), and view
  changes

.. _network-overview-label:

Network Overview
================

Fault Tolerance
---------------

A PBFT network consists of nodes that are ordered from 0 to `n-1`, where
`n` is the total number of nodes in the network. The
:doc:`on-chain setting <on-chain-settings>` ``sawtooth.consensus.pbft.members``
lists all PBFT member nodes and determines the node order.

The PBFT algorithm guarantees network `safety
<https://en.wikipedia.org/wiki/Liveness#Liveness_and_safety>`__
as long as the number of faulty nodes remains below the required percentage.
The maximum number of faulty nodes that the network can tolerate is determined
by the formula :math:`f = \frac{n - 1}{3}`. In other words, no more than one
third of the nodes (rounded down) can be unreachable or dishonest at any given
time.

For example, a four-node network can tolerate one faulty node. (PBFT requires a
minimum of four nodes in order to maintain Byzantine fault tolerance.)
Increasing the size of the network reduces the likelihood that all
:math:`\frac{n - 1}{3}` nodes would be faulty at the same time.

.. _view-changes-choosing-primary-label:

View Changes: Choosing a New Primary
------------------------------------

A `view` is the period of time that a given node is the primary, so a `view
change` means switching to a different primary node. The next primary is
selected in a round-robin (circular) fashion, according to the order of nodes
listed in the :doc:`on-chain setting <on-chain-settings>`
``sawtooth.consensus.pbft.members``.

In a four-node network, for example, the first node (node 0) is the primary at
view 0, the second node (node 1) is the primary at view 1, and so on.  When the
network gets to view 4, it will return to node 0 as the primary.

The algorithm uses the formula `p = v mod n` to determine the next
primary. In this formula, `p` is the primary, `v` is the view number, and `n` is
the total number of nodes in the network. For example, if a four-node network is
at view 7, the formula `7 mod 4` determines that node 3 is the primary.

The Sawtooth PBFT algorithm changes the primary at regular intervals, as well as
when the secondary nodes determine that the current primary is faulty.
See :ref:`view-changing-mode-label` for a description of this process.

Sequence Numbers
----------------

In addition to moving through a series of views, the network moves through a
series of `sequence numbers`. In Sawtooth PBFT, a node's sequence number is
the same as the block number of the next block in the chain. For example, a node
that is on sequence number 10 has already committed block 9 and is evaluating
block 10.

Also, each message includes a sequence number that indicates which block the
message is for. For example, a message with sequence number 10 applies to block
number 10.

.. _node-storage-label:

Information Storage
-------------------

Each node stores several key pieces of information as part of its state:

* List of PBFT member nodes in the network (from
  ``sawtooth.consensus.pbft.members``)

* Current view number, which identifies the primary node

* Current sequence number, which is also the number of the block being processed

* The current head of the chain

* If in normal mode, the step of the algorithm it’s on
  (see :ref:`normal-mode-label`)

* Log of all blocks it has received

* Log of all messages it has received

.. _network-config-label:

Network Configuration
---------------------

Sawtooth PBFT configures the network with on-chain settings, which are processed
by the `Settings transaction processor
<https://sawtooth.hyperledger.org/docs/core/releases/latest/transaction_family_specifications/settings_transaction_family.html>`__ (or an equivalent).

These settings list each node in the network, set the view-change period (how
often the primary changes), and specify other items such as the block publishing
frequency, timeout periods, and message log size.
For more information, see :doc:`on-chain-settings`.


.. _consensus-messages-label:

Consensus Messages
==================

When a node receives a new consensus message from a member node, it checks the
message type and creates the appropriate language-specific object for that type.
All PBFT consensus messages are serialized as `protobufs (protocol buffers)
<https://developers.google.com/protocol-buffers/>`__.

Generally, the message object must be verified to make sure that everything is
legitimate. The PBFT algorithm handles consensus-related verification, such as
making sure that messages match and that there are the correct number of
messages.  The Sawtooth validator verifies the non-consensus parts of a message,
such as ensuring that the message has a valid signature.


Message Definitions
-------------------

Most Sawtooth PBFT messages use the ``PbftMessage`` message format, as shown
below. An auxiliary ``PbftViewChange`` format is used to request a view change
when a node suspects that the primary is faulty or unresponsive.

Sawtooth PBFT also uses some of the message types defined in the consensus API,
such as ``BlockNew`` and ``BlockCommit`` (as well as the system ``Shutdown``
message). These messages are called "updates" to distinguish them from the
consensus messages.

.. code-block:: protobuf

   // PBFT-specific block information (don't need to keep sending the whole payload
   // around the network)
   message PbftBlock {
     bytes block_id = 1;

     bytes signer_id = 2;

     uint64 block_num = 3;

     bytes summary = 4;
   }

   // Represents all common information used in a PBFT message
   message PbftMessageInfo {
     // Type of the message
     string msg_type = 1;

     // View number
     uint64 view = 2;

     // Sequence number (helps with ordering the log)
     uint64 seq_num = 3;

     // Node who signed the message
     bytes signer_id = 4;
   }

   // A generic PBFT message (PrePrepare, Prepare, Commit)
   message PbftMessage {
     // Message information
     PbftMessageInfo info = 1;

     // The actual message
     PbftBlock block = 2;
   }

   // View change message, for when a node suspects the primary node is faulty
   message PbftViewChange {
     // Message information
     PbftMessageInfo info = 1;
   }

Message Types
-------------

A Sawtooth PBFT message has one of the following types:

* ``PrePrepare``: Sent by the primary node when it has received a new block from
  the validator (as a ``BlockNew`` update).

* ``Prepare``: Broadcast from every node after a ``PrePrepare`` has been received
  for the current working block. This message is used to verify the ``PrePrepare``
  message and to signify that the block is ready to be checked.

* ``Commit``: Broadcast from every node after a ``BlockValid`` update has been
  received for the current working block. This message is used to determine if
  there is consensus for committing the current working block.

* ``ViewChange``: Sent by any node that suspects that the primary node is
  faulty. Sufficient ``ViewChange`` messages will trigger a view change.


.. _pbft-operation-label:

PBFT Operation
==============

The Sawtooth PBFT algorithm starts with initialization, then operates in one of
two modes:

* :ref:`Normal mode <normal-mode-label>` for processing blocks

* :ref:`View Changing mode <view-changing-mode-label>` for switching to a
  different primary node

.. note::

   The original PBFT definition includes a checkpointing procedure that is
   responsible for garbage collection of the log. Sawtooth PBFT does not
   implement this checkpointing procedure; instead, it cleans the log
   periodically during its normal operation. For more information, see
   :ref:`log-pruning-label`.


Initialization
--------------

When the Sawtooth PBFT consensus engine starts, it does the following:

* Loads its configuration

* Initializes its state and message log

* Establishes timers and counters for block durations and view changes,
  based on the on-chain settings


.. _normal-mode-label:

Normal Mode
-----------

In Normal mode, nodes check blocks and approve them to be committed to the
blockchain. The Sawtooth PBFT algorithm usually operates in normal mode unless a
:ref:`view change <view-changing-mode-label>` is necessary.


Procedure
^^^^^^^^^

The normal mode proceeds as follows:

1. All nodes begin in the ``PrePreparing`` phase; the purpose of this phase is
   for the primary to publish a new block and endorse the block with a
   ``PrePrepare`` message.

   - The primary node will send a request to its validator to initialize a new
     block. After a configurable timeout (determined by the
     ``sawtooth.consensus.pbft.block_duration`` setting), the primary will send
     a request to the validator to finalize the block and broadcast it to the
     network.

   - After receiving the block in a ``BlockNew`` update and ensuring that the
     block is valid, all nodes will store the block in their PBFT logs.

   - After receiving the ``BlockNew`` update, the primary will broadcast a
     ``PrePrepare`` message for that block to all of the nodes in the network.
     When the nodes receive this ``PrePrepare`` message, they will make sure it
     is valid; if it is, they will add it to their respective logs and move on
     to the ``Preparing`` phase.

#. In the ``Preparing`` phase, all secondary nodes (not the primary) broadcast a
   ``Prepare`` message that matches the accepted ``PrePrepare`` message. Each
   node will then add its own ``Prepare`` to its log, then accept ``Prepare``
   messages from other nodes and add them to its log. Once a node has ``2f + 1``
   ``Prepare`` messages in its log that match the accepted ``PrePrepare``, it
   will move on to the ``Committing`` phase.

#. The ``Committing`` phase is similar to the ``Preparing`` phase; nodes
   broadcast a ``Commit`` message to all nodes in the network, wait until there
   are ``2f + 1`` ``Commit`` messages in their logs, then move on to the
   ``Finishing`` phase. The only major difference between the ``Preparing`` and
   ``Committing`` phases is that in the ``Committing`` phase, the primary node
   is allowed to broadcast a message.

#. Once in the ``Finishing`` phase, each node will tell its validator to commit
   the block for which they have a matching ``PrePrepare``, ``2f + 1``
   ``Prepare`` messages, and ``2f + 1`` ``Commit`` messages. The node will then
   wait for a ``BlockCommit`` notification from its validator to signal that the
   block has been successfully committed to the chain. After receiving this
   confirmation, the node will update its state as follows:

   - Increment its sequence number by 1

   - Update its current chain head to the block that was just committed

   - Reset its phase to ``PrePreparing``

   Finally, the primary node will initialize a new block to start the process
   all over again.

This diagram summarizes the four Normal mode phases, the messages sent, and the
interactions with the validators. N1 is the primary node; N2, N3, and N4 are
secondary nodes.

.. figure:: images/normal_mode_procedure.png
    :alt: PBFT normal operation procedure


.. _log-pruning-label:

Log Pruning
^^^^^^^^^^^

Sawtooth PBFT does not implement a checkpointing procedure (garbage collection
of the log). Instead, each node cleans the log periodically during normal
operation.

Log size is controlled by a configurable setting, as determined by the on-chain
setting ``sawtooth.consensus.pbft.max_log_size``. When a block is committed,
each node compares the size of its log against the maximum size. If the log
exceeds this value, Sawtooth PBFT uses these rules to prune the log:

- Keep blocks and messages for the sequence number of the block that was just
  committed, plus those for any higher (newer) sequence numbers

- Delete blocks and messages for all lower (earlier) sequence numbers


.. _view-changing-mode-label:

View Changing Mode
------------------

A `view change` switches to a different primary node. A view change can be
trigged if the primary node is unresponsive, as determined by its failure to
commit the current working block within a specified amount of time.

When a secondary node receives a ``BlockNew`` message, it starts a commit timer.
If that node receives a ``Commit`` message before the time expires, it cancels
the timer and proceeds as normal. If the timer expires, it considers the primary
node to be faulty and requests a view change by sending a ``ViewChange``
message.  However, view changing mode does not occur until enough other nodes
agree (send their own ``ViewChange`` messages).

View changing mode has the following steps:

1. Any node who decides the primary is faulty sends a ``ViewChange`` message to
   all nodes. This message contains the node’s current sequence number (block
   number) and  its current view.

#. After sending the ``ViewChange`` message, the node enters View Changing mode.

#. Once a node receives :math:`2f + 1` ``ViewChange`` messages (including
   its own), it changes its own view to :math:`v + 1`, and resumes Normal
   operation.

The next primary node is determined by the node ID, in sequential order, based
on the order of nodes in the ``sawtooth.consensus.pbft.members`` on-chain setting.
For more information, see :ref:`view-changes-choosing-primary-label`.


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
