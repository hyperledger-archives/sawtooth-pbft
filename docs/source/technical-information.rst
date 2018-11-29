*********************
Technical Information
*********************

The Sawtooth PBFT algorithm operates within the framework described by the
`Sawtooth Consensus API
<https://github.com/hyperledger/sawtooth-rfcs/blob/master/text/0000-consensus-api.md>`__.
The ``start`` method contains an event loop which handles all incoming
messages, in the form of ``Update``\ s. The most important form of ``Update``
to the functionality of PBFT is ``Update::PeerMessage``, but other updates
like ``BlockNew``, ``BlockCommit``, ``BlockValid``, ``BlockInvalid``, and
``Shutdown`` are considered.


Peer Messages
=============

When a message arrives from a peer, it must be interrogated for its type, and
then the system must create a corresponding language-specific object of that
message type. This is made easier by the fact that all consensus messages are
Protobuf-serialized. Generally, once a message is converted into an
appropriate object, it needs to be checked for content to make sure everything
is legitimate. Some of these checks are performed by the validator (such as
checking that a message’s signature is valid), but some (making sure messages
match, and that there are the correct number of them) need to be handled by
the Sawtooth PBFT consensus engine.

Message Definitions
-------------------

By definition, nodes in a Sawtooth PBFT network need to send a significant
number of messages to each other. Most messages have similar contents, shown
by ``PbftMessage``. Auxiliary messages related to view changes are also shown.
Furthermore, Sawtooth PBFT uses some of the message types defined in the
Consensus API (referred to as updates), such as blockchain-related updates
like ``BlockNew`` and ``BlockCommit``, and the system update ``Shutdown``.

The following `Protobuf
<https://developers.google.com/protocol-buffers/>`__-style definitions are
used to represent consensus-related messages in the Sawtooth PBFT system:

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

   // A generic PBFT message (PrePrepare, Prepare, Commit, Checkpoint)
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

     // Set of `2f + 1` checkpoint messages, proving correctness of stable
     // checkpoint mentioned in info's `sequence_number`
     repeated PbftMessage checkpoint_messages = 2;
   }


.. _pbft-on-chain-settings-label:

On-Chain Settings
=================

The following on-chain settings are configurable, using the `settings
transaction family
<https://sawtooth.hyperledger.org/docs/core/releases/latest/transaction_family_specifications/settings_transaction_family.html>`__:


- ``sawtooth.consensus.pbft.peers`` (required):

  List of the peers in a Sawtooth PBFT network; a JSON-formatted string of
  ``[<public-key-1>, <public-key-2>, ..., <public-key-n>]``.
  ``sawtooth.consensus.pbft.peers`` could look something like this in a
  four-node network:

  .. code-block:: console

    [
      "0203f3a0f914c9d80825b72346eeae42e884094ae3d0bd3c544c4c7e8ed37a3e6c",
      "02f83c8fb57bb8dc4c72a4ba0846e5c14bc02228e1d627f5c2dcafa209b7c5ffd2",
      "dc26a7099e81bb02869cc8ae57da030fbe4cf276b38ab37d2cc815fec63a14ab",
      "df8e8388ced559bd35c2b05199ca9f8fbebb420979715003355dcb7363016c1d"
    ]

- | ``sawtooth.consensus.pbft.block_duration`` (optional, default 200 ms):
  | How often to try to publish a block

- | ``sawtooth.consensus.pbft.checkpoint_period`` (optional, default 100 blocks):
  | How many committed blocks in between each checkpoint

- | ``sawtooth.consensus.pbft.commit_timeout`` (optional, default 4000 ms):
  | How long to wait between block commits before deeming a primary node faulty

- | ``sawtooth.consensus.pbft.message_timeout`` (optional, default 10 ms):
  | How long to wait for updates from the Consensus API

- | ``sawtooth.consensus.pbft.max_log_size`` (optional, default 1000 messages):
  | The maximum number of messages that can be in the log


Node Information Storage
========================

Every node keeps track of the following state information:

- Its own id

- Its current sequence number and view number

- Whether it’s a primary or secondary node

- Which step of the algorithm it’s on

- Mode of operation (``Normal``, ``ViewChanging``, ``Checkpointing``)

- The maximum number of faulty nodes allowed in the network

- The block that it’s currently working on

- Log of every peer message that has been sent to it (used to determine if it
  has received enough matching messages to proceed to the next stage of the
  algorithm; can be `garbage collected
  <algorithm-operation.html#checkpointing-mode>`__ every so often).

- List of its connected peers. This is taken from the
  `sawtooth.consensus.pbft.peers` on-chain setting. The length of this peer list
  is used to calculate :math:`f`, the maximum number of faulty nodes this
  network can tolerate.


Message Types
=============

- ``PrePrepare``: Sent from primary node to all nodes in the network,
  notifying them that a new message (``BlockNew``) has been received from the
  validator.

- ``Prepare``: Broadcast from every node once a ``PrePrepare`` is received for
  the current working block; used as verification of the ``PrePrepare``
  message, and to signify that the block is ready to be checked.

- ``Commit``: Broadcast from every node once a ``BlockValid`` update is
  received for the current working block; used to determine if there is
  consensus that nodes should indeed commit the block contained in the
  original message.

- ``Checkpoint``: Sent by any node that has commmitted ``checkpoint_period``
  blocks to the chain

- ``ViewChange``: Sent by any node that suspects that the primary node is
  faulty.


States
======

**States:** Sawtooth PBFT follows a state-machine replication pattern, where
these states are defined:

- ``NotStarted``: No blocks are being processed. No new ``BlockNew`` updates
  have been received. In this stage, a node enters ``Checkpointing`` mode if
  ``checkpoint_period`` blocks have been committed to the chain. If no
  checkpoint occurs, the node is ready to receive a ``BlockNew`` update for
  the next block.

- ``PrePreparing``: A ``BlockNew`` has been received through the Consensus
  API. Ready to receive a ``PrePrepare`` message for the block corresponding to
  the ``BlockNew`` message just received.

- ``Preparing``: A ``PrePrepare`` message has been received and is valid.
  Ready to receive ``Prepare`` messages corresponding to this ``PrePrepare``.

- ``Checking``: The predicate ``prepared`` is true; meaning this node has a
  ``BlockNew``, a ``PrePrepare``, and :math:`2f + 1` corresponding ``Prepare``
  messages. Ready to receive a ``BlockValid`` update.

- ``Committing``: A ``BlockValid`` has been received. Ready to receive
  ``Commit`` messages.

- ``Finished``: The predicate ``committed`` is true and the block has been
  committed to the chain. Ready to receive a ``BlockCommit`` update.

These states may be interrupted at any time if the commit timeout expires,
forcing the node into ``ViewChanging`` mode.

**State Transitions:** The following state transitions are defined;
listed with their causes:

- ``NotStarted`` → ``PrePreparing``: Receive a ``BlockNew`` update for
  the next block.

- ``PrePreparing`` → ``Preparing``: Receive a ``PrePrepare`` message
  corresponding to the ``BlockNew``.

- ``Preparing`` → ``Checking``: ``prepared`` predicate is true.

- ``Checking`` → ``Committing``: Receive a ``BlockValid`` update corresponding
  to the current working block.

- ``Committing`` → ``Finished``: ``committed`` predicate is true.

- ``Finished`` → ``NotStarted``: Receive a ``BlockCommit`` update for the
  current working block.

The states, state transitions, and actions that the algorithm takes are
represented in the following diagram:

.. figure:: images/pbft_states.png
   :alt: Sawtooth PBFT states

   Possible states in the Sawtooth PBFT algorithm. The outer ring of blue ovals
   represents normal mode operation, and the gray boxes represent actions the
   algorithm takes.

Initialization
==============

At the beginning of the Engine’s ``start`` method, some initial setup is
required:

- Initialize state with sequence number 0 and view 0

- Create the message log with all of its fields empty

- Establish timers and counters for checkpoint periods and block durations,
  which are loaded from the on-chain settings

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
