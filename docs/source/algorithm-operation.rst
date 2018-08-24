*******************
Algorithm Operation
*******************

Sawtooth PBFT has three primary modes of operation: ``Normal``,
``Checkpointing``, and ``ViewChanging``.


Normal Mode
===========

``Normal`` mode is the default mode of operation for Sawtooth PBFT. This is
the mode that the algorithm will spend most of its time in, and is where
blocks can be committed to the chain.

Predicates
----------

In order to keep the algorithm explanation below concise, we’ll define
some predicates here.

- ``prepared`` is true for the current node if the following messages are
  present in its log:

   - The original ``BlockNew`` message
   - A ``PrePrepare`` message matching the original message (in the current
     view)
   - :math:`2f + 1` matching ``Prepare`` messages from different nodes that
     match ``PrePrepare`` message above (including its own)

- ``committed`` is true if for the current node:

   - ``prepared`` is true
   - This node has accepted :math:`2f + 1` ``Commit`` messages, including its
     own


Normal Mode Operation
---------------------

In ``Normal`` mode (when the primary node is not faulty), the Sawtooth PBFT
consensus algorithm operates as follows, inside the event loop of the
``start`` method:

1. Receive a ``BlockNew`` message from the Consensus API, representative of
   several batched client requests. The primary node checks the legitimacy of
   the message and assigns this message a sequence number, then broadcasts a
   ``PrePrepare`` message to all nodes. Legitimacy is checked by looking at
   the ``signer_id`` of the block in the ``BlockNew`` message, and making sure
   the ``previous_id`` is valid as the current chain head. The consensus seal
   is checked here as well, and all nodes tentatively update their working
   blocks. Secondary nodes ignore ``BlockNew`` messages; only append them to
   their logs. All nodes start a view change timer, just in case the primary
   node doesn't go through with committing this block.

#. Receive ``PrePrepare`` messages and check their legitimacy. If the
   ``PrePrepare`` is determined to be invalid, then start a view change.
   ``PrePrepare`` messages are legitimate if all the following are true:

    - ``signer_id`` and ``summary`` of block inside ``PrePrepare`` match the
      corresponding fields of the original ``BlockNew`` block
    - View in ``PrePrepare`` message corresponds to this server’s current view
    - This message hasn’t been accepted already with a different ``summary``
    - Sequence number is within the sequential bounds of the log (low and high
      water marks)

#. Once the ``PrePrepare`` is accepted:

    - If primary: double check message matches the ``BlockNew``, then
      broadcast a ``Prepare`` message to all nodes.
    - If secondary: update its own sequence number from the message, then
      broadcast a ``Prepare`` message to all nodes.

#. Receive ``Prepare`` messages, and check them all against their associated
   ``PrePrepare`` message in this node’s message log.

#. Once the predicate ``prepared`` is true for this node, then call
   ``check_blocks()`` on the current working block. If an error occurs
   (``ReceiveError`` or ``UnknownBlock``), abort (call ``ignore_block()``).
   Otherwise, wait for a response (``BlockValid`` or ``BlockInvalid``) from
   the validator. If ``BlockValid``, then broadcast a ``Commit`` message to
   all other nodes. If ``BlockInvalid``, then call ``ignore_block()``, and
   start a view change.

#. When the predicate ``committed`` is true for this node, then it should
   commit the block using ``commit_block()``, and advance the chain head.

#. When a ``BlockCommit`` update is received by the primary node, it calls
   ``initialize_block()``. Upon receipt of ``BlockCommit``, all nodes stop
   their view change timers.

#. If ``block_duration`` has elapsed, then try to ``summarize_block()`` with
   the current working block. If the working block is not ready
   (``BlockNotReady`` or ``InvalidState`` occurs), then nothing happens.
   Otherwise, ``finalize_block()`` is called with a serialized summary of all
   the ``Commit`` messages this node has received (which functions as the
   consensus seal). This in turn sends out a ``BlockNew`` update to the
   network, starting the next cycle of the algorithm.

A visual overview of the messages passed during ``Normal`` mode is presented
in the following diagram:

.. figure:: images/message_passing.png
    :alt: Messages passed during normal operation

    Overview of messages passed between nodes, and interactions with the
    validators. Node 1 (N1) is the primary node, while N2-N4 are secondary
    nodes.


ViewChanging Mode
=================

Sometimes, the node currently in charge (the primary) becomes faulty.  This
could mean it is either malicious, or experiencing internal problems. In
either of these cases, a view change is necessary. View changes are triggered
by a timeout: When a secondary node receives a ``BlockNew`` message, a timer
is started. If the secondary ends up receiving a ``Commit`` message, the timer
is cancelled, and the algorithm proceeds as normal. If the timer expires, the
primary node is considered faulty and a view change is initiated. This ensures
Byzantine fault tolerance due to the fact that each step of the algorithm will
not proceed to the next unless it receives a certain number of matching
messages, and due to the fact that the Validator does not pass on any messages
that have invalid signatures.

The view change process is as follows:

1. Any node who discovers the primary as faulty (whose timer timed out) sends
   a ``ViewChange`` message to all nodes, containing the node’s current
   sequence number, its current view, proof of the previous checkpoint, and
   pending messages that have happened since that previous checkpoint. The
   node enters ``ViewChanging`` mode.

2. Once a server receives :math:`2f + 1` ``ViewChange`` messages (including
   its own), it changes its own view to :math:`v + 1`, and resumes ``Normal``
   operation. The new primary node’s ID is :math:`p = v \mod n`. This means
   that nodes become primary in sequential, cyclic order, based on their
   numeric ID (i.e. node 0 is the primary in view 0, 1 is the primary in view
   1, ..., 0 is the primary in view 4, etc.).


Checkpointing Mode
==================

After each ``checkpoint_period`` (usually around 100 successfully completed
cycles of the algorithm), server log messages can be garbage-collected. When
each node reaches a checkpoint, it enters ``Checkpointing`` mode and sends out
a ``Checkpoint`` message to all of the other servers, with that node’s current
state (described by a ``PbftBlock``).  When the current node has :math:`2f +
1` matching ``Checkpoint`` messages from different servers, the checkpoint is
considered *stable* and the logs can be garbage collected: All log entries
with sequence number less than the one in the ``Checkpoint`` message are
discarded, and all previous checkpoints are removed. The high and low water
marks are updated to reflect the sequence number of the new stable checkpoint.
Once garbage collection is complete, the node resumes ``Normal`` operation.

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
