Glossary
========

.. glossary::

  Node
    Machine running all the components necessary for a working blockchain
    (including the Validator, the REST API, at least one transaction processor,
    and the PBFT algorithm itself). In this RFC, unless otherwise specified,
    it can be assumed that *Node* refers to the PBFT component of the machine.

  Server
    Synonym for node.

  Replica
    Synonym for node.

  Validator
    Component of a node responsible for interactions with the blockchain.
    Interactions with the validator are abstracted by the Consensus API.

  Block
    A part of the
    `blockchain <https://en.wikipedia.org/wiki/Block chain>`__,
    containing some operations and a link to the previous block.

  Primary
    Node in charge of making the final consensus decisions and committing to
    the blockchain.  Additionally is responsible for publishing the blocks given
    to it by the Consensus API, and starting the consensus process.

  Secondaries
    Auxiliary nodes used for consensus.

  Client
    Machine that sends requests to and receives replies from the network of
    nodes. PBFT has no direct interaction with clients; the Validator bundles
    all client requests into blocks and sends them through the Consensus API to
    the consensus algorithm.

  Consensus seal
    Proof that a block underwent consensus.

  Block duration
    How many seconds to wait before trying to publish a block.

  Member node
    Sawtooth node that participates in PBFT consensus. Membership is controlled
    by the on-chain setting ``sawtooth.consensus.pbft.members``.

  Message
    Block, with additional information (see `Message
    Types <message-types.html>`__).

  Working block
    The block that has been initialized but not finalized, and is currently
    being committed to.

  View
    The period of time of PBFT when the current primary is in charge. The view
    changes when the primary is deemed faulty, as described in
    `View Changes <#view-changes>`__.

  :math:`n`
    The total number of nodes in the network.

  :math:`f`
    The maximum number of faulty nodes.

  :math:`v`
    The current view number (how many primary node changes have occurred).

  :math:`p`
    The primary server number; :math:`p = v \mod n`.


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
