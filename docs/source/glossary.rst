Glossary
========

.. glossary::

  Node
    Machine running all the components necessary for a working blockchain
    (including the Validator, the REST API, at least one transaction processor,
    and the PBFT algorithm itself). In this RFC, unless otherwise specified,
    it can be assumed that *Node* refers to the PBFT component of the machine.

    The `original PBFT paper <http://pmg.csail.mit.edu/papers/osdi99.pdf>`__
    uses the terms `server` or `replica` instead of `node`.

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

  Member node
    Sawtooth node that participates in PBFT consensus. Membership is controlled
    by the on-chain setting ``sawtooth.consensus.pbft.members``.

  Message
    Block, with additional information (see :ref:`pbft-arch-message-types`).

  Working block
    The block that has been initialized but not finalized, and is currently
    being committed to.

  View
    The period of time of PBFT when the current primary is in charge. The view
    changes when the primary is deemed faulty (see
    :ref:`view-changes-choosing-primary-label`).

  Consensus API
    Sawtooth component that abstracts consensus-related interactions between
    the validator and a consensus engine. The consensus API allows `dynamic
    consensus`, a feature that allows a choice of consensus for a Sawtooth
    network.

  Consensus engine
    Component that provides consensus functionality for a Sawtooth
    network. The consensus engine communicates with the validator through
    the consensus API.

  Transaction processor
    Sawtooth component that validates transactions and updates state based on
    rules defined by the associated `transaction family`. (These rules specify
    the business logic, also called a `smart contract`, for the transaction
    processor.) For more information, see the `Hyperledger Sawtooth
    documentation <https://sawtooth.hyperledger.org/docs/core/releases/latest/transaction_family_specifications.html>`__.


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
