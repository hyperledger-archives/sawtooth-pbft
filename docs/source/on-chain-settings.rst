
.. _pbft-on-chain-settings-label:

On-Chain Settings
=================

The following on-chain settings are configurable, using the `Settings
transaction family
<https://sawtooth.hyperledger.org/docs/core/releases/latest/transaction_family_specifications/settings_transaction_family.html>`__:


- ``sawtooth.consensus.pbft.peers`` (required)

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

- | ``sawtooth.consensus.pbft.block_duration`` (optional, default 200 ms)
  | How often to try to publish a block

- | ``sawtooth.consensus.pbft.checkpoint_period`` (optional, default 100 blocks)
  | How many committed blocks in between each checkpoint

- | ``sawtooth.consensus.pbft.commit_timeout`` (optional, default 4000 ms)
  | How long to wait between block commits before deeming a primary node faulty

- | ``sawtooth.consensus.pbft.message_timeout`` (optional, default 10 ms)
  | How long to wait for updates from the Consensus API

- | ``sawtooth.consensus.pbft.max_log_size`` (optional, default 1000 messages)
  | The maximum number of messages that can be in the log


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
