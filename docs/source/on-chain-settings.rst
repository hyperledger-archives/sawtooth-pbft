**********************
PBFT On-Chain Settings
**********************

Sawtooth PBFT includes on-chain settings for configuring PBFT consensus on a
Hyperledger Sawtooth network. The `Settings transaction
processor <https://sawtooth.hyperledger.org/docs/core/releases/latest/transaction_family_specifications/settings_transaction_family.html>`__
(or an equivalent) is required to process these settings.

.. tip::

   To display the existing settings, use `sawtooth settings
   list <https://sawtooth.hyperledger.org/docs/core/releases/latest/cli/sawtooth.html#sawtooth-settings-list>`__.

   To change a setting, use `sawset proposal
   create <https://sawtooth.hyperledger.org/docs/core/releases/latest/cli/sawset.html#sawset-proposal-create>`__.
   This command requires a signing key (the ``--key`` option) that specifies the
   public key of a user or validator that has permission to change settings. See
   ``sawtooth.identity.allowed_keys`` in `Configuring Validator and Transactor
   Permissions <https://sawtooth.hyperledger.org/docs/core/releases/latest/sysadmin_guide/configuring_permissions.html>`__.

- | ``sawtooth.consensus.pbft.block_publishing_delay``
  | (Optional; default 200 ms)
  | How often to try to publish a block.

- | ``sawtooth.consensus.pbft.commit_timeout``
  | (Optional; default 30000 ms)
  | How long to wait between block commits before determining that the primary
  | node is faulty.

- | ``sawtooth.consensus.pbft.forced_view_change_period``
  | (Optional; default 30 blocks)
  | Number of blocks to commit before forcing a view change.

- | ``sawtooth.consensus.pbft.idle_timeout``
  | (Optional; default 30000 ms)
  | How long to wait for the next ``BlockNew`` and ``PrePrepare`` messages
  | before determining that the primary node is faulty. The idle timeout must be
  | longer than the block duration.

- | ``sawtooth.consensus.pbft.members``
  | (Required)
  | List of validator public keys for the member nodes in the PBFT network,
  | as a comma-separated list (in a JSON-formatted string):
  | ``[public-key-1, public-key-2, ..., public-key-n]``

- | ``sawtooth.consensus.pbft.view_change_duration``
  | (Optional; default 5000 ms)
  | How long to wait for a valid ``NewView`` message before starting the next
  | view change. For more information, see :ref:`view-changing-mode-label`.


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
