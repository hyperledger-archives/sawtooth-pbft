****************
Configuring PBFT
****************

Sawtooth PBFT is configured in two ways:

- Local settings - Command-line (CLI) options when running the PBFT executable
  or service

- Network settings - On-chain settings that are defined for the Sawtooth network


.. _cli-options-label:

=========================
PBFT Command-Line Options
=========================

Sawtooth PBFT uses command-line options to provide local configuration. These
options only affect the local behavior of a PBFT node, not the network as a
whole. The PBFT consensus engine, ``pbft-engine``, has the following
command-line options:

- | ``-C, --connect CONNECT``
  | (Optional; default ``tcp://localhost:5050``)
  | Connection endpoint for validator

- | ``-b, --exponential-retry-base BASE``
  | (Optional; default 100 ms)
  | Base timeout for exponential backoff used for validator requests

- | ``-m, --exponential-retry-max MAX``
  | (Optional; default 60000 ms)
  | Max timeout for exponential backoff used for validator requests

- | ``-L, --log-config LOG_CONFIG``
  | (Optional)
  | Path to logging config file; if not present, console logging is used

- | ``-l, --max-log-size MAX_LOG_SIZE``
  | (Optional; default 10000 messages)
  | How large the PBFT log is allowed to get before being pruned

- | ``-s, --storage-location STORAGE_LOCATION``
  | (Optional; default ``memory``)
  | Where to store PBFT's state: ``memory`` or ``disk+/path/to/file``

- | ``-u, --update-recv-timeout TIMEOUT``
  | (Optional; default 10 ms)
  | Timeout for receiving an update from the validator

- | ``-v``
  | (Optional)
  | Increase output verbosity


.. _on-chain-settings-label:

======================
PBFT On-Chain Settings
======================

Sawtooth PBFT includes on-chain settings for network-wide configuration on a
Hyperledger Sawtooth network. These settings affect how the whole network
operates, so it is desirable that they be the same on all nodes. The `Settings
transaction processor <https://sawtooth.hyperledger.org/docs/core/releases/latest/transaction_family_specifications/settings_transaction_family.html>`__
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
  | (Optional; default 1000 ms)
  | How often to try to publish a block.

- | ``sawtooth.consensus.pbft.commit_timeout``
  | (Optional; default 10000 ms)
  | How long to wait (after Pre-Preparing) for the node to commit the block
  | before determining that the primary node is faulty.

- | ``sawtooth.consensus.pbft.forced_view_change_interval``
  | (Optional; default 100 blocks)
  | Number of blocks to commit before forcing a view change.

- | ``sawtooth.consensus.pbft.idle_timeout``
  | (Optional; default 30000 ms)
  | How long to wait for the next ``BlockNew`` and ``PrePrepare`` messages
  | before determining that the primary node is faulty. The idle timeout must be
  | longer than the block publishing delay.

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
