********************
Using PBFT Consensus
********************

Sawtooth PBFT consensus provides Byzantine fault tolerance for a network with
restricted membership. It has the following requirements:

* A network using PBFT consensus must have at least four nodes. A network with
  fewer nodes will fail; a new network with less than four nodes will not start.

* A PBFT network must be fully peered; that is, all nodes must be directly
  connected to all other nodes. Static peering is recommended.

* Each node on the network must install and run the PBFT consensus engine.

  - Package: ``sawtooth-pbft-engine``
  - Executable: ``pbft-engine``
  - Service: ``sawtooth-pbft-engine.service``

* Each node must run the Settings transaction processor (or an equivalent) to
  handle the PBFT and Sawtooth on-chain settings.

* The genesis block must specify the PBFT consensus engine name and version,
  using the on-chain settings ``sawtooth.consensus.algorithm.name`` and
  ``sawtooth.consensus.algorithm.version``.

  - The PBFT consensus engine name is ``pbft``.

  - The version number is in the file ``sawtooth-pbft/Cargo.toml`` (see the
    `sawtooth-pbft <https://github.com/hyperledger/sawtooth-pbft/>`_ repository)
    as ``version = "{major}.{minor}.{patch}"``. Use only the first two digits
    (major and minor release numbers); omit the patch number.  For example, if
    the version is 1.0.3, use ``1.0`` for the version setting.

* The on-chain configuration setting ``sawtooth.consensus.pbft.members`` must
  list all PBFT member nodes in the network. For more information, see
  :ref:`on-chain-settings-label`.

For the procedure to configure PBFT, see the Hyperledger Sawtooth documentation:

* Developers: `Creating a Sawtooth
  Network <https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/creating_sawtooth_network.html>`__
  shows how to create a test network with PBFT consensus for an application
  development environment.

* Sawtooth administrators: `Setting Up a Sawtooth
  Node <https://sawtooth.hyperledger.org/docs/core/releases/latest/sysadmin_guide/setting_up_sawtooth_poet-sim.html>`__
  explains how to create a Sawtooth network with PBFT consensus, plus how to add
  or remove nodes for an existing network.


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
