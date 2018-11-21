***************************
Installing and Testing PBFT
***************************

This procedure describes how to install PBFT, start a four-node network in
Docker containers, and run a basic liveness test.

**Prerequisites:** `Docker and Docker Compose <https://www.docker.com/>`__ must
be installed.

1. Clone the PBFT repository.

     .. code-block:: console

        $ git clone https://github.com/hyperledger/sawtooth-pbft.git

#. Run the following commands to install the dependencies for PBFT and connect
   to the interactive shell container, ``sawtooth-dev-pbft``.

     .. code-block:: console

        $ cd sawtooth-pbft
        $ docker build . -f Dockerfile -t sawtooth-dev-pbft
        $ docker run -v $(pwd):/project/sawtooth-pbft -it sawtooth-dev-pbft bash

   .. tip::

      If you have already configured a ``cargo-registry`` Docker volume, use
      the following ``docker run`` command to speed up the build time in the
      next step.

       .. code-block:: console

          $ docker run -v $(pwd):/project/sawtooth-pbft \
          -v cargo-registry:/root/.cargo/registry \
          -it sawtooth-dev-pbft bash

#.  Build the PBFT project.

      .. code-block:: console

         $ cargo build

#. After the project has finished building, exit the ``sawtooth-dev-pbft``
   shell container.

#. Run the PBFT test script on your host system from the ``sawtooth-pbft``
   directory.

     .. code-block:: console

        % tests/pbft.sh

   This script builds several Docker images, starts up a network of four
   Sawtooth nodes with PBFT consensus, then goes through a liveness test of
   55 blocks (using the Docker Compose file ``test_liveness.yaml``). The default
   log level is ``INFO``, so the test script displays a large amount of
   information as it executes.

**Optional Changes**

* The ``sawtooth-pbft`` repository includes several Docker Compose files for
  testing. To specify a different Compose file (such as ``grafana.yaml``,
  ``client.yaml``, or ``pbft_unit_tests.yaml``), include the file name on the
  command line, as in this example:

    .. code-block:: console

       $ tests/pbft.sh pbft_unit_tests

* To pass additional arguments to Docker Compose, put them after the Compose
  file, as in this example:

    .. code-block:: console

       $ tests/pbft.sh client --abort-on-container-exit

* To adjust the :ref:`PBFT on-chain settings <pbft-on-chain-settings-label>`,
  edit ``test_liveness.yaml`` and change the ``sawset proposal create``
  parameters for the four validator containers. For example:

    .. code-block:: yaml

       validator-0
          ...
          sawset proposal create \
            ...
            sawtooth.consensus.pbft.peers=\\['\\\"'$$(cat /etc/sawtooth/keys/validator.pub)'\\\"','\\\"'$$(cat /etc/sawtooth/keys/validator-1.pub)'\\\"','\\\"'$$(cat /etc/sawtooth/keys/validator-2.pub)'\\\"','\\\"'$$(cat /etc/sawtooth/keys/validator-3.pub)'\\\"'\\] \
            sawtooth.consensus.pbft.block_duration=100 \
            sawtooth.consensus.pbft.checkpoint_period=10 \
            sawtooth.consensus.pbft.view_change_timeout=4000 \
            sawtooth.consensus.pbft.message_timeout=10 \
            sawtooth.consensus.pbft.max_log_size=1000 \
          ...


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
