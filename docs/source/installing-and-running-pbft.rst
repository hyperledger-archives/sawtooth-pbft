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

        % bin/run_docker_test tests/test_liveness.yaml

   This command builds several Docker images, starts up a network of four
   Sawtooth nodes with PBFT consensus, then goes through a liveness test of
   55 blocks, as defined in the Docker Compose file ``test_liveness.yaml``.
   The default log level is ``INFO``, so the test script displays a large amount
   of information as it executes.

   Tips:

   * This script has several options, such as ``--clean``, ``--no-build``, and
     ``--timeout``. For more information, execute ``run_docker_test --help``.

   * To run a different test, specify a different Compose file for
     ``run_docker_test``. The ``sawtooth-pbft/tests/`` directory includes several
     Docker Compose files for testing, such as ``grafana.yaml``, ``client.yaml``,
     and ``pbft_unit_tests.yaml``.

   * To adjust the :ref:`<on-chain-settings-label>`, edit the testing Compose
     file and change the ``sawset proposal create`` parameter for the genesis
     validator container (``validator-0``). For more information, see
     :ref:`on-chain-settings-label`. This example shows the settings in
     ``test_liveness.yaml``:

    .. code-block:: yaml

       validator-0
          ...
          sawset proposal create \
            ...
            sawtooth.consensus.algorithm.name=pbft \
            sawtooth.consensus.algorithm.version=1.0 \
            sawtooth.consensus.pbft.members=\\['\\\"'$$(cat /etc/sawtooth/keys/validator.pub)'\\\"','\\\"'$$(cat /etc/sawtooth/keys/validator-1.pub)'\\\"','\\\"'$$(cat /etc/sawtooth/keys/validator-2.pub)'\\\"','\\\"'$$(cat /etc/sawtooth/keys/validator-3.pub)'\\\"'\\] \
          ...

   * To adjust the :ref:`<cli-options-label>`, edit the testing Compose file and
     change the options used with the ``pbft-engine`` command for each PBFT
     container. For more information, see :ref:`<cli-options-label>`. This
     example shows the options in ``test_liveness.yaml`` for the ``pbft-0``
     container:

     .. code-block:: yaml

        pbft-0
          ...
          command: ./target/debug/pbft-engine --connect tcp://validator-0:5050 -vv
          ...


.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
