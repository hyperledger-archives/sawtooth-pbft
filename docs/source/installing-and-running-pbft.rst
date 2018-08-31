***************************
Installing and Running PBFT
***************************

Prerequisites: `Docker and Docker Compose <https://www.docker.com/>`__ must be installed.

Use the following steps to start a four-node network and run a liveness test:

1.  Clone the PBFT repo: ``git clone https://github.com/bitwiseio/sawtooth-pbft.git``

#.  Run the following commands to connect to the ``sawtooth-dev-pbft``
    interactive shell:

    .. code-block:: console

       cd sawtooth-pbft

       docker build . -f Dockerfile -t sawtooth-dev-pbft

       docker run -v $(pwd):/project/sawtooth-pbft -it sawtooth-dev-pbft bash

       # You can optionally use this to speed up your build times, if you have a cargo-registry Docker volume set up:
       docker run -v $(pwd):/project/sawtooth-pbft -v cargo-registry:/root/.cargo/registry -it sawtooth-dev-pbft bash

#.  Once you have the ``sawtooth-dev-pbft`` interactive shell up, run:

    .. code-block:: console

       cargo build

#.  Once the project finishes building, exit the interactive shell and run

    .. code-block:: console

       tests/pbft.sh

This script first builds a few docker images, then starts up a network of four
nodes and goes through a liveness test of 55 blocks (using the Docker Compose
file ``test_liveness.yaml``). The default log level is ``INFO``, so it prints
out quite a bit of information as the algorithm executes. All the parameters
mentioned in `On-Chain Settings
<technical-information.html#on-chain-settings>`__ can be adjusted inside of
the file ``tests/test_liveness.yaml``, as well as the log level for each of
the services in the network.

If you'd like to specify a different Docker Compose file to use (such as
``grafana.yaml``, ``client.yaml``, or ``pbft_unit_tests.yaml``), provide
``pbft.sh`` with an additional argument:

.. code-block:: console

    tests/pbft.sh pbft_unit_tests

If you'd like to pass additional arguments to Docker Compose, they go after
the compose file you're using:

.. code-block:: console

    tests/pbft.sh client --abort-on-container-exit

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
