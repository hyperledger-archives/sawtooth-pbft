*****************************
Introduction to Sawtooth PBFT
*****************************

This guide describes a practical Byzantine fault tolerant (PBFT) consensus
algorithm for `Hyperledger Sawtooth
<https://github.com/hyperledger/sawtooth-core>`__.

`Practical Byzantine Fault Tolerance
<https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html>`__,
a paper written in 1999 by Miguel Castro and Barbara Liskov, describes a
consensus algorithm that solves the `Byzantine Generals Problem
<https://en.wikipedia.org/wiki/Byzantine_fault_tolerance#Byzantine_Generals'_Problem>`__,
while still remaining computationally feasible. This implementation of PBFT
consensus for Hyperledger Sawtooth is based off the methodology described in
the 1999 paper, and adapted for use in a blockchain context.

The Sawtooth PBFT algorithm is a voting-based consensus mechanism with
Byzantine fault tolerance. This algorithm ensures `safety and liveness
<https://en.wikipedia.org/wiki/Liveness#Liveness_and_safety>`__ of a network,
provided at most :math:`\lfloor \frac{n - 1}{3} \rfloor` nodes are faulty, where
:math:`n` is the total number of nodes in the network. The Sawtooth PBFT
algorithm is also inherently crash fault tolerant. Another advantage of PBFT
is that blocks committed by nodes are final, so there are no forks in the
network. This is verified by a "Consensus Seal," which is appended to the
following block and used to verify that the block was added correctly.

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
