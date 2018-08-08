***************************
Sawtooth PBFT API Reference
***************************

This implementation of PBFT is written in the systems programming language
`Rust <https://www.rust-lang.org/en-US/>`__. The implementation is heavily
based on the `original PBFT paper
<https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html>`__,
but draws some inspiration from the PBFT derivative `MinBFT
<http://homepages.gsd.inesc-id.pt/~mpc/pubs/Veronese-Efficient%20Byzantine%20Fault%20Tolerance.pdf>`__,
as well as the idea for `Istanbul Byzantine fault tolerance
<https://github.com/ethereum/EIPs/issues/650>`__ from the Ethereum network.

.. raw:: html

    <p class="large-text">
        <a href="pbft_doc/sawtooth_pbft/index.html">
            Sawtooth PBFT API (rustdocs)
        </a>
    </p>


Dependencies of Sawtooth PBFT are are specified in `Cargo.toml
<https://github.com/bitwiseio/sawtooth-pbft/blob/master/Cargo.toml>`__.

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
