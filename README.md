# 指環 (ZiWaan)

A API-compatible replacement for [the ring](https://github.com/briansmith/ring).

Aims to replace C/asm implementations with pure Rust's cryptographic primitives
for increased security and portability.

In the choice of cryptographic primitives,
the implementation with formal proof is preferred,
followed by mature implementations in the community.
Therefore, the performance may be slightly worse than ring on certain platforms.
