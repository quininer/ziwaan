# 指環 (ZiWaan)

A API-compatible replacement for [the ring](https://github.com/briansmith/ring).

Warning, this is just a toy. You should not use it in a production environment.

# Feature table

|feature\backend | rust-crypto backend| openssl backend|
|--- | --- | ---|
|aead | 5| _|
|chacha20\_poly1305\_openssh | 0| 0|
|digest (and more) | 5| _|
|curve25519 | 5| _|
|p256 | 3| 4|
|p384 | 2| 4|
|rsa | 1| 4|

* The content of the table is a subjective completion score, on a scale of 1 to 5, with higher values representing higher completion.
* `0` means not yet implemented, `\_` means using `rust-crypto backend` implementation.
