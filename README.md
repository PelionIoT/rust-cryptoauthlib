**rust-cryptoauthlib**
***

The Rust wrapper for the [Microchip CryptoAuthentication Library](https://github.com/MicrochipTech/cryptoauthlib).

***

[[_TOC_]]
## Repository cloning
The wrapper carries own cryptoauthentication library (3.1.0) as a git submodule, hence its cloning requires caution.<br>
For the snippets below, double check the GITREPO URI; this one works for now:
~~~
GITREPO = https://github.com/RobertDrazkowskiGL/rust-cryptoauthlib.git
~~~
### Cloning the whole repository in one step
~~~
git clone --recurse-submodules $GITREPO
~~~
### Cloning the wrapper first then subsequently the cryptoauthlib submodule
~~~
git clone $GITREPO
cd rust-cryptoauthlib
git submodule update --init --recursive
~~~
## Compilation instructions.
A release build<br>
~~~
cargo build --release
~~~

A debug build
~~~
cargo build
~~~
## Running tests
~~~
cargo test
~~~