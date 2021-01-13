**rust-cryptoauthlib**
***

The Rust wrapper for the [Microchip CryptoAuthentication Library](https://github.com/MicrochipTech/cryptoauthlib).

***

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
The above fixes also below compilation error:<br>
`CMake Error: The source directory "/home/user/rust-cryptoauthlib/cryptoauthlib-sys/cryptoauthlib" does not appear to contain CMakeLists.txt.`
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
