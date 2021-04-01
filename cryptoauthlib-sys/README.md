**rust-cryptoauthlib/cryptoauthlib-sys**
***

The Rust bindings for the [Microchip CryptoAuthentication Library](https://github.com/MicrochipTech/cryptoauthlib) version 3.1.0.

***
This workspace member provides a "raw" Rust bindings, generated automatically.

## About
The underlying C library was cloned as a submodule using below command:
~~~
git submodule add -b Release/v3.1.x https://github.com/MicrochipTech/cryptoauthlib.git
~~~
The library was locally compiled to investigate what cmake arguments are needed.<br>
After the above succeeded, the bindings were generated automatically from the build output using following command:
~~~
bindgen cryptoauthlib/lib/cryptoauthlib.h -o src/bindings.rs --
    -I ./cryptoauthlib/lib/
    -I ./target/release/build/cryptoauthlib-sys-****************/out/build/lib/
~~~
