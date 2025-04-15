# 🍳 nonstick

Nonstick lets you use PAM (Pluggable Authentication Modules) from Rust without having to deal with icky unsafe code.

## Status

It is currently very incomplete.
It only provides functionality for developing your own PAM authentication module (i.e., a backend that PAM calls to authenticate a user or do something similar).
At the moment, [Linux-PAM](https://github.com/linux-pam/linux-pam) is the only supported PAM implementation.

I will make an effort not to break APIs with development, but consider it alpha, pre-1.0 software.
While the code itself should be _secure_ and mostly safe, the API may not be completely stable.

Goals include:

- Bindings for PAM clients.
- Support for non–Linux-PAM implementations.

## Credits

This is a direct fork of [Anthony Nowell](http://anowell.com/)’s [`pam-rs`/`pam-bindings` crate](https://crates.io/crates/pam-bindings).
`pam-rs` was in turn inspired by:

- [`rust-pam` by tozny](https://github.com/tozny/rust-pam)
- [`pam_groupmap` by ndenev](https://github.com/ndenev/pam_groupmap)
- [`pam-http` by beatgammit](https://github.com/beatgammit/pam-http)
