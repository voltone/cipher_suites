## Changelog

## v0.3.0

* Tests updated for Erlang/OTP 20.3. Note that some tests now fail on older
  OTP versions, but the library works as before
* Add support for some fully specified ChaCha20-Poly1305 suites, which are not
  (currently) recognized by name by Erlang/OTP

## v0.2.0

* Added `CipherSuites.init_phoenix_endpoint/1` and removed
  `CipherSuites.ApplyConfig`
* Demoted 3DES from HIGH to MEDIUM, to align with recent OpenSSL versions
* Support for new `:ssl` module versions that return suite definition
  as a map rather than a 4-tuple
* Fix deprecation warning (now requiring Elixir 1.4 or later)
* Code formatting

## v0.1.0

Initial version
