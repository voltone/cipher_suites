# CipherSuites

Select and sort the cipher suites for an Erlang/Elixir application using
the widely used OpenSSL syntax.

When looking for advice on how to improve the security and performance of an
SSL/TLS server, you'll often come across instructions for applications such as
Apache, Nginx, HAProxy. Odds are, they include a cipher suite recommendation
looking something like this:

`ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS`

This is cipher list in OpenSSL format, and it can be tricky to convert it to
a cipher list that Erlang's `:ssl` module understands. This library offers
a function to do exactly that:
[CipherSuites.select/1](https://hexdocs.pm/cipher_suites/CipherSuites.html#select/1)

## Example

```elixir
iex> CipherSuites.select("aRSA+kEECDH+AES256:!SHA")
[{:ecdhe_rsa, :aes_256_gcm, :null, :sha384},
 {:ecdhe_rsa, :aes_256_cbc, :sha384, :sha384}]
```

## Documentation

Full documentation is available [here](http://hexdocs.pm/cipher_suites/).

## Installation

The package is [available in Hex](https://hex.pm/packages/cipher_suites) and can be installed
by adding `cipher_suites` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:cipher_suites, "~> 0.2.1"}
  ]
end
```
