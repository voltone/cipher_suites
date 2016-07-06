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

## Documentation

Full documentation is available [here](http://hexdocs.pm/cipher_suites/).

## Installation

Install using [Hex](https://hex.pm/):

  1. Add cipher_suites to your list of dependencies in `mix.exs`:

        def deps do
          [{:cipher_suites, "~> 0.1.0"}]
        end

  2. Ensure cipher_suites is also specified as an application dependency, to
     ensure proper release packaging:

        def application do
          [applications: [:cipher_suites]]
        end
