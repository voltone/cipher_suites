# CipherSuites

Select and sort the cipher suites for an Erlang/Elixir application using
the widely used OpenSSL syntax.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add cipher_suites to your list of dependencies in `mix.exs`:

        def deps do
          [{:cipher_suites, "~> 0.1.0"}]
        end

  2. Ensure cipher_suites is started before your application:

        def application do
          [applications: [:cipher_suites]]
        end
