defmodule CipherSuites.Mixfile do
  use Mix.Project

  def project do
    [
      app: :cipher_suites,
      version: "0.2.0",
      elixir: "~> 1.4",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "CipherSuites",
      description: description(),
      package: package(),
      docs: [main: CipherSuites],
      source_url: "https://github.com/voltone/cipher_suites"
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:ex_doc, "~> 0.18.3", only: :dev}
    ]
  end

  defp description do
    """
    Select and sort the cipher suites for an Erlang/Elixir application using
    the widely used OpenSSL syntax.
    """
  end

  defp package do
    [
      maintainers: ["Bram Verburg"],
      licenses: ["BSD 3-Clause"],
      links: %{"GitHub" => "https://github.com/voltone/cipher_suites"}
    ]
  end
end
