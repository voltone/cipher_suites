defmodule CipherSuites.ApplyConfig do
  @moduledoc """
  Helper functions for applying cipher selection strings in configuration
  files.

  ## Rationale

  It is not possible to call `CipherSuites.select/1` directly from within an
  application's configuration file, since the configuration file is loaded
  before its dependencies are compiled (or even fetched). This module defines
  helpers that can be used to transport cipher selection strings used in
  configuration files into the corresponding list of cipher suites during
  application startup.

  This has the added benefit that the filter is always applied at runtime,
  using the correct `:ssl` module version and the actual cipher suites
  available. A hypothetical call to `select/1` from the configuration file
  could lead to unexpected results when used in a Release, since
  configuration files are evaluated as part of the Release build process and
  the cipher selection string would therefore be applied to the cipher suites
  supported by the build server.

  ## Usage

  Add a call to the relevant function at the top of the application's
  `start/2` callback. For example:

      def start(_type, _args) do
        import Supervisor.Spec

        CipherSuites.ApplyConfig.phoenix_endpoint(:my_app, MyApp.Endpoint)

        # Define workers and child supervisors to be supervised
        children = [
          # Start the endpoint when the application starts
          supervisor(MyApp.Endpoint, []),
          # ...

  Please refer to the documentation for the individual functions for
  information on how to modify the configuration.
  """

  @doc """
  Applies the cipher selection string in the Phoenix Endpoint configuration.

  In the Endpoint's `:https` key, specify the `:ciphers` option as a cipher
  selection string, e.g.:

      config :my_app, MyApp.Endpoint,
        http: [port: 4000],
        https: [
          port: 4001,
          keyfile: "priv/server.key",
          certfile: "priv/server.crt",
          ciphers: "!MEDIUM:!LOW:kRSA+SHA",
          honor_cipher_order: true
        ],

  When calling the function from the application's `start/2` callback, pass
  in the OTP application name as an atom, and the name of the Endpoint module,
  e.g.:

      CipherSuites.ApplyConfig.phoenix_endpoint(:my_app, MyApp.Endpoint)
  """
  @spec phoenix_endpoint(atom, module) :: :ok
  def phoenix_endpoint(otp_app, endpoint) do
    config =
      Application.get_env(otp_app, endpoint)
      |> update_in([:https, :ciphers], fn
           expression when is_binary(expression) ->
             CipherSuites.select(expression)
           list -> list
         end)
    Application.put_env(otp_app, endpoint, config)
  end

end
