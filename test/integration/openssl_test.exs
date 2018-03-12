defmodule CipherSuites.OpenSSLTest do
  use ExUnit.Case

  # Integration testing with OpenSSL's CLI. Make sure the `openssl`
  # binary exists in your $PATH, or that you specify its full path
  # using the :openssl_cmd configuration for your test environment.

  @moduletag :openssl

  setup_all do
    all = openssl_ciphers("ALL:COMPLEMENTOFALL")
    default = openssl_ciphers("DEFAULT")

    if all == [] or default == [] do
      raise "Could not get cipher list from OpenSSL; please make sure\n" <>
              "the openssl binary is available and supports the -V option " <>
              "for the\n`ciphers` command"
    end

    # Remember original cipher suite settings and restore them when done
    # with OpenSSL integration testing
    orig_all = Application.get_env(:cipher_suites, :all_suites)
    orig_default = Application.get_env(:cipher_suites, :default_suites)

    on_exit(fn ->
      Application.put_env(:cipher_suites, :all_suites, orig_all)
      Application.put_env(:cipher_suites, :default_suites, orig_default)
    end)

    # Set up the cipher suites to match what OpenSSL offers, to be able
    # to compare the results produced by CipherSuites and OpenSSL's CLI
    Application.put_env(:cipher_suites, :all_suites, all)
    Application.put_env(:cipher_suites, :default_suites, default)
  end

  @cases [
    # All keywords from OpenSSL man page
    "DEFAULT",
    "ALL",
    "COMPLEMENTOFDEFAULT",
    "COMPLEMENTOFALL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "eNULL",
    "NULL",
    "aNULL",
    "RSA",
    "kRSA",
    "aRSA",
    "kDHE",
    "kEDH",
    "DH",
    "DHE",
    "EDH",
    "ADH",
    "kEECDH",
    "kECDHE",
    "ECDH",
    "ECDHE",
    "EECDH",
    "AECDH",
    "aDSS",
    "DSS",
    "aDH",
    "aECDSA",
    "ECDSA",
    "SSLv3",
    "TLSv1.0",
    "TLSv1.2",
    "AES128",
    "AES256",
    "AES",
    "AESGCM",
    "3DES",
    "DES",
    "RC4",
    "IDEA",
    "MD5",
    "SHA1",
    "SHA",
    "SHA256",
    "SHA384",
    "kPSK",
    "PSK",
    "kDHEPSK",
    "kRSAPSK",
    "aPSK",
    "kSRP",
    "SRP",
    "aSRP",

    # OpenSSL suite names
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "SRP-RSA-3DES-EDE-CBC-SHA",

    # Test cases from CipherSuitesTest
    "aRSA+kEDH+AES256",
    "aRSA+kEDH+AES256:-SSLv3",
    "aRSA+kEDH+SHA",
    "aRSA+kEDH+SHA:@STRENGTH",
    "aRSA+kEECDH+SHA256:aRSA+kEDH+SHA256:+AES128",
    "!MEDIUM:!LOW:kRSA+SHA",

    # Additional OpenSSL test cases
    "DEFAULT:!MEDIUM",
    "DEFAULT:+MEDIUM",
    "RSA+AES",
    "aRSA+AES:-SRP",
    "DES:3DES:AES128:AES256:CHACHA20:@STRENGTH"
  ]

  Enum.each(@cases, fn statement ->
    @statement statement
    test @statement do
      assert CipherSuites.select(@statement) == openssl_ciphers(@statement)
    end
  end)

  # Helpers

  defp openssl_ciphers(filter) do
    openssl = Application.get_env(:cipher_suites, :openssl_cmd, "openssl")

    :os.cmd('#{openssl} ciphers -V #{filter}')
    |> to_string
    |> String.split("\n")
    |> Enum.map(&openssl_parse_cipher/1)
    |> Enum.reject(&is_nil/1)
  end

  defp openssl_parse_cipher(line) do
    case Regex.run(~r/0x([0-9A-F]{2}),0x([0-9A-F]{2})/, line) do
      nil ->
        nil

      [_, hi, lo] ->
        %{key_exchange: key_exchange, cipher: cipher, mac: mac, prf: prf} =
          :ssl_cipher.suite_definition(Base.decode16!(hi) <> Base.decode16!(lo))

        {key_exchange, cipher, mac, prf}
    end
  rescue
    # ignore OpenSSL cipher not supported by Erlang.OTP
    FunctionClauseError ->
      nil
  end
end
