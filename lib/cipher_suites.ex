defmodule CipherSuites do
  @moduledoc """
  Support OpenSSL-style cipher suite selection in Erlang/Elixir applications.
  """

  @doc """
  Applies the specified OpenSSL cipher selection string to the list of known
  cipher suites and returns the resulting list.

  The result can be used in the `:ciphers` option for `:ssl` client and
  server connections, as well as in most TLS-capable applications, such as
  Ranch, Cowboy, Plug and Phoenix.

  Example:

      iex> CipherSuites.select("aRSA+kEECDH+AES256:!SHA")
      [{:ecdhe_rsa, :aes_256_gcm, :null, :sha384},
       {:ecdhe_rsa, :aes_256_cbc, :sha384, :sha384}]

  Please refer to the
  [OpenSSL man page](https://www.openssl.org/docs/manmaster/apps/ciphers.html)
  for more information about the syntax of the cipher selection string.
  """
  @spec select(binary) :: [:ssl.ciphersuite()]
  def select(expression) do
    expression
    |> String.split([":", ",", " "], trim: true)
    |> filter()
  end

  @doc """
  Returns all known cipher suites, as reported by the `:ssl` module.

  Note that this function returns all known cipher suites, including null
  ciphers, which is different from what `select("ALL")` returns!
  """
  @spec all() :: [:ssl.ciphersuite()]
  def all do
    Application.get_env(:cipher_suites, :all_suites, :ssl.cipher_suites(:all))
  end

  @doc """
  Returns the default cipher suites, as reported by the `:ssl` module.
  """
  @spec default() :: [:ssl.ciphersuite()]
  def default do
    Application.get_env(:cipher_suites, :default_suites, :ssl.cipher_suites())
  end

  @doc """
  Expands a cipher suite spec string in OpenSSL format in a Phoenix Endpoint
  configuration. For use in the Endpoint's `init/2` callback, e.g.:

      # Inside config.exs
      config :my_app, MyAppWeb.Endpoint,
        https: [
          port: 4001,
          certfile: "priv/cert.pem",
          keyfile: "priv/key.pem",
          ciphers: "aRSA+kEECDH+AES256:!SHA"
        ]

      # Inside MyAppWeb.Endpoint...
      def init(_key, config) do
        {:ok, CipherSuites.init_phoenix_endpoint(config)}
      end
  """
  @spec init_phoenix_endpoint(Keyword.t()) :: Keyword.t()
  def init_phoenix_endpoint(config) do
    if get_in(config, [:https, :ciphers]) do
      update_in(config, [:https, :ciphers], fn
        spec when is_binary(spec) -> CipherSuites.select(spec)
        list -> list
      end)
    else
      config
    end
  end

  # Private

  @high [
    :aes_128_cbc,
    :aes_128_gcm,
    :aes_256_cbc,
    :aes_256_gcm,
    :chacha20_poly1305
  ]
  @medium [:rc4_128, :idea_cbc, :"3des_ede_cbc"]
  @low [:des40_cbc, :des_cbc]

  @key_size %{
    null: 0,
    rc4_128: 128,
    idea_cbc: 128,
    des40_cbc: 40,
    des_cbc: 56,
    # OpenSSL treats 3DES as having an effective
    "3des_ede_cbc": 112,
    # key size of 112 bits instead of 156, due
    # to known weaknesses
    aes_128_cbc: 128,
    aes_256_cbc: 256,
    aes_128_gcm: 128,
    aes_256_gcm: 256,
    chacha20_poly1305: 256
  }

  # DEFAULT: "When used, this must be the first cipherstring specified.
  # This [...] is normally ALL:!COMPLEMENTOFDEFAULT:!eNULL".
  defp filter(["DEFAULT" | tokens]) do
    filter(["ALL", "!COMPLEMENTOFDEFAULT", "!eNULL" | tokens])
  end

  # Modifiers: "Each cipher string can be optionally preceded by the
  # characters !, - or +."
  # This function also handles special cipher strings starting with "@".
  defp filter(tokens) do
    result =
      Enum.reduce(tokens, %{included: [], excluded: []}, fn
        "@STRENGTH", state ->
          sort_by_strength(state)

        # "@SECLEVEL=" <> n    ->
        "!" <> cipher, state ->
          exclude(cipher, state)

        "-" <> cipher, state ->
          delete(cipher, state)

        "+" <> cipher, state ->
          move_to_end(cipher, state)

        cipher, state ->
          append(cipher, state)
      end)

    result.included -- result.excluded
  end

  # "If ! is used then the ciphers are permanently deleted from the list.
  # The ciphers deleted can never reappear in the list even if they are
  # explicitly stated."
  defp exclude(cipher, state) do
    %{state | excluded: merge(state.excluded, cipher_string(cipher))}
  end

  # "If - is used then the ciphers are deleted from the list, but some or
  # all of the ciphers can be added again by later options."
  defp delete(cipher, state) do
    %{state | included: state.included -- cipher_string(cipher)}
  end

  # "If + is used then the ciphers are moved to the end of the list. This
  # option doesn't add any new ciphers it just moves matching existing
  # ones."
  defp move_to_end(cipher, state) do
    ciphers = cipher_string(cipher)
    {last, first} = Enum.split_with(state.included, &(&1 in ciphers))
    %{state | included: first ++ last}
  end

  # "If none of these characters is present then the string is just
  # interpreted as a list of ciphers to be appended to the current
  # preference list. If the list includes any ciphers already present they
  # will be ignored: that is they will not moved to the end of the list."
  defp append(cipher, state) do
    %{state | included: merge(state.included, cipher_string(cipher))}
  end

  # "The cipher string @STRENGTH can be used at any point to sort the
  # current cipher list in order of encryption algorithm key length."
  defp sort_by_strength(state) do
    sorted =
      state.included
      |> Enum.map(fn suite -> {@key_size[elem(suite, 1)], suite} end)
      |> Enum.sort_by(&elem(&1, 0), &>=/2)
      |> Enum.map(&elem(&1, 1))

    %{state | included: sorted}
  end

  # "Lists of cipher suites can be combined in a single cipher string
  # using the + character."
  defp cipher_string(cipher) do
    case openssl_suite(cipher) do
      nil ->
        cipher
        |> String.split("+")
        |> find(all())

      suite ->
        [suite]
    end
  end

  # Select only those cipher suites from `acc` that match all the given
  # criteria
  defp find([], acc), do: acc

  defp find([cipher | more], acc) do
    ciphers = find(cipher)
    find(more, Enum.filter(acc, &(&1 in ciphers)))
  end

  defp find("ALL"), do: all() -- find("COMPLEMENTOFALL")
  defp find("COMPLEMENTOFDEFAULT"), do: find("ALL") -- default()
  defp find("COMPLEMENTOFALL"), do: cipher_string("eNULL")

  defp find("HIGH"), do: all_with_cipher(@high)
  defp find("MEDIUM"), do: all_with_cipher(@medium)
  defp find("LOW"), do: all_with_cipher(@low)

  defp find("eNULL"), do: all_with_cipher(:null)
  defp find("NULL"), do: find("eNULL")
  defp find("aNULL"), do: all_with_key_exchange([:dh_anon, :ecdh_anon])

  defp find("kRSA"), do: all_with_key_exchange(:rsa)
  defp find("RSA"), do: find("kRSA")
  defp find("aRSA"), do: all_with_key_exchange([:rsa, :dhe_rsa, :srp_rsa, :ecdhe_rsa])
  defp find("kDHr"), do: all_with_key_exchange(:dh_rsa)
  defp find("kDHd"), do: all_with_key_exchange(:dh_dss)
  defp find("kDH"), do: all_with_key_exchange([:dh_rsa, :dh_dss])
  defp find("kDHE"), do: all_with_key_exchange([:dhe_rsa, :dhe_dss, :dh_anon, :dhe_psk])
  defp find("kEDH"), do: find("kDHE")

  defp find("DH"),
    do: all_with_key_exchange([:dh_rsa, :dh_dss, :dhe_rsa, :dhe_dss, :dh_anon, :dhe_psk])

  defp find("DHE"), do: all_with_key_exchange([:dhe_rsa, :dhe_dss, :dhe_psk])
  defp find("EDH"), do: find("DHE")
  defp find("ADH"), do: all_with_key_exchange(:dh_anon)
  defp find("kEECDH"), do: all_with_key_exchange([:ecdhe_rsa, :ecdhe_ecdsa, :ecdh_anon])
  defp find("kECDHE"), do: find("kEECDH")

  defp find("ECDH"),
    do: all_with_key_exchange([:ecdhe_rsa, :ecdhe_ecdsa, :ecdh_rsa, :ecdh_ecdsa, :ecdh_anon])

  defp find("ECDHE"), do: all_with_key_exchange([:ecdhe_rsa, :ecdhe_ecdsa])
  defp find("EECDH"), do: find("ECDHE")
  defp find("AECDH"), do: all_with_key_exchange(:ecdh_anon)
  defp find("aDSS"), do: all_with_key_exchange([:dhe_dss, :srp_dss])
  defp find("DSS"), do: find("aDSS")
  defp find("aDH"), do: all_with_key_exchange([:dh_rsa, :dh_dss])
  defp find("aECDSA"), do: all_with_key_exchange(:ecdhe_ecdsa)
  defp find("ECDSA"), do: find("aECDSA")

  defp find("SSLv3") do
    # Baseline ciphersuites, no AEAD, fixed PRF; note that many
    # implementations didn't add ECC support until TLS 1.0 or later, but
    # technically they can be used with SSLv3
    find_all(
      [
        :ecdhe_ecdsa,
        :ecdhe_rsa,
        :ecdh_ecdsa,
        :ecdh_rsa,
        :dhe_rsa,
        :dhe_dss,
        :rsa,
        :dh_anon,
        :ecdh_anon,
        :dhe_psk,
        :rsa_psk,
        :psk,
        :srp_anon,
        :srp_rsa,
        :srp_dss
      ],
      [:aes_256_cbc, :"3des_ede_cbc", :aes_128_cbc, :des_cbc, :rc4_128, :null],
      [:sha, :md5],
      [:default_prf]
    )
  end

  defp find("TLSv1.0") do
    []
  end

  defp find("TLSv1.2") do
    # TLS 1.2 adds AEAD ciphers, HMAC-SHA256 and new pseudo-random function
    # (PRF) options
    find_any([], [:chacha20_poly1305, :aes_256_gcm, :aes_128_gcm], [:null, :sha256, :sha384], [
      :sha256,
      :sha384
    ])
  end

  defp find("AES128"), do: all_with_cipher([:aes_128_cbc, :aes_128_gcm])
  defp find("AES256"), do: all_with_cipher([:aes_256_cbc, :aes_256_gcm])
  defp find("AES"), do: all_with_cipher([:aes_128_cbc, :aes_128_gcm, :aes_256_cbc, :aes_256_gcm])
  defp find("AESGCM"), do: all_with_cipher([:aes_128_gcm, :aes_256_gcm])
  defp find("CHACHA20"), do: all_with_cipher(:chacha20)
  defp find("3DES"), do: all_with_cipher(:"3des_ede_cbc")
  defp find("DES"), do: all_with_cipher(:des_cbc)
  defp find("RC4"), do: all_with_cipher(:rc4_128)
  defp find("IDEA"), do: all_with_cipher(:idea_cbc)

  defp find("MD5"), do: all_with_hash(:md5)
  defp find("SHA1"), do: all_with_hash(:sha)
  defp find("SHA"), do: find("SHA1")
  defp find("SHA256"), do: all_with_hash(:sha256)
  defp find("SHA384"), do: all_with_hash(:sha384)

  defp find("kPSK"), do: all_with_key_exchange(:psk)
  defp find("PSK"), do: find("kPSK")
  defp find("kDHEPSK"), do: all_with_key_exchange(:dhe_psk)
  defp find("kRSAPSK"), do: all_with_key_exchange(:rsa_psk)
  defp find("aPSK"), do: all_with_key_exchange([:psk, :dhe_psk, :rsa_psk])

  defp find("kSRP"), do: all_with_key_exchange([:srp, :srp_rsa, :srp_dss, :srp_anon])
  defp find("SRP"), do: find("kSRP")
  defp find("aSRP"), do: all_with_key_exchange(:srp_anon)

  # Unsupported
  defp find("AESCCM"), do: []
  defp find("AESCCM8"), do: []
  defp find("CAMELLIA128"), do: []
  defp find("CAMELLIA256"), do: []
  defp find("CAMELLIA"), do: []
  defp find("RC2"), do: []
  defp find("SEED"), do: []

  defp find("aGOST"), do: []
  defp find("aGOST01"), do: []
  defp find("kGOST"), do: []
  defp find("GOST94"), do: []
  defp find("GOST89MAC"), do: []

  defp find("kECDHEPSK"), do: []

  defp merge(a, b) do
    Enum.uniq(a ++ b)
  end

  defp find_all(key_exchanges, ciphers, hash_functions, prfs) do
    Enum.filter(all(), fn
      {key_exchange, cipher, hash} ->
        key_exchange in key_exchanges and cipher in ciphers and hash in hash_functions and
          :default_prf in prfs

      {key_exchange, cipher, hash, prf} ->
        key_exchange in key_exchanges and cipher in ciphers and hash in hash_functions and
          prf in prfs
    end)
  end

  defp find_any(key_exchanges, ciphers, hash_functions, prfs) do
    Enum.filter(all(), fn
      {key_exchange, cipher, hash} ->
        key_exchange in key_exchanges or cipher in ciphers or hash in hash_functions or
          :default_prf in prfs

      {key_exchange, cipher, hash, prf} ->
        key_exchange in key_exchanges or cipher in ciphers or hash in hash_functions or
          prf in prfs
    end)
  end

  defp all_with_key_exchange(key_exchanges) when is_list(key_exchanges) do
    Enum.filter(all(), &(elem(&1, 0) in key_exchanges))
  end

  defp all_with_key_exchange(key_exchange) do
    Enum.filter(all(), &(elem(&1, 0) == key_exchange))
  end

  defp all_with_cipher(ciphers) when is_list(ciphers) do
    Enum.filter(all(), &(elem(&1, 1) in ciphers))
  end

  defp all_with_cipher(cipher) do
    Enum.filter(all(), &(elem(&1, 1) == cipher))
  end

  defp all_with_hash(hash) do
    Enum.filter(all(), &(elem(&1, 2) == hash))
  end

  defp openssl_suite(cipher_name) do
    definition =
      cipher_name
      |> String.to_charlist()
      |> :ssl_cipher.openssl_suite()
      |> :ssl_cipher.suite_definition()

    case definition do
      %{key_exchange: key_exchange, cipher: cipher, mac: mac, prf: prf} ->
        {key_exchange, cipher, mac, prf}

      tuple ->
        tuple
    end
  rescue
    FunctionClauseError -> nil
  end
end
