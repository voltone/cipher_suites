defmodule CipherSuitesTest do
  use ExUnit.Case
  doctest CipherSuites

  @certfile Path.join([__DIR__, "cert", "server.crt"])
  @keyfile  Path.join([__DIR__, "cert", "server.key"])

  test "all" do
    assert CipherSuites.select("ALL") == CipherSuites.all()
  end

  test "default" do
    assert CipherSuites.select("DEFAULT") == CipherSuites.default()
  end

  test "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA" do
    assert CipherSuites.select("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA") == [
      {:ecdhe_rsa, :aes_256_gcm, :null, :sha384},
      {:ecdhe_rsa, :aes_256_cbc, :sha, :default_prf}
    ]
  end

  test "aRSA+kEDH+AES256" do
    assert CipherSuites.select("aRSA+kEDH+AES256") == [
      {:dhe_rsa, :aes_256_gcm, :null, :sha384},
      {:dhe_rsa, :aes_256_cbc, :sha256},
      {:dhe_rsa, :aes_256_cbc, :sha}
    ]
  end

  test "aRSA+kEDH+AES256:-SSLv3" do
    assert CipherSuites.select("aRSA+kEDH+AES256:-SSLv3") == [
      {:dhe_rsa, :aes_256_gcm, :null, :sha384},
      {:dhe_rsa, :aes_256_cbc, :sha256}
    ]
  end

  test "aRSA+kEDH+SHA" do
    assert CipherSuites.select("aRSA+kEDH+SHA") == [
      {:dhe_rsa, :aes_256_cbc, :sha},
      {:dhe_rsa, :"3des_ede_cbc", :sha},
      {:dhe_rsa, :aes_128_cbc, :sha},
      {:dhe_rsa, :des_cbc, :sha}
    ]
  end

  test "aRSA+kEDH+SHA:@STRENGTH" do
    assert CipherSuites.select("aRSA+kEDH+SHA:@STRENGTH") == [
      {:dhe_rsa, :aes_256_cbc, :sha},
      {:dhe_rsa, :aes_128_cbc, :sha},
      {:dhe_rsa, :"3des_ede_cbc", :sha},
      {:dhe_rsa, :des_cbc, :sha}
    ]
  end

  test "aRSA+kEECDH+SHA256:aRSA+kEDH+SHA256:+AES128" do
    assert CipherSuites.select("aRSA+kEECDH+SHA256:aRSA+kEDH+SHA256:+AES128") == [
      {:dhe_rsa, :aes_256_cbc, :sha256},
      {:ecdhe_rsa, :aes_128_cbc, :sha256, :sha256},
      {:dhe_rsa, :aes_128_cbc, :sha256}
    ]
  end

  test "!MEDIUM:!LOW:kRSA+SHA" do
    assert CipherSuites.select("!MEDIUM:!LOW:kRSA+SHA") == [
      {:rsa, :aes_256_cbc, :sha},
      {:rsa, :"3des_ede_cbc", :sha},
      {:rsa, :aes_128_cbc, :sha}
    ]
  end

  test "connection through :ssl" do
    Application.ensure_all_started(:ssl)

    server_ciphers = CipherSuites.select("aRSA+kEECDH")
    client_ciphers = CipherSuites.select("aRSA+AES256+AESGCM")
    expected_cipher = hd(Enum.filter(server_ciphers, &(&1 in client_ciphers)))

    assert {:ok, listen} = :ssl.listen(0, [
      certfile: @certfile,
      keyfile: @keyfile,
      ciphers: server_ciphers,
      honor_cipher_order: true,
      active: false,
    ])
    {:ok, {_, server_port}} = :ssl.sockname(listen)

    spawn fn ->
      {:ok, client} = :ssl.connect({127, 0, 0, 1}, server_port, [
        ciphers: client_ciphers,
        active: false,
      ], 500)
      :ssl.send(client, 'Hello, world!\n')
      :ssl.close(client)
    end

    assert {:ok, server} = :ssl.transport_accept(listen, 500)
    assert :ok = :ssl.ssl_accept(server, [], 500)
    assert {:ok, 'Hello, world!\n'} = :ssl.recv(server, 0, 500)
    assert {:ok, [cipher_suite: ^expected_cipher]} =
      :ssl.connection_information(server, [:cipher_suite])

    :ssl.close(server)
  end

end
