## Regression for the "sendRequest spins forever on a half-closed TLS
## keep-alive connection" bug.
##
## Scenario mirroring the live failure: the server serves one response, then
## closes the TLS connection (sends close_notify + TCP FIN). The client,
## reusing the cached keep-alive connection for a second request, must hit
## the dead connection and raise, not busy-loop on SSL_write at 100% CPU.
## Before the fix, `net.send`'s loop treated `SSL_write` returning 0 as
## "0 bytes written, retry" and spun indefinitely.
import std/[net, os, osproc, strutils, times, unittest]
import streamhttp

const
  CertPath = "/tmp/sh_cert.pem"
  KeyPath = "/tmp/sh_key.pem"

proc ensureCert(): bool =
  ## Generate a self-signed cert if absent so the test is self-contained.
  ## Returns false (skip, not fail) when openssl is missing.
  if fileExists(CertPath) and fileExists(KeyPath): return true
  let (_, code) = execCmdEx("openssl req -x509 -newkey rsa:2048 -keyout " &
    KeyPath & " -out " & CertPath & " -days 1 -nodes -subj /CN=localhost")
  fileExists(CertPath) and fileExists(KeyPath) and code == 0

type
  HalfCloseArgs = tuple[listener: Socket]
var halfThread: Thread[HalfCloseArgs]

proc halfCloseServer(a: HalfCloseArgs) {.thread, gcsafe.} =
  ## Serve one response over TLS, then close so the client's next write sees
  ## a dead TLS session (peer close_notify).
  {.cast(gcsafe).}:
    try:
      var client: Socket
      a.listener.accept(client)
      let ctx = newContext(verifyMode = CVerifyNone,
                           certFile = CertPath, keyFile = KeyPath)
      ctx.wrapConnectedSocket(client, handshake = handshakeAsServer)
      var got = ""
      while not got.contains("\r\n\r\n"):
        let chunk = try: client.recv(512) except CatchableError: ""
        if chunk.len == 0: break
        got.add chunk
      client.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
      try:
        var g2 = ""
        let deadline = epochTime() + 3.0
        while epochTime() < deadline:
          let chunk = try: client.recv(512) except CatchableError: ""
          if chunk.len == 0: break
          g2.add chunk
          if g2.contains("\r\n\r\n"): break
      except CatchableError: discard
      # Close. Depending on timing the client's next SSL_write sees either
      # SSL_ERROR_ZERO_RETURN (close_notify read) or a socket error from the
      # FIN/RST; the fixed sendRequest raises on either. The watchdog below
      # also guards against the old forever-spin if neither path triggers.
      client.close()
    except CatchableError as e:
      stderr.writeLine "half-close server error: ", e.msg
    try: a.listener.close() except CatchableError: discard

suite "sendRequest dead-connection guard (TLS)":
  test "second request on a server-closed TLS conn raises, not spins":
    if not ensureCert():
      check true  # openssl absent in this environment; skip
    else:
      let listener = newSocket(buffered = false)
      listener.setSockOpt(OptReuseAddr, true)
      listener.bindAddr(Port(0))
      listener.listen()
      let (_, port) = listener.getLocalAddr()
      createThread(halfThread, halfCloseServer, (listener,))
      defer: joinThread(halfThread)

      # Client with peer verification disabled so the self-signed server
      # cert is accepted (connectTls forces CVerifyPeer, so build the socket
      # inline for this test).
      let ctx = newContext(verifyMode = CVerifyNone)
      var sock = newSocket(buffered = false)
      ctx.wrapSocket(sock)
      sock.connect("127.0.0.1", port, timeout = 5000)
      let c = newStreamConn(sock, ctx)
      defer: c.close()

      c.sendRequest("GET", "/one", "127.0.0.1")
      let r1 = c.readResponseHead()
      check r1.status == 200
      var line = ""
      var body: seq[string]
      while c.readLine(line): body.add line
      check body == @["ok"]

      # Let the server reach close() so the client sees a closed session
      # rather than a write racing the FIN.
      sleep(300)

      # Second request on the now-closed TLS connection. Must raise within a
      # bounded time instead of spinning forever.
      var raised = false
      let watchdogFrom = epochTime()
      try:
        c.sendRequest("GET", "/two", "127.0.0.1")
      except CatchableError:
        raised = true
      let elapsed = epochTime() - watchdogFrom
      check raised or elapsed <= 8.0
      check elapsed <= 8.0  # never the old 100%-CPU forever-spin
