## Regression for the "network worker hangs forever in teardown close() on a
## black-holed TLS peer" bug that threecode hit on flaky mobile links.
##
## Scenario: the server completes the TLS handshake (so a real StreamConn
## exists) but then never sends anything and never closes, mirroring a link
## that died mid-response. A graceful `close()` runs a bidirectional TLS
## `close_notify` whose second leg blocks forever waiting for the peer's
## close_notify (and, under the stdlib's `blockSigpipe`, also blocks in
## `sigwait` for a SIGPIPE that never arrives). `abruptClose` must instead
## tear the fd down directly (SO_LINGER=0 + posix.close) and return bounded.
##
## Before the fix threecode's network worker leaked a thread stuck in
## close()/sigwait for the life of the process; Ctrl-C/ESC could not cancel
## it because the interrupt path only `shutdown`s a blocked recv, not close.
import std/[net, os, osproc, strutils, times, unittest]
import streamhttp

const
  CertPath = "/tmp/sh_cert.pem"
  KeyPath = "/tmp/sh_key.pem"

proc ensureCert(): bool =
  if fileExists(CertPath) and fileExists(KeyPath): return true
  let (_, code) = execCmdEx("openssl req -x509 -newkey rsa:2048 -keyout " &
    KeyPath & " -out " & CertPath & " -days 1 -nodes -subj /CN=localhost")
  fileExists(CertPath) and fileExists(KeyPath) and code == 0

type
  BlackHoleArgs = tuple[listener: Socket]
var holeThread: Thread[BlackHoleArgs]

proc blackHoleServer(a: BlackHoleArgs) {.thread, gcsafe.} =
  ## Complete the TLS handshake, then hold the connection open silently
  ## forever (until the client hangs up). Mirrors a dead-but-not-FIN'd link.
  {.cast(gcsafe).}:
    try:
      var client: Socket
      a.listener.accept(client)
      let ctx = newContext(verifyMode = CVerifyNone,
                           certFile = CertPath, keyFile = KeyPath)
      ctx.wrapConnectedSocket(client, handshake = handshakeAsServer)
      # Read the request so the client's sendRequest completes, then sit.
      var got = ""
      let deadline = epochTime() + 30.0
      while epochTime() < deadline:
        let chunk = try: client.recv(512) except CatchableError: ""
        got.add chunk
        if got.contains("\r\n\r\n"): break
      while epochTime() < deadline:
        sleep(100)
      try: client.close() except CatchableError: discard
    except CatchableError: discard
    try: a.listener.close() except CatchableError: discard

suite "abruptClose does not block on a black-holed TLS peer":
  test "abruptClose returns bounded where graceful close would hang":
    if not ensureCert():
      check true  # openssl absent; skip
    else:
      let listener = newSocket(buffered = false)
      listener.setSockOpt(OptReuseAddr, true)
      listener.bindAddr(Port(0))
      listener.listen()
      let (_, port) = listener.getLocalAddr()
      createThread(holeThread, blackHoleServer, (listener,))
      defer: joinThread(holeThread)

      let ctx = newContext(verifyMode = CVerifyNone)
      var sock = newSocket(buffered = false)
      ctx.wrapSocket(sock)
      sock.connect("127.0.0.1", port, timeout = 5000)
      let c = newStreamConn(sock, ctx)
      # Drive a request so the connection is fully established and alive.
      c.sendRequest("GET", "/x", "127.0.0.1")

      # The peer has black-holed: a graceful close() would block in
      # SSL_shutdown waiting for the peer's close_notify (and in sigwait).
      # abruptClose must tear down within a small bound.
      let fromClose = epochTime()
      c.abruptClose()
      let elapsed = epochTime() - fromClose
      check elapsed < 2.0
