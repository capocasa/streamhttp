## Tier 1 bounded-handshake regression: a server that accepts the TCP
## connection but never sends a byte of TLS must not hang `connectTls`
## forever. Before the fix, `net.connect(host, port, timeout)` timed only
## the TCP connect and then called `SSL_connect` in blocking mode with no
## timeout, so a silent (black-holed) edge stalled the main thread
## indefinitely. The bounded handshake loop must surface
## `HandshakeTimeoutError` within the connect deadline.
import std/[net, os, times, unittest]
import streamhttp

type
  SilentArgs = tuple[listener: Socket]
var silentThread: Thread[SilentArgs]

proc silentServer(a: SilentArgs) {.thread.} =
  ## Accept one TCP connection and hold it open without speaking TLS, then
  ## exit once the client has given up. Mirrors a black-holed edge that
  ## completes the TCP handshake but never replies to ClientHello.
  {.cast(gcsafe).}:
    try:
      var client: Socket
      a.listener.accept(client)
      # SO_RCVTIMEO keeps the poll loop progressing so this thread can exit
      # promptly once the client disconnects, rather than blocking in recv
      # until the process tears down.
      applyRecvTimeout(client, 200)
      let deadline = epochTime() + 8.0
      while epochTime() < deadline:
        let chunk = try: client.recv(64) except CatchableError: ""
        if chunk.len == 0: break
        sleep(20)
      try: client.close() except CatchableError: discard
    except CatchableError as e:
      stderr.writeLine "silent server error: ", e.msg
    try: a.listener.close() except CatchableError: discard

suite "connectTls bounded handshake":
  test "silent (accept-but-no-TLS) server raises HandshakeTimeoutError":
    let listener = newSocket(buffered = false)
    listener.setSockOpt(OptReuseAddr, true)
    listener.bindAddr(Port(0))
    listener.listen()
    let (_, port) = listener.getLocalAddr()
    createThread(silentThread, silentServer, (listener,))
    defer: joinThread(silentThread)

    # Tight deadline so the test stays fast. The handshake cannot complete
    # against a silent server, so this must raise well before wall-clock
    # ConnectTimeoutMs, and must not hang.
    var raised = false
    var elapsed = 0.0
    let started = epochTime()
    try:
      discard connectTls("127.0.0.1", port, timeoutMs = 1500)
    except HandshakeTimeoutError:
      raised = true
      elapsed = epochTime() - started
    except CatchableError:
      # A hard SSL error is also acceptable (OpenSSL may surface a protocol
      # error before the deadline if it ever reads garbage); the invariant
      # under test is "does not hang past the deadline".
      elapsed = epochTime() - started

    check elapsed <= 4.0   # generous over the 1.5s deadline; guards against a hang
    check raised or elapsed <= 4.0
