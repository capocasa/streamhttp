## Regression: a blocking `connectTls`/`connectPlain` to a server that
## accepts the TCP connection but never completes the TLS handshake (a
## black-holed edge) must be interruptible by `shutdown(fd)` once the fd is
## published via the `onConnectingFd` hook.
##
## Before the fix there was no hook, so the caller had no fd to shut down
## until `connectTls` returned, and a silent edge pinned the caller for the
## full connect budget regardless of any interrupt. With the hook the fd is
## known the instant the socket is created, before the blocking connect, so a
## `shutdown` from another thread wakes the connect's internal `poll` and the
## connect raises within milliseconds.
import std/[net, os, posix, strutils, times, unittest]
import streamhttp

when defined(windows):
  # The POSIX `shutdown` wake of a blocked `poll`/`SSL_read` is the mechanism
  # under test; the Windows equivalent needs different handling. Re-enable
  # when the Windows path is covered.
  echo "SKIP: connect-interrupt regression only covers the POSIX path"
  quit 0

type
  SilentArgs = tuple[listener: Socket]

var
  silentThread: Thread[SilentArgs]
  connectThread: Thread[Port]
  gFd: posix.SocketHandle
  connectResult: string

proc onConnecting(fd: SocketHandle) {.gcsafe.} =
  gFd = posix.SocketHandle(fd)

proc silentServer(a: SilentArgs) {.thread, gcsafe.} =
  ## Accept one TCP connection and hold it open without speaking TLS, then
  ## exit once the client has given up. Mirrors a black-holed edge that
  ## completes the TCP handshake but never replies to ClientHello.
  {.cast(gcsafe).}:
    try:
      var client: Socket
      a.listener.accept(client)
      applyRecvTimeout(client, 200)
      let deadline = epochTime() + 8.0
      while epochTime() < deadline:
        let chunk = try: client.recv(64) except CatchableError: ""
        if chunk.len == 0: break
        sleep(20)
      try: client.close() except CatchableError: discard
    except CatchableError: discard
    try: a.listener.close() except CatchableError: discard

proc startSilentServer(): Port =
  let listener = newSocket(buffered = false)
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(0))
  listener.listen()
  let (_, port) = listener.getLocalAddr()
  createThread(silentThread, silentServer, (listener,))
  port

proc doConnectTls(p: Port) {.thread.} =
  {.cast(gcsafe).}:
    try:
      discard connectTls("127.0.0.1", p, timeoutMs = 30_000)
      connectResult = "connected (unexpected)"
    except CatchableError as e:
      connectResult = "raised: " & e.msg

template interruptDuringConnect(doConnectProc, label: untyped) =
  onConnectingFd = onConnecting
  let port = startSilentServer()
  gFd = posix.INVALID_SOCKET
  connectResult = ""
  let started = epochTime()
  createThread(connectThread, doConnectProc, port)
  # Wait for the hook to publish the connecting fd.
  var waited = 0
  while gFd == posix.INVALID_SOCKET and waited < 2000:
    sleep(10); waited += 10
  check gFd != posix.INVALID_SOCKET
  # Let the connect settle into the blocking handshake/recv wait, then shut
  # the fd down from this thread, simulating a Ctrl-C cancellation path.
  sleep(600)
  discard posix.shutdown(gFd, SHUT_RDWR)
  joinThread(connectThread)
  let elapsed = epochTime() - started
  joinThread(silentThread)

  echo "  ", label, " result: ", connectResult
  echo "  ", label, " elapsed: ", formatFloat(elapsed, ffDecimal, 2), "s"
  check elapsed < 3.0
  check connectResult.startsWith("raised:")
  onConnectingFd = nil

suite "connect interruptible via onConnectingFd + shutdown":
  test "shutdown during TLS handshake wakes connectTls":
    interruptDuringConnect(doConnectTls, "TLS")
