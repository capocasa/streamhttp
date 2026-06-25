import std/[net, os, strutils, tables, unittest]
import streamhttp

# ---------- BodyDecoder unit tests ----------

# Canonical drain pattern: keep calling decode, collect emitted bytes
# regardless of result code, stop on drDone or drError. drDone implies
# "body complete; any bytes from this call are in `buf`". drNeedMore is
# the only result that doesn't advance.
proc drain(d: var BodyDecoder): tuple[got: string, final: DecodeResult] =
  while true:
    var buf = ""
    let r = d.decode(buf)
    result.got.add buf
    if r != drBytes:
      result.final = r
      return

suite "BodyDecoder: identity sized":
  test "exact length, single feed":
    var d = initBodyDecoder(beIdentity, contentLength = 5)
    d.feed("hello")
    let (got, final) = drain(d)
    check got == "hello"
    check final == drDone

  test "exact length, partial feeds":
    var d = initBodyDecoder(beIdentity, contentLength = 12)
    var got = ""
    d.feed("hello, ")
    let (a, ra) = drain(d)
    got.add a
    check ra == drNeedMore
    d.feed("world!")
    let (b, rb) = drain(d)
    got.add b
    check rb == drDone
    check got == "hello, world"

  test "extra bytes past content-length are left dangling":
    var d = initBodyDecoder(beIdentity, contentLength = 5)
    d.feed("hellotail")
    let (got, final) = drain(d)
    check got == "hello"
    check final == drDone

  test "zero-length body":
    var d = initBodyDecoder(beIdentity, contentLength = 0)
    let (got, final) = drain(d)
    check got == ""
    check final == drDone

suite "BodyDecoder: identity until-close":
  test "yields what's buffered, stops on markEof":
    var d = initBodyDecoder(beIdentity)
    d.feed("first")
    let (a, ra) = drain(d)
    check a == "first"
    check ra == drNeedMore
    d.feed("more")
    let (b, rb) = drain(d)
    check b == "more"
    check rb == drNeedMore
    d.markEof()
    let (c, rc) = drain(d)
    check c == ""
    check rc == drDone

suite "BodyDecoder: chunked":
  test "single chunk + terminator":
    var d = initBodyDecoder(beChunked)
    d.feed("5\r\nhello\r\n0\r\n\r\n")
    let (got, final) = drain(d)
    check got == "hello"
    check final == drDone

  test "multiple chunks":
    var d = initBodyDecoder(beChunked)
    d.feed("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
    let (got, final) = drain(d)
    check got == "helloworld"
    check final == drDone

  test "chunk header split across feeds":
    var d = initBodyDecoder(beChunked)
    d.feed("5")
    let (a, ra) = drain(d)
    check a == ""
    check ra == drNeedMore
    d.feed("\r\nhello\r\n0\r\n\r\n")
    let (b, rb) = drain(d)
    check b == "hello"
    check rb == drDone

  test "chunk body split across feeds":
    var d = initBodyDecoder(beChunked)
    d.feed("a\r\nhel")
    var got = ""
    let (a, ra) = drain(d)
    got.add a
    check ra == drNeedMore
    d.feed("loworld\r\n0\r\n\r\n")
    let (b, rb) = drain(d)
    got.add b
    check got == "helloworld"
    check rb == drDone

  test "chunk extension after semicolon is ignored":
    var d = initBodyDecoder(beChunked)
    d.feed("5;name=value\r\nhello\r\n0\r\n\r\n")
    let (got, final) = drain(d)
    check got == "hello"
    check final == drDone

  test "trailer headers are discarded":
    var d = initBodyDecoder(beChunked)
    d.feed("5\r\nhello\r\n0\r\nFoo: bar\r\nBaz: qux\r\n\r\n")
    let (got, final) = drain(d)
    check got == "hello"
    check final == drDone

  test "uppercase hex size accepted":
    var d = initBodyDecoder(beChunked)
    d.feed("A\r\nhelloworld\r\n0\r\n\r\n")
    let (got, final) = drain(d)
    check got == "helloworld"
    check final == drDone

  test "large hex size accepted (mixed case)":
    var d = initBodyDecoder(beChunked)
    let body = "x".repeat(0x1AB)
    d.feed("1aB\r\n" & body & "\r\n0\r\n\r\n")
    let (got, final) = drain(d)
    check got == body
    check final == drDone

  test "malformed chunk size returns drError":
    var d = initBodyDecoder(beChunked)
    d.feed("nope\r\n")
    let (_, final) = drain(d)
    check final == drError

  test "missing CRLF after chunk body returns drError":
    var d = initBodyDecoder(beChunked)
    d.feed("5\r\nhelloXX0\r\n\r\n")
    let (got, final) = drain(d)
    check got == "hello"
    check final == drError

# ---------- StreamConn integration: local TCP server ----------

# Tiny one-shot HTTP server in a thread. Accepts one connection,
# discards the request up to the first blank line, sends a canned
# response, closes the connection. Used to drive `StreamConn` end to end
# without a real network.

type
  ServerArgs = tuple[listener: Socket, canned: string]

var srvThread: Thread[ServerArgs]

proc serverThread(args: ServerArgs) {.thread, gcsafe.} =
  {.cast(gcsafe).}:
    try:
      var client: Socket
      args.listener.accept(client)
      # don't bother parsing the request; we know what the test sends and
      # we just need to blast the canned response back. Reading the
      # request is a needless coordination point that can deadlock if
      # client send happens to be small or the kernel buffers oddly.
      client.send(args.canned)
      client.close()
    except CatchableError as e:
      stderr.writeLine "server thread error: ", e.msg
    try: args.listener.close() except CatchableError: discard

proc startServer(canned: string): Port =
  let listener = newSocket(buffered = false)
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(0))
  listener.listen()
  let (_, port) = listener.getLocalAddr()
  createThread(srvThread, serverThread, (listener, canned))
  port

proc joinServer() =
  joinThread(srvThread)

suite "StreamConn end-to-end (plain TCP)":
  test "chunked SSE-style response yields lines as they arrive":
    let canned =
      "HTTP/1.1 200 OK\r\n" &
      "Content-Type: text/event-stream\r\n" &
      "Transfer-Encoding: chunked\r\n" &
      "\r\n" &
      # three SSE events split across three chunks
      "10\r\ndata: first\n\ndat\r\n" &     # 16 bytes: "data: first\n\ndat"
      "12\r\na: second\n\ndata: t\r\n" &    # 18 bytes: "a: second\n\ndata: t"
      "6\r\nhird\n\n\r\n" &                  # 6 bytes:  "hird\n\n"
      "0\r\n\r\n"                             # terminator
    let port = startServer(canned)
    defer: joinServer()
    let c = connectPlain("127.0.0.1", port)
    defer: c.close()
    c.sendRequest("GET", "/", "127.0.0.1")
    let resp = c.readResponseHead()
    check resp.status == 200
    check "chunked" in resp.headers.getOrDefault("transfer-encoding")
    var got: seq[string]
    var line = ""
    while c.readLine(line):
      got.add line
    # Body bytes after decoding: "data: first\n\ndata: second\n\ndata: third\n\n"
    # split on '\n' (with trailing \r stripped, but there's no \r here):
    check got == @["data: first", "", "data: second", "", "data: third", ""]

  test "content-length response":
    let canned =
      "HTTP/1.1 200 OK\r\n" &
      "Content-Type: text/plain\r\n" &
      "Content-Length: 27\r\n" &
      "\r\n" &
      "line one\nline two\nline 3!!\n"
    let port = startServer(canned)
    defer: joinServer()
    let c = connectPlain("127.0.0.1", port)
    defer: c.close()
    c.sendRequest("GET", "/", "127.0.0.1")
    let resp = c.readResponseHead()
    check resp.status == 200
    check resp.headers.getOrDefault("content-length") == "27"
    var got: seq[string]
    var line = ""
    while c.readLine(line):
      got.add line
    check got == @["line one", "line two", "line 3!!"]

  test "until-close response":
    let canned =
      "HTTP/1.1 200 OK\r\n" &
      "Content-Type: text/plain\r\n" &
      "Connection: close\r\n" &
      "\r\n" &
      "alpha\nbeta\ngamma"
    let port = startServer(canned)
    defer: joinServer()
    let c = connectPlain("127.0.0.1", port)
    defer: c.close()
    c.sendRequest("GET", "/", "127.0.0.1")
    let resp = c.readResponseHead()
    check resp.status == 200
    var got: seq[string]
    var line = ""
    while c.readLine(line):
      got.add line
    # final line has no trailing \n, but readLine still returns it on EOF
    check got == @["alpha", "beta", "gamma"]

  test "keep-alive: same conn handles back-to-back requests":
    # Server stays open between two responses; we send two requests on
    # one StreamConn. Without the per-response state reset in
    # `readResponseHead`, the second body would short-circuit because
    # the first body's `bodyDone` is still set.
    let resp1 =
      "HTTP/1.1 200 OK\r\n" &
      "Content-Length: 5\r\n" &
      "\r\n" &
      "first"
    let resp2 =
      "HTTP/1.1 200 OK\r\n" &
      "Transfer-Encoding: chunked\r\n" &
      "\r\n" &
      "6\r\nsecond\r\n" &
      "0\r\n\r\n"
    type KaArgs = tuple[listener: Socket, r1, r2: string]
    proc kaThread(a: KaArgs) {.thread, gcsafe.} =
      {.cast(gcsafe).}:
        try:
          var client: Socket
          a.listener.accept(client)
          for response in [a.r1, a.r2]:
            var got = ""
            while not got.contains("\r\n\r\n"):
              let chunk = try: client.recv(512) except CatchableError: ""
              if chunk.len == 0: break
              got.add chunk
            client.send(response)
          client.close()
        except CatchableError as e:
          stderr.writeLine "ka server: ", e.msg
        try: a.listener.close() except CatchableError: discard
    var th: Thread[KaArgs]
    let listener = newSocket(buffered = false)
    listener.setSockOpt(OptReuseAddr, true)
    listener.bindAddr(Port(0))
    listener.listen()
    let (_, port) = listener.getLocalAddr()
    createThread(th, kaThread, (listener, resp1, resp2))
    defer: joinThread(th)
    let c = connectPlain("127.0.0.1", port)
    defer: c.close()
    c.sendRequest("GET", "/one", "127.0.0.1")
    let r1 = c.readResponseHead()
    check r1.status == 200
    var line = ""
    var got1: seq[string]
    while c.readLine(line): got1.add line
    check got1 == @["first"]
    c.sendRequest("GET", "/two", "127.0.0.1")
    let r2 = c.readResponseHead()
    check r2.status == 200
    var got2: seq[string]
    while c.readLine(line): got2.add line
    check got2 == @["second"]

  test "non-2xx status surfaces":
    let canned =
      "HTTP/1.1 429 Too Many Requests\r\n" &
      "Retry-After: 30\r\n" &
      "Content-Length: 5\r\n" &
      "\r\n" &
      "limit"
    let port = startServer(canned)
    defer: joinServer()
    let c = connectPlain("127.0.0.1", port)
    defer: c.close()
    c.sendRequest("GET", "/", "127.0.0.1")
    let resp = c.readResponseHead()
    check resp.status == 429
    check resp.headers.getOrDefault("retry-after") == "30"
    var line = ""
    check c.readLine(line) == true
    check line == "limit"
    check c.readLine(line) == false

# ---------- Fragmented-delivery regression ----------
#
# The streaming-truncation bug was an OpenSSL internal-buffering issue that
# only manifests over real TLS (`net.recv(size, timeout)` mishandles
# `SSL_pending` bytes; see the note in streamhttp.nim). A plain-socket unit
# test cannot reproduce the TLS-internal part. What it CAN guard is the
# read-loop structure that replaced the broken `recv(size, timeout)` path:
# `recvChunk` must correctly re-assemble a body that arrives in many small
# fragments separated by delays, never declaring EOF early and never dropping
# a fragment. If a future change reintroduces a "0-byte recv = EOF" guess
# between fragments, this test fails.
#
# The server below sends each SSE chunk as its own `send` with a 15ms gap,
# so the client's `recvChunk` polls, reads one fragment, loops, polls again,
# etc. — exactly the cadence that exposed the original truncation.

type FragArgs = object
  listener: Socket

proc fragServer(args: FragArgs) {.thread, gcsafe.} =
  {.cast(gcsafe).}:
    try:
      var client: Socket
      args.listener.accept(client)
      # Send the head, then drip the chunked body one chunk per send with a
      # delay between each, so the recv loop has to poll repeatedly.
      client.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
      sleep 15
      for i in 1..12:
        let body = "data: line" & $i & "\n\n"
        client.send(toHex(body.len, 2) & "\r\n" & body & "\r\n")
        sleep 15
      client.send("0\r\n\r\n")
      client.close()
    except CatchableError as e:
      stderr.writeLine "frag server: ", e.msg
    try: args.listener.close() except CatchableError: discard

suite "StreamConn fragmented-delivery regression":
  test "drip-fed chunked body reassembles with no truncation (poll path)":
    var fragTh: Thread[FragArgs]
    let listener = newSocket(buffered = false)
    listener.setSockOpt(OptReuseAddr, true)
    listener.bindAddr(Port(0))
    listener.listen()
    let (_, port) = listener.getLocalAddr()
    createThread(fragTh, fragServer, FragArgs(listener: listener))
    defer: joinThread(fragTh)
    let c = connectPlain("127.0.0.1", port)
    defer: c.close()
    # A short readTimeoutMs forces recvChunk through the pollReadable path
    # (the path the fix rewrote) instead of the plain blocking branch.
    c.readTimeoutMs = 2000
    c.sendRequest("POST", "/", "127.0.0.1", body = "{}")
    let resp = c.readResponseHead()
    check resp.status == 200
    var got: seq[string]
    var line = ""
    while c.readLine(line):
      got.add line
    # Body decodes to 12 SSE lines, each "data: lineN" followed by a blank.
    check got.len == 24
    check got[0] == "data: line1"
    check got[1] == ""
    check got[22] == "data: line12"
    check got[23] == ""
