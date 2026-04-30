import std/[net, strutils, tables, unittest]
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
