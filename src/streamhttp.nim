## Synchronous streaming HTTP/1.1 client.
##
## Reads response bodies as they arrive. The whole point: SSE / chunked
## transfer encoding without a subprocess `curl`, without an async
## runtime, without buffering the body before returning. A `StreamConn`
## wraps a `net.Socket` (TLS or plain) and yields one body line at a
## time as data trickles in. Block on `recv` like any sync client; the
## main thread waits for the next line the same way `outputStream.readLine`
## waits for a subprocess pipe.
##
## Scope: HTTP/1.1, chunked + content-length + until-close bodies, no
## redirects, no HTTP/2, no compression. Nothing the underlying stdlib
## doesn't already give us — the value is in the chunked-decoding
## state machine and the line-buffered API on top.

import std/[net, parseutils, strutils, tables]

type
  BodyEncoding* = enum
    beIdentity   ## plain — Content-Length, or until-close (HTTP/1.0 style)
    beChunked    ## Transfer-Encoding: chunked

  ChunkState = enum
    csNeedSize, csInChunk, csChunkEnd, csTrailer, csDone

  BodyDecoder* = object
    encoding*: BodyEncoding
    sized*: bool            ## identity only: contentRemaining is meaningful
    raw: string             ## raw socket bytes pending decode
    chunkRemaining: int     ## chunked: bytes left in current chunk
    contentRemaining: int   ## identity-sized: bytes left to read
    state: ChunkState
    closed: bool            ## socket EOF observed

  DecodeResult* = enum
    drBytes      ## body bytes appended to caller's buffer; may have more
    drNeedMore   ## feed more raw bytes to make progress
    drDone       ## body fully consumed
    drError      ## malformed input (chunked size unparseable etc.)

  StreamResponse* = object
    status*: int
    statusText*: string
    headers*: Table[string, string]   ## keys lowercased

  StreamConn* = ref object
    sock: Socket
    ctx: SslContext              ## kept alive for the connection's lifetime
    decoder: BodyDecoder
    headBuf: string              ## bytes pulled while reading head, may overlap into body
    lineBuf: string              ## decoded body bytes pending line split
    bodyDone: bool               ## decoder hit end-of-body
    closed: bool

# ---------- BodyDecoder (pure, testable) ----------

proc initBodyDecoder*(encoding: BodyEncoding;
                      contentLength: int = -1): BodyDecoder =
  ## `contentLength >= 0` and `encoding == beIdentity` → sized identity body.
  ## `contentLength < 0`  and `encoding == beIdentity` → read until close.
  ## `encoding == beChunked` → contentLength ignored.
  result.encoding = encoding
  result.state = csNeedSize
  if encoding == beIdentity and contentLength >= 0:
    result.sized = true
    result.contentRemaining = contentLength

proc feed*(d: var BodyDecoder; data: string) =
  ## Add raw socket bytes to the decoder.
  d.raw.add data

proc markEof*(d: var BodyDecoder) =
  ## Tell the decoder the socket has closed. Required for until-close
  ## identity bodies — without it, `decode` keeps returning `drNeedMore`
  ## forever. Idempotent.
  d.closed = true

proc decode*(d: var BodyDecoder; outBuf: var string): DecodeResult =
  ## Move body bytes from the internal raw buffer into `outBuf`. Returns
  ## `drBytes` if body bytes were emitted, `drNeedMore` if more raw bytes
  ## are needed, `drDone` when the body is fully consumed, `drError` on
  ## malformed input. Caller appends to `outBuf` across calls.
  case d.encoding
  of beIdentity:
    if d.sized:
      if d.contentRemaining == 0:
        return drDone
      let n = min(d.raw.len, d.contentRemaining)
      if n == 0:
        return drNeedMore
      outBuf.add d.raw[0 ..< n]
      d.raw = d.raw[n .. ^1]
      d.contentRemaining -= n
      return if d.contentRemaining == 0: drDone else: drBytes
    else:
      if d.raw.len > 0:
        outBuf.add d.raw
        d.raw.setLen 0
        return drBytes
      return if d.closed: drDone else: drNeedMore
  of beChunked:
    var emitted = false
    while true:
      case d.state
      of csNeedSize:
        let nl = d.raw.find("\r\n")
        if nl < 0:
          return if emitted: drBytes else: drNeedMore
        let header = d.raw[0 ..< nl]
        d.raw.delete(0 .. nl + 1)
        let semi = header.find(';')
        let sizeStr =
          if semi < 0: header.strip(chars = {' ', '\t', '\r'})
          else: header[0 ..< semi].strip(chars = {' ', '\t', '\r'})
        var size = 0
        let parsed = parseHex(sizeStr, size)
        if parsed == 0 or parsed != sizeStr.len:
          return drError
        if size == 0:
          d.state = csTrailer
        else:
          d.chunkRemaining = size
          d.state = csInChunk
      of csInChunk:
        if d.chunkRemaining == 0:
          d.state = csChunkEnd
          continue
        if d.raw.len == 0:
          return if emitted: drBytes else: drNeedMore
        let n = min(d.raw.len, d.chunkRemaining)
        outBuf.add d.raw[0 ..< n]
        d.raw.delete(0 ..< n)
        d.chunkRemaining -= n
        emitted = true
        if d.chunkRemaining == 0:
          d.state = csChunkEnd
        else:
          # partial chunk — drained `raw`, return so caller can pump more
          return drBytes
      of csChunkEnd:
        if d.raw.len < 2:
          return if emitted: drBytes else: drNeedMore
        if d.raw[0] != '\r' or d.raw[1] != '\n':
          return drError
        d.raw.delete(0 .. 1)
        d.state = csNeedSize
      of csTrailer:
        let nl = d.raw.find("\r\n")
        if nl < 0:
          return if emitted: drBytes else: drNeedMore
        if nl == 0:
          d.raw.delete(0 .. 1)
          d.state = csDone
          return drDone
        # discard one trailer header line; loop to read more
        d.raw.delete(0 .. nl + 1)
      of csDone:
        return drDone

# ---------- Socket helpers ----------

const RecvSize = 4096

proc recvIntoHead(c: StreamConn): bool =
  let chunk = try: c.sock.recv(RecvSize) except CatchableError: ""
  if chunk.len == 0: return false
  c.headBuf.add chunk
  true

proc readHeadLine(c: StreamConn): string =
  ## Consume up to and including the next CRLF in `headBuf`. Returns the
  ## line contents without the trailing CRLF. Raises `IOError` on EOF.
  while true:
    let nl = c.headBuf.find("\r\n")
    if nl >= 0:
      result = c.headBuf[0 ..< nl]
      c.headBuf.delete(0 .. nl + 1)
      return
    if not c.recvIntoHead():
      raise newException(IOError, "EOF before end of HTTP header")

# ---------- Public API ----------

proc newStreamConn*(sock: Socket; ctx: SslContext = nil): StreamConn =
  ## Wrap an already-connected (and TLS-handshaken if applicable) socket.
  ## Pass `ctx` so it stays alive as long as the connection — destroying
  ## the SslContext while the socket is still in use crashes openssl.
  StreamConn(sock: sock, ctx: ctx)

proc connectTls*(host: string; port: Port = Port(443);
                 timeoutMs: int = 20_000;
                 caFile: string = ""): StreamConn =
  ## Open a TLS connection. `caFile` is an optional CA bundle (skip
  ## scanning system locations when set). Returns a `StreamConn` ready
  ## for `sendRequest`.
  let ctx = newContext(verifyMode = CVerifyPeer, caFile = caFile)
  var sock = newSocket(buffered = false)
  ctx.wrapSocket(sock)
  sock.connect(host, port, timeout = timeoutMs)
  newStreamConn(sock, ctx)

proc connectPlain*(host: string; port: Port;
                   timeoutMs: int = 20_000): StreamConn =
  ## Open a plain (non-TLS) TCP connection. For testing against local
  ## servers, or http:// endpoints when you don't care about TLS.
  var sock = newSocket(buffered = false)
  sock.connect(host, port, timeout = timeoutMs)
  newStreamConn(sock)

proc sendRequest*(c: StreamConn;
                  httpMethod: string;
                  path: string;
                  host: string;
                  headers: openArray[(string, string)] = [];
                  body: string = "") =
  ## Send an HTTP/1.1 request. `Host` and (when `body.len > 0`)
  ## `Content-Length` are added automatically; `Connection: keep-alive`
  ## is set so the connection stays open across requests if you want to
  ## reuse it. Caller adds Authorization, Accept, Content-Type, etc.
  ## via `headers`.
  var req = httpMethod.toUpperAscii & " " & path & " HTTP/1.1\r\n"
  req.add "Host: " & host & "\r\n"
  if body.len > 0:
    req.add "Content-Length: " & $body.len & "\r\n"
  for (k, v) in headers:
    req.add k & ": " & v & "\r\n"
  req.add "Connection: keep-alive\r\n"
  req.add "\r\n"
  if body.len > 0:
    req.add body
  c.sock.send(req)

proc readResponseHead*(c: StreamConn): StreamResponse =
  ## Read status line + headers. Configures the body decoder based on
  ## `Transfer-Encoding` / `Content-Length`. Subsequent `readLine` calls
  ## yield body lines.
  let statusLine = c.readHeadLine()
  let parts = statusLine.split(' ', 2)
  if parts.len < 2:
    raise newException(IOError, "bad status line: " & statusLine)
  result.status = try: parseInt(parts[1]) except CatchableError:
    raise newException(IOError, "bad status code: " & parts[1])
  if parts.len >= 3: result.statusText = parts[2]
  while true:
    let line = c.readHeadLine()
    if line.len == 0: break
    let i = line.find(':')
    if i > 0:
      let k = line[0 ..< i].strip.toLowerAscii
      let v = line[i + 1 .. ^1].strip
      result.headers[k] = v
  let te = result.headers.getOrDefault("transfer-encoding").toLowerAscii
  if "chunked" in te:
    c.decoder = initBodyDecoder(beChunked)
  else:
    let cl = result.headers.getOrDefault("content-length")
    if cl.len > 0:
      let n = try: parseInt(cl) except CatchableError: -1
      c.decoder = initBodyDecoder(beIdentity, n)
    else:
      c.decoder = initBodyDecoder(beIdentity)
  # any leftover bytes from the head read are body bytes
  if c.headBuf.len > 0:
    c.decoder.feed(c.headBuf)
    c.headBuf.setLen 0

proc readLine*(c: StreamConn; line: var string): bool =
  ## Read one body line (terminated by `\n`, trailing `\r` stripped).
  ## Returns true with the line contents in `line`, or false on
  ## end-of-body. Blocks on `recv` between chunks. Lines longer than
  ## `RecvSize` are accumulated across multiple recvs, no length cap.
  while true:
    let nl = c.lineBuf.find('\n')
    if nl >= 0:
      var s = c.lineBuf[0 ..< nl]
      if s.len > 0 and s[^1] == '\r': s.setLen(s.len - 1)
      line = s
      c.lineBuf.delete(0 .. nl)
      return true
    # No newline in lineBuf. If body's done, the remainder is the last
    # (un-newline-terminated) line; flush it then signal EOF.
    if c.bodyDone:
      if c.lineBuf.len > 0:
        line = c.lineBuf
        c.lineBuf.setLen 0
        return true
      return false
    var bodyChunk = ""
    case c.decoder.decode(bodyChunk)
    of drBytes:
      c.lineBuf.add bodyChunk
    of drDone:
      c.lineBuf.add bodyChunk
      c.bodyDone = true
    of drNeedMore:
      let raw = try: c.sock.recv(RecvSize) except CatchableError: ""
      if raw.len == 0:
        c.decoder.markEof()
        var tail = ""
        discard c.decoder.decode(tail)
        c.lineBuf.add tail
        c.bodyDone = true
      else:
        c.decoder.feed(raw)
    of drError:
      raise newException(IOError, "malformed chunked transfer encoding")

iterator lines*(c: StreamConn): string =
  ## Yields each body line in turn, stopping at end-of-body. Trailing
  ## `\r` stripped. Convenience over manual `readLine`.
  var line = ""
  while c.readLine(line):
    yield line

proc close*(c: StreamConn) =
  ## Close the underlying socket. Idempotent.
  if not c.closed:
    c.closed = true
    try: c.sock.close() except CatchableError: discard
