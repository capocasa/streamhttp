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

import std/[nativesockets, net, parseutils, strutils, tables]
when defined(posix) and not defined(windows):
  import std/posix except SocketHandle
when defined(ssl):
  import std/openssl

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

  StreamConnObj = object
    sock: Socket
    readTimeoutMs*: int  ## >0: recv aborts after this many ms idle, raising StreamTimeoutError
    ctx: SslContext              ## kept alive for the connection's lifetime
    decoder: BodyDecoder
    headBuf: string              ## bytes pulled while reading head, may overlap into body
    lineBuf: string              ## decoded body bytes pending line split
    bodyDone: bool               ## decoder hit end-of-body
    closed: bool
  StreamConn* = ref StreamConnObj
  ## `readTimeoutMs` is exported but must be assigned via `setReadTimeoutMs`
  ## so the per-read deadline is mirrored onto the kernel socket as
  ## `SO_RCVTIMEO`. A plain field assignment would leave `SSL_read`/`recv`
  ## without a hard deadline and the timeout would only bound the `poll`
  ## step, not the blocking read that follows it.

# ---------- BodyDecoder (pure, testable) ----------

type
  StreamTimeoutError* = object of CatchableError
    ## Raised by `readLine`/`recvIntoHead` when `readTimeoutMs` elapses with no
    ## data. Distinct from EOF so callers can distinguish a transient stall
    ## from a closed connection.
    ## Distinguish from EOF: the caller may retry after checking liveness.

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

const streamDebug {.booldefine.} = false

template sdbg*(msg: string) =
  when streamDebug:
    stderr.writeLine("[sdbg] " & msg)

proc applyRecvTimeout*(sock: Socket; timeoutMs: int) =
  ## Set `SO_RCVTIMEO` on the underlying socket fd so a blocking `recv` (and,
  ## on TLS, the `SSL_read` it drives) is woken by the kernel after
  ## `timeoutMs` of inactivity. Without this, `poll()`-then-`recv` has a
  ## race window: `poll` can report the fd readable for a TLS record that
  ## OpenSSL consumes internally (a `close_notify` alert, a `NewSessionTicket`,
  ## or a renegotiation handshake) and then blocks in `SSL_read` waiting for
  ## the next application-data record. `poll` is immune to that record type,
  ## so the bounded `poll` step returns but the unbounded `SSL_read` after it
  ## stalls. `SO_RCVTIMEO` makes the kernel interrupt the stall and surface
  ## `EAGAIN`, which `net.recv` raises as `OSError`; `recvChunk` translates
  ## that to `StreamTimeoutError` so the caller's wake loop fires. A no-op
  ## (and safe) on Windows, which we don't ship TLS on.
  if timeoutMs <= 0: return
  when defined(posix) and not defined(windows):
    var tv: Timeval
    tv.tv_sec = Time(timeoutMs div 1000)
    tv.tv_usec = Suseconds((timeoutMs mod 1000) * 1000)
    discard setsockopt(sock.getFd, SOL_SOCKET, SO_RCVTIMEO,
                       addr(tv), sizeof(tv).SockLen)

proc setReadTimeoutMs*(c: StreamConn; timeoutMs: int) =
  ## Assign `readTimeoutMs` and mirror it onto the kernel socket as
  ## `SO_RCVTIMEO`. This is the only correct way to change the per-read
  ## deadline after construction.
  c.readTimeoutMs = timeoutMs
  applyRecvTimeout(c.sock, timeoutMs)

# ---------- Correct TLS read path ----------
#
# Why we don't use `net.recv(size, timeout)` for TLS sockets:
#
# Nim's `recv(socket, data, size, timeout)` loops calling `waitFor`, which
# checks `SSL_pending()` and then calls `select()`/`poll()` on the *raw* fd.
# For SSL this ordering is wrong: `select` on the raw fd does not understand
# OpenSSL's internal record buffer. A single `SSL_read` can pull several TLS
# records off one TCP segment into OpenSSL's plaintext buffer; `select` then
# reports the fd *not* readable (the bytes were already consumed from the
# kernel), so the loop's next `waitFor` either times out or, worse, sees a
# TCP FIN and declares EOF — while `SSL_pending` bytes sit undecoded. The
# result: streamed responses truncate after the first recv batch. Real-world
# symptom (z.ai GLM over TLS): the whole SSE body cut to ~500 bytes, or the
# very first head read returning 0.
#
# The correct SSL read pattern, used here, is:
#   1. If `SSL_pending() > 0`, OpenSSL has decrypted bytes buffered from a
#      previous read — call `SSL_read` directly, no `poll`. This is the case
#      that `net`'s loop mishandles.
#   2. Otherwise `poll()` the raw fd for the timeout. On timeout, raise
#      `StreamTimeoutError` so the caller can re-check its interrupt/quiet
#      flags. When `poll` reports readable, call the *blocking* low-level
#      `recv` (a single `SSL_read`) exactly once — one `SSL_read` pulls
#      exactly the records OpenSSL needs rather than re-polling mid-record.
#      NOTE: `poll` reporting readable does NOT guarantee `SSL_read` returns
#      promptly: the readable edge may be a `close_notify` alert, a
#      `NewSessionTicket`, or a renegotiation handshake that OpenSSL
#      consumes internally and then blocks waiting for the next
#      application-data record. To bound that stall, `setReadTimeoutMs`
#      sets `SO_RCVTIMEO` on the kernel socket so the blocked read is woken
#      with `EAGAIN`, which `doRecv` promotes to `StreamTimeoutError`. A
#      plain `readTimeoutMs=` field assignment does NOT set `SO_RCVTIMEO`,
#      so it leaves a path that hangs forever under a quiet-network spinner.
#
# Plain (non-TLS) sockets have no internal buffer, so `poll()` + blocking
# `recv` is also correct for them. When `readTimeoutMs <= 0` we skip `poll`
# and just block, matching the old behaviour and keeping the plain-HTTP test
# server path unchanged.

proc sslPendingBytes(c: StreamConn): int {.inline.} =
  when defined(ssl):
    if c.sock.isSsl: result = SSL_pending(c.sock.sslHandle).int
  else: result = 0

proc pollReadable(c: StreamConn): bool =
  ## Block up to `readTimeoutMs` for the socket to be readable. Returns true
  ## if data is available, false on timeout. Callers raise `StreamTimeoutError`
  ## when this returns false and a timeout is in effect.
  when defined(posix) and not defined(windows):
    var pfd: posix.TPollfd
    pfd.fd = cast[cint](c.sock.getFd)
    pfd.events = posix.POLLIN or posix.POLLPRI
    # Retry on EINTR (signal interrupted poll) so a stray signal during the
    # bounded wait doesn't masquerade as a hard timeout. A few retries is
    # enough — EINTR storms don't happen in practice.
    var n = -1
    for _ in 0 ..< 8:
      n = posix.poll(addr pfd, posix.Tnfds(1), c.readTimeoutMs.cint)
      if n >= 0: break
    # n == 0 → timed out; n > 0 → readable; n < 0 → persistent error, treat
    # as not-ready and let the caller's recv surface it (becomes empty/EOF).
    result = n > 0 and (pfd.revents and (posix.POLLIN or posix.POLLPRI)) != 0
  else:
    # Windows: `selectRead` wants `seq[SocketHandle]`, not `seq[Socket]`.
    # Plain sockets only on Windows in practice; the TLS truncation this
    # fixes is POSIX OpenSSL.
    var fds = @[c.sock.getFd]
    result = selectRead(fds, c.readTimeoutMs) == 1

proc doRecv(c: StreamConn): string =
  ## One blocking `recv`/`SSL_read` on the underlying socket. With
  ## `SO_RCVTIMEO` applied by `setReadTimeoutMs`, a stalled read is woken by
  ## the kernel and promoted to `StreamTimeoutError` so the caller's wake
  ## loop fires. Other errors propagate so the caller can distinguish them
  ## from a clean EOF.
  ##
  ## The timeout surfaces differently on plain vs TLS sockets. On a plain
  ## socket the kernel recv returns EAGAIN, which `net` raises as `OSError`.
  ## On a TLS socket OpenSSL turns the EAGAIN into `SSL_ERROR_WANT_READ` (or
  ## WANT_WRITE), which `net.socketError` raises as
  ## `SslError("Not enough data on socket.")`, not an `OSError`. Both are the
  ## same condition under our `SO_RCVTIMEO` regime and must map to the same
  ## `StreamTimeoutError` or the quiet/interrupt wake loop never fires and a
  ## slow-but-healthy provider (z.ai GLM, ~7s to first byte) is reported as
  ## `request failed: Not enough data on socket.`.
  try:
    result = c.sock.recv(RecvSize)
  except OSError as e:
    # Use the exception's stored `errorCode` (captured at raise time) rather
    # than re-reading `errno`, which another syscall may have clobbered. A
    # genuine socket error (peer reset etc.) carries a different errno and
    # re-raises here so the caller surfaces it as a hard error.
    when defined(posix) and not defined(windows):
      if e.errorCode == EAGAIN.int32 or e.errorCode == EWOULDBLOCK.int32:
        raise newException(StreamTimeoutError, "recv timed out (SO_RCVTIMEO)")
    raise e
  except CatchableError as e:
    when defined(ssl):
      # TLS counterpart of the EAGAIN branch above: `SO_RCVTIMEO` expiry
      # under SSL_read becomes SSL_ERROR_WANT_READ/WANT_WRITE, raised by
      # `net` as `SslError("Not enough data on socket.")`. Match that exact
      # message and promote it; any other `SslError` (alert, handshake
      # failure) is a real fault and re-raises.
      if e of SslError and
          "Not enough data on socket" in e.msg:
        raise newException(StreamTimeoutError, "recv timed out (SO_RCVTIMEO)")
    raise e

proc recvChunk(c: StreamConn): string =
  ## Pull one batch of body/head bytes from the socket. Empty string = clean
  ## EOF (peer closed). Raises `StreamTimeoutError` when `readTimeoutMs`
  ## elapses with no data. Correctly drains OpenSSL's internal buffer for TLS
  ## sockets — see the note above on why `net.recv(size, timeout)` is wrong.
  if c.readTimeoutMs <= 0:
    # No timeout requested: plain blocking read. Correct for both TLS and
    # plain sockets; the SSL loop bug only appears in `net`'s *timeout* path.
    result = c.sock.recv(RecvSize)
    sdbg "recvChunk(blocking) got " & $result.len & " bytes"
    return
  # Fast path: OpenSSL has decrypted bytes sitting in its internal buffer from
  # a previous SSL_read. `poll()` would NOT report the fd readable for these
  # (they're already off the kernel socket), so we must drain them directly.
  # This single branch is the difference between a complete stream and a
  # 500-byte truncation over TLS.
  if sslPendingBytes(c) > 0:
    result = c.doRecv()
    sdbg "recvChunk(sslPending) got " & $result.len & " bytes"
    return
  # Wait for the fd to be readable, bounded by the timeout.
  if not c.pollReadable():
    raise newException(StreamTimeoutError, "recv timed out")
  # poll said readable — but on TLS the readability may be a close_notify or
  # a renegotiation handshake rather than app data. A blocking recv here does
  # a single SSL_read; if it yields 0 the peer genuinely closed (after the
  # SSL_pending drain above already took everything that was buffered). The
  # `SO_RCVTIMEO` set by `setReadTimeoutMs` guarantees this read cannot
  # outlive `readTimeoutMs` even in that case: the kernel surfaces EAGAIN,
  # `doRecv` promotes it to `StreamTimeoutError`, and the caller's wake loop
  # re-checks interrupt/quiet instead of hanging forever under the hourglass.
  result = c.doRecv()
  sdbg "recvChunk(poll) got " & $result.len & " bytes"

proc recvIntoHead(c: StreamConn): bool =
  var chunk = ""
  try:
    chunk = c.recvChunk()
  except StreamTimeoutError:
    raise
  except CatchableError as e:
    # Don't swallow the error as clean EOF: a transient read failure
    # (reset, TLS alert, EINTR) would otherwise masquerade as a graceful
    # connection close, leave `headBuf` half-filled, and let
    # `readResponseHead` build a truncated/empty response. Re-raise so the
    # caller's `except CatchableError` surfaces it as a request failure.
    sdbg "recvIntoHead exception: " & e.msg
    raise e
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

proc isIpAddress(s: string): bool =
  ## Crude IPv4/IPv6 check so we skip SNI for raw-IP hosts (TLS forbids SNI
  ## for literal addresses; some servers reject the extension there).
  if s.len == 0: return false
  var dots = 0
  for ch in s:
    if ch == '.': inc dots
    elif ch == ':': return true   # looks like IPv6
    elif ch notin {'0'..'9'}: return false
  dots == 3

proc connectTls*(host: string; port: Port = Port(443);
                 timeoutMs: int = 20_000;
                 caFile: string = ""): StreamConn =
  ## Open a TLS connection. `caFile` is an optional CA bundle (skip
  ## scanning system locations when set). Returns a `StreamConn` ready
  ## for `sendRequest`.
  ##
  ## Sets SNI (Server Name Indication) from `host` when it is a hostname,
  ## not a literal IP. SNI is standard practice for TLS to a named host:
  ## most modern edges and CDNs use it to pick the certificate/vhost, and a
  ## few will reject or mis-route a ClientHello that omits it. It is set
  ## before the handshake via `SSL_set_tlsext_host_name`.
  let ctx = newContext(verifyMode = CVerifyPeer, caFile = caFile)
  var sock = newSocket(buffered = false)
  ctx.wrapSocket(sock)
  when defined(ssl):
    if not isIpAddress(host):
      # Must be called before the handshake. A no-op on OpenSSL builds
      # without TLSEXT, hence `discard`.
      discard SSL_set_tlsext_host_name(sock.sslHandle, host)
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
  ## yield body lines. Resets per-response state (`bodyDone`, `lineBuf`)
  ## so the same `StreamConn` can be reused for back-to-back requests
  ## over a keep-alive connection — without this, a second response on
  ## the same conn would short-circuit `readLine` immediately because
  ## the previous body's `bodyDone` is still set.
  c.bodyDone = false
  c.lineBuf.setLen 0
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
      var raw = ""
      try:
        raw = c.recvChunk()
      except StreamTimeoutError:
        raise
      except CatchableError as e:
        sdbg "readLine recv exception: " & e.msg
        raw = ""
      sdbg "readLine recv got " & $raw.len & " bytes, lineBuf=" & $c.lineBuf.len
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

proc getFd*(c: StreamConn): SocketHandle =
  ## Underlying socket fd. Exposed so callers can `posix.shutdown` it
  ## from a signal handler / watcher thread to interrupt a blocking
  ## `recv`. Returns `osInvalidSocket` after `close`.
  if c.closed: osInvalidSocket
  else: c.sock.getFd

proc close*(c: StreamConn) =
  ## Close the underlying socket. Idempotent.
  if not c.closed:
    c.closed = true
    try: c.sock.close() except CatchableError: discard
