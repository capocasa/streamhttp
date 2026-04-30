# streamhttp

Tiny synchronous streaming HTTP/1.1 client for Nim. Reads response
bodies as they arrive — chunked transfer encoding, content-length,
connection-close — without an async runtime, without a subprocess,
without buffering the body up front.

For when you wanted to consume Server-Sent Events from a sync call site
and Nim's `std/httpclient` was busy slurping the whole body before
giving you anything.

## Why?

Nim's stdlib `HttpClient` calls `parseBody` synchronously inside
`request`, which means the whole body is read before the call returns.
Fine for one-shots, useless for SSE. The async client streams via
`FutureStream` but drags `std/asyncdispatch` into your code. Subprocess
`curl` works but forks a process per request and you parse stdout
markers.

This module reads bytes off a `net.Socket` (TLS or plain), runs them
through a tiny chunked-encoding state machine, and yields one body line
at a time as data trickles in. Block on `recv` like any sync client.

## Usage

```nim
import streamhttp

let c = connectTls("api.openai.com")
defer: c.close()
c.sendRequest("POST", "/v1/chat/completions", "api.openai.com",
              headers = {"Authorization": "Bearer " & key,
                         "Content-Type": "application/json",
                         "Accept": "text/event-stream"},
              body = jsonBody)
let resp = c.readResponseHead()
echo "status: ", resp.status
for line in c.lines:
  if line.startsWith("data: "):
    let payload = line["data: ".len .. ^1]
    if payload == "[DONE]": break
    process(payload)  # parse SSE event as it arrives
```

Plain HTTP for testing or http:// endpoints:

```nim
let c = connectPlain("127.0.0.1", Port(8080))
```

Already-connected socket (BYO TLS):

```nim
let c = newStreamConn(mySocket, mySslCtx)
```

## Decoder API

The chunked-encoding decoder is exposed separately for testing or for
consumers that drive their own I/O:

```nim
var d = initBodyDecoder(beChunked)
d.feed(rawBytes)
var buf = ""
case d.decode(buf)
of drBytes:    # buf has body bytes, may have more
of drNeedMore: # feed more rawBytes
of drDone:     # body fully consumed (any final bytes in buf)
of drError:    # malformed input
```

Three encodings supported:

- `beIdentity` with `contentLength >= 0` — sized body
- `beIdentity` with `contentLength < 0` — read until socket close (HTTP/1.0 style); call `markEof` when the socket closes
- `beChunked` — `Transfer-Encoding: chunked` per RFC 7230, ignoring chunk extensions and discarding trailer headers

## Scope

What's in: HTTP/1.1, TLS via `std/net`, sized + chunked + until-close
bodies, line-buffered API on top, connection keep-alive (no special
handling — just don't `close` between requests on the same `StreamConn`).

What's not: HTTP/2, redirects, automatic decompression, request
streaming, cookies, proxy support. If you want any of those, reach for
[chronos](https://github.com/status-im/nim-chronos) or roll your own on
top of this.

## Install

```
nimble install streamhttp
```

Requires `-d:ssl` for TLS support (Nim convention).

## License

MIT.
