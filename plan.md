# streamhttp SSE truncation investigation

## The bug

3code, a coding agent built on top of streamhttp, drops tool-call arguments
when talking to GLM-5.2 over HTTPS. The symptom: bash commands arrive at the
tool with empty/truncated arguments, so nothing runs and the model is blind.

This is NOT a model bug. curl with the identical request and HTTP/1.1 gets the
full streamed response every time. 3code/streamhttp gets EOF after the first
recv batch.

## Root cause (narrowed, not fully confirmed)

streamhttp's `readLine` treats a zero-length `recv` as clean EOF:

```nim
# streamhttp.nim, in readLine:
let raw = try: c.sock.recv(RecvSize, c.readTimeoutMs)
          except CatchableError as e: ""
if raw.len == 0:
  c.decoder.markEof()
  c.bodyDone = true
```

The problem: on TLS sockets, `recv(size, timeout)` returning `""` does NOT
always mean the server closed the connection. It can also mean:

1. **SSL_pending data after select reports the fd readable due to a TCP FIN.**
   Nim's `net.waitFor` (net.nim:1442) checks `SSL_pending()` first. If that is
   0, it does `select()` on the raw fd. If the TCP layer sent a FIN (which
   happens during a TLS connection close handshake), `select` reports the fd
   ready. `waitFor` returns, `SSL_read` is called, returns 0, `recv` returns 0.
   But there may still be un-decrypted data buffered inside OpenSSL from a
   prior `SSL_read` that fetched multiple TLS records at once. The correct
   pattern is to call `SSL_read` until it returns `SSL_ERROR_WANT_READ`, not
   to rely on `select`/`poll` to gate reads on an SSL socket.

2. **`except CatchableError as e: ""` swallows real errors as EOF.** Any
   non-timeout exception (SslError, OSError, reset) becomes a silent EOF.

## How it was reproduced and measured

### Setup

- Profile: `zai.glm-5.2`, reasoning `max`, `thinking:{type:enabled,effort:max}`
- Prompt: "Run the bash command: echo SOMETHING"
- GLM sends `tool_stream:true` (3code sets it via `applyStreamingOptions`)

### What the server actually sends (captured via curl, raw SSE)

With `tool_stream:true`, GLM streams tool-call arguments as ~13 tiny
per-token deltas:

```
delta 1: {"tool_calls":[{...,"function":{"name":"bash","arguments":"{"}}]}
delta 2: {"tool_calls":[{...,"function":{"arguments":"command"}}]}
delta 3: {"tool_calls":[{...,"function":{"arguments":"\":\""}}]}
...
delta N: {"tool_calls":[{...,"function":{"arguments":"}"}}]}
data: [DONE]
```

curl assembles these into `{"command":"echo SOMETHING"}` every time,
reliably.

### What 3code/streamhttp sees (debug instrumentation)

Added `-d:streamDebug` dumps to streamhttp's `readLine` and
`readResponseHead`. Ran the real 3code binary pointed at the local source
(`--path:~/p/streamhttp/src`) so the instrumentation compiled in.

Typical output for a single turn:

```
[sdbg] head-left body=3619: [chunked]  (headers + first body batch)
[sdbg] recv EOF lineBuf.len=94         (next recv returned 0 bytes)
```

The first `recv` returns ~3.6KB (headers + reasoning content chunks). The
NEXT `recv` returns 0 bytes (EOF). No exception is raised, so path (2) above
is not the trigger here; it is path (1) or a genuine-but-premature close.

The `lineBuf` has leftover decoded bytes (94-212), which `readLine` drains
before returning false. So a few SSE lines survive, then the stream ends.

### The asymmetry

| client        | result                                   |
|---------------|------------------------------------------|
| curl (HTTP/2) | all ~13 tool deltas + [DONE]             |
| curl --http1.1| all deltas + [DONE] (tested, works)      |
| 3code/streamhttp | EOF after first recv batch            |

HTTP version is NOT the cause. TLS read buffering is the prime suspect.

## Current workaround (in 3code, not streamhttp)

3code's `applyStreamingOptions` previously set `tool_stream:true` for Z.ai/GLM.
Disabled. Without `tool_stream`, GLM sends tool-call arguments in a SINGLE
delta (verified via curl), which sidesteps the per-token streaming path that
triggers the truncation. Reasoning still streams live (that is gated by
`stream:true` + `thinking:enabled`, NOT by `tool_stream`). Tradeoff: tool-call
arguments are no longer streamed token-by-token (they arrive whole), but they
arrive reliably. Reasoning/thinking streaming is unaffected.

This is a workaround, not a fix. The underlying streamhttp bug will bite any
streamed response where the server sends data in a pattern that exposes the
SSL read race.

## Detailed instructions to continue debugging

All paths assume the 3code checkout is at `~/p/3code/fixblanks` and
streamhttp source is at `~/p/streamhttp`.

### 1. Reproduce deterministically

```bash
cd ~/p/3code/fixblanks
nim c -d:ssl -d:streamDebug \
  --path:src --path:../ttty/src --path:../../3/unicodedb/src \
  --path:../tinotify/src --path:~/p/streamhttp/src \
  -o:3code src/threecode.nim

cd /tmp && rm -rf repro && mkdir repro && cd repro
~/p/3code/fixblanks/3code -D "Run the bash command: echo DEBUG_TEST" 2>/dev/null
# debug output goes to the session log, not stderr:
f=$(ls -t ~/.local/share/3code/sessions/ | head -1)
strings ~/.local/share/3code/sessions/$f | grep '\[sdbg\]'
```

To re-enable `tool_stream` for the repro (the truncation trigger), edit
`src/threecode/api.nim` `applyStreamingOptions` and re-add:

```nim
if p.family == "glm":
  case providerOf(p)
  of "zai", "zai-coding", "zaicode":
    body["tool_stream"] = %true
  else: discard
```

The truncation is intermittent but frequent with `tool_stream` on. Run the
repro 5-10 times; you will see `recv EOF` after one batch.

### 2. Confirm the SSL_pending hypothesis

The leading theory: OpenSSL has buffered TLS records from the first read, but
`SSL_pending()` returns 0 because the data spans multiple records fetched in
one `SSL_read`. After `select()` reports the fd ready (due to TCP FIN),
`recv` returns 0 and streamhttp declares EOF, leaving the buffered records
undecoded.

To test: in streamhttp's `readLine`, when `recv` returns 0 on a TLS socket,
do NOT immediately mark EOF. Instead, retry the raw `recv` a few times with
a short timeout to drain any remaining OpenSSL-buffered data. Pseudocode:

```nim
if raw.len == 0:
  # On TLS sockets, a zero recv can mean the fd saw a FIN but OpenSSL
  # may still have decrypted records buffered. Drain before declaring EOF.
  if c.isTls:
    var drained = false
    for _ in 0 ..< 3:
      sleep(5)
      let r2 = c.sock.recv(RecvSize, 50)  # very short timeout
      if r2.len > 0:
        c.decoder.feed(r2)
        drained = true
      else: break
    if drained: continue   # re-loop, try to produce a line
  c.decoder.markEof()
  c.bodyDone = true
```

This is a hack to confirm the hypothesis, not a production fix. If the
truncation goes away with this retry loop, the hypothesis is confirmed and
the real fix is to restructure the SSL read loop to use `SSL_read` until it
returns `SSL_ERROR_WANT_READ` instead of relying on `select`.

### 3. The correct long-term fix

The proper pattern for reading an SSL/TLS socket is:

1. Call `SSL_read`. If it returns data, process it, then loop.
2. If `SSL_read` returns `SSL_ERROR_WANT_READ`, THEN call `select()`/`poll()`.
3. After `select` returns ready, go back to step 1.

Nim's `net.recv(size, timeout)` does roughly the inverse: it calls
`select()` first (via `waitFor`), then `SSL_read`. This works for plain
sockets but is racy for SSL because `select` on the raw fd does not know
about OpenSSL's internal buffer, and a TCP FIN makes `select` report the fd
readable even when OpenSSL has pending plaintext.

Streamhttp may need its own SSL read loop rather than delegating to
`net.recv(size, timeout)`. The `SSL_pending` check in `waitFor` only catches
data left over from the immediately-preceding `SSL_read`, not data that
arrived in the same TCP segment but a different TLS record.

### 4. Minimal repro outside 3code

Write a standalone test that:
- Opens a TLS connection to `api.z.ai:443`
- POSTs the GLM chat/completions request with `tool_stream:true`
- Uses streamhttp's `readResponseHead` + `readLine` loop
- Counts how many SSE lines are received

If the standalone test reproduces the truncation, the bug is fully isolated
to streamhttp. Compare against the same request read via raw `SSL_read` in a
loop to confirm the record-buffer theory.

### 5. Tests to add once fixed

The existing streaming test harness is at
`~/p/3code/fixblanks/tests/test_streaming_sse.nim`. It drives the real
`streamHttp` recv loop via a LOCAL plain-HTTP server with canned SSE. It
cannot currently reproduce this bug because it uses plain HTTP, not TLS, so
the SSL buffering path is never exercised.

To test the fix end-to-end, add a test scenario that uses a real TLS
connection (e.g. a local TLS-terminating proxy) and serves a canned SSE
response split across multiple TLS records in one TCP segment. Assert that
all SSE lines are received.

### Key files

- streamhttp: `src/streamhttp.nim` `readLine` (~line 316), `readResponseHead`
  (~line 250), `Decoder` (~line 120)
- Nim net: `recv(socket, data, size, timeout)` (~line 1479), `waitFor`
  (~line 1442) in `lib/pure/net.nim`
- 3code consumer: `src/threecode/api.nim` `streamHttp` recv loop (~line 486)
- 3code workaround: `src/threecode/api.nim` `applyStreamingOptions` (~line 700)
- 3code tests: `tests/test_streaming_sse.nim`
