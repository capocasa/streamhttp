## Comprehensive SSE-correctness driver over real TLS.
##
## Drives streamhttp's real recv loop against the live z.ai glm-4.7-flash
## streaming endpoint in two modes and asserts *perfect* SSE reception:
## zero read errors, every genuine 200 reaching completion (`data: [DONE]`
## or a non-empty `finish_reason`), and content/tool data intact.
##
## The source of truth for "correct transmission" is a complete SSE response.
## A truncation (the bug this exists to catch) is a 200 whose body ends before
## completion — the TLS read race documented in the streamhttp module comment.
##
## Two comparison techniques, both using a SHARED SSE parser so the comparison
## is apples-to-apples:
##
## 1. Completion asymmetry (the bug discriminator).
##    For each mode we run the SAME request through streamhttp AND through curl
##    (ground-truth HTTP client). curl assembles the stream reliably; if
##    streamhttp truncates where curl completes, that is exactly the
##    TLS-internal-buffer bug. We assert streamhttp completes whenever curl
##    does, for every genuine 200.
##
## 2. Byte-exact replay oracle.
##    We capture ONE real curl response per mode to a file (the true wire
##    bytes), parse it with the shared parser (expected), AND replay those
##    exact bytes through a local chunked server into streamhttp's recv loop
##    (actual), then assert actual == expected. This proves streamhttp's
##    line/chunk reconstruction is bit-faithful to the real HTTP response,
##    independent of model non-determinism.
##
## z.ai's free tier rate-limits aggressively (HTTP 429, code 1305/1302). A
## rate-limit is a legitimate short response, NOT a streamhttp bug. This
## driver retries rate-limits with backoff and only counts genuine HTTP 200
## streaming responses as testable trials.
##
## Run:
##   GLM_API_KEY=<key> nim c -d:ssl -d:release --path:src -r \
##       tests/test_sse_correctness.nim

import std/[algorithm, json, monotimes, net, os, osproc, parseutils, random,
            sequtils, strformat, strutils, tables, threadpool, times]
import streamhttp

const
  KeyEnv = "GLM_API_KEY"
  Host = "api.z.ai"
  Path = "/api/paas/v4/chat/completions"
  Model = "glm-4.7-flash"
  OutMarker = "CORRECTNESS_SENTINEL"
  OutCount = 8             # ask for N lines → forces multiple recv batches
  ToolCmd = "echo CORRECTNESS_TOOL_OK"
  ToolName = "bash"

# ---------------------------------------------------------------------------
# Shared SSE reconstruction — the single source of truth for "what the stream
# said". Used by the streamhttp path, the curl path, and the replay oracle so
# every comparison is byte-faithful. Mirrors the accumulation logic in 3code's
# `streamHttp` consumer (api.nim): tool-call arguments are concatenated across
# per-token deltas, content/reasoning concatenated, completion signals tracked.
# ---------------------------------------------------------------------------

type
  Recon = object
    content: string
    reasoning: string
    tools: OrderedTable[int, tuple[name, args: string]]
    sawDone: bool
    sawFinish: bool
    dataLines: int          # count of `data: {json}` lines decoded
    reachedTerminal: bool   # [DONE] seen OR connection closed: safe to stop

proc reconInit(): Recon =
  result.tools = initOrderedTable[int, (string, string)]()

proc feedLine(r: var Recon; line: string) =
  ## Feed one decoded SSE body line (no trailing \r\n) into the reconstruction.
  if not line.startsWith("data: "): return
  inc r.dataLines
  let payload = line["data: ".len .. ^1]
  if payload.strip == "[DONE]":
    r.sawDone = true
    r.reachedTerminal = true
    return
  let j = try: parseJson(payload) except CatchableError: return
  let choices = j{"choices"}
  if choices == nil or choices.kind != JArray or choices.len == 0: return
  let choice = choices[0]
  let fr = choice{"finish_reason"}
  if fr != nil and fr.kind == JString and fr.getStr.len > 0:
    r.sawFinish = true
    # NOTE: finish_reason marks the response complete but does NOT stop the
    # read loop — the server still sends `data: [DONE]` after it, and we must
    # keep reading to observe it. Only [DONE] or connection-close is terminal.
  let delta = choice{"delta"}
  if delta == nil or delta.kind != JObject: return
  var rs = delta{"reasoning_content"}.getStr("")
  if rs.len == 0: rs = delta{"reasoning"}.getStr("")
  if rs.len > 0: r.reasoning &= rs
  let c = delta{"content"}.getStr("")
  if c.len > 0: r.content &= c
  let tc = delta{"tool_calls"}
  if tc != nil and tc.kind == JArray:
    for call in tc:
      let idx = call{"index"}.getInt(0)
      if idx notin r.tools: r.tools[idx] = ("", "")
      var slot = r.tools[idx]
      let fn = call{"function"}
      if fn != nil and fn.kind == JObject:
        if fn{"name"}.getStr("").len > 0: slot.name = slot.name & fn{"name"}.getStr
        if "arguments" in fn:
          slot.args = slot.args & fn{"arguments"}.getStr("")
      r.tools[idx] = slot

proc feedText(r: var Recon; text: string) =
  ## Feed a raw SSE byte blob (as captured from curl) — split on lines.
  for line in text.split('\n'):
    var s = line
    if s.len > 0 and s[^1] == '\r': s.setLen(s.len - 1)
    r.feedLine(s)

proc totalToolArgs(r: Recon): string =
  for k in toSeq(r.tools.keys).sorted:
    result &= r.tools[k].args

proc toolArgsValid(r: Recon): bool =
  ## Every accumulated tool-call argument must be complete, parseable JSON.
  if r.tools.len == 0: return false
  for k in r.tools.keys:
    let a = r.tools[k].args
    if a.len == 0: return false
    try: discard parseJson(a)
    except CatchableError: return false
  result = true

# ---------------------------------------------------------------------------
# Request bodies per mode.
# ---------------------------------------------------------------------------

proc bodyOut(): string =
  ## Plain-text response, long enough to span several recv batches. The marker
  ## proves the tail of the stream arrived — a truncation loses the end.
  let prompt = "Count from 1 to " & $OutCount & ", each number on its own " &
    "line. End the very last line with the word " & OutMarker & ". " &
    "Reply with only the numbers and the marker."
  $(%*{
    "model": Model,
    "stream": true,
    "messages": [{"role": "user", "content": prompt}]
  })

proc bodyTool(): string =
  ## tool_stream:true — the truncation trigger. GLM streams tool-call args as
  ## many tiny per-token deltas; the TLS read race drops them mid-stream.
  $(%*{
    "model": Model,
    "stream": true,
    "tool_stream": true,
    "messages": [{"role": "user",
      "content": "Run the bash command: " & ToolCmd}],
    "tools": [{"type": "function", "function": {
      "name": ToolName,
      "description": "Run a bash command",
      "parameters": {"type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"]}}}],
    "tool_choice": "auto"
  })

# ---------------------------------------------------------------------------
# Path A: streamhttp real-TLS recv loop.
# ---------------------------------------------------------------------------

type
  TrialResult = object
    mode: string
    ok: bool                 # got a genuine, parseable completion
    status: int
    sawDone: bool
    sawFinish: bool
    truncated: bool          # 200 with data but no completion signal
    empty200: bool           # 200 with zero data lines (the "empty reply")
    rateLimited: bool
    readError: string        # non-empty on a recv/transport error
    dataLines: int
    content: string
    reasoning: string
    toolArgs: string
    toolArgsOk: bool
    secs: float

proc runStreamhttp(mode: string; bodyStr: string): TrialResult =
  result.mode = mode
  var conn = connectTls(Host, caFile = "")
  conn.readTimeoutMs = 5000
  defer: conn.close()
  let t0 = getMonoTime()
  try:
    conn.sendRequest("POST", Path, Host, {
      "Authorization": "Bearer " & getEnv(KeyEnv),
      "Content-Type": "application/json",
      "Accept": "text/event-stream"
    }, bodyStr)
  except CatchableError as e:
    result.readError = "sendRequest: " & e.msg
    return
  let resp =
    try: conn.readResponseHead()
    except CatchableError as e:
      result.readError = "readResponseHead: " & e.msg
      return
  result.status = resp.status
  if resp.status == 429:
    var line = ""
    while conn.readLine(line): discard
    result.rateLimited = true
    return
  if resp.status != 200:
    var line = ""; var b: seq[string]
    while conn.readLine(line): b.add line
    result.readError = "HTTP " & $resp.status & ": " & b.join(" ")
    return
  var rec = reconInit()
  var timedOut = false
  while not timedOut:
    var line = ""
    let got =
      try: conn.readLine(line)
      except StreamTimeoutError:
        if (getMonoTime() - t0).inSeconds > 90: timedOut = true
        true
      except CatchableError as e:
        result.readError = "readLine: " & e.msg
        false
    if not got:
      if not timedOut: break
      continue
    if line.len > 0: rec.feedLine(line)
    if rec.reachedTerminal: break   # [DONE] seen — stop; (finish_reason alone is NOT terminal)
  result.secs = (getMonoTime() - t0).inMilliseconds.float / 1000.0
  result.sawDone = rec.sawDone
  result.sawFinish = rec.sawFinish
  result.dataLines = rec.dataLines
  result.content = rec.content
  result.reasoning = rec.reasoning
  result.toolArgs = rec.totalToolArgs()
  result.toolArgsOk = rec.toolArgsValid()
  result.empty200 = rec.dataLines == 0
  result.truncated = not rec.sawDone and not rec.sawFinish and rec.dataLines > 0
  result.ok = (rec.sawDone or rec.sawFinish) and rec.dataLines > 0

# ---------------------------------------------------------------------------
# Path B: curl ground-truth HTTP response, parsed with the SAME reconstructor.
# ---------------------------------------------------------------------------

proc runCurl(mode, bodyStr: string; capturePath = ""): TrialResult =
  ## POST the same body via curl (the reference HTTP client) and reconstruct
  ## from the raw bytes it sees. `capturePath` non-empty also writes the raw
  ## SSE to that file for the byte-exact replay oracle.
  result.mode = mode
  let t0 = getMonoTime()
  # Shell-join args into a single command string for execCmdEx (it does not
  # take an args array). poStdErrToStdOut keeps curl's progress/errors in the
  # captured buffer so a transport failure surfaces as non-200 text.
  let cmd = "curl -sS -N --max-time 90 https://" & Host & Path &
            " -H " & ("Authorization: Bearer " & getEnv(KeyEnv)).quoteShell &
            " -H 'Content-Type: application/json' -H 'Accept: text/event-stream'" &
            " -d " & bodyStr.quoteShell
  let (raw, code) = execCmdEx(cmd, options = {poUsePath, poStdErrToStdOut})
  discard code
  result.secs = (getMonoTime() - t0).inMilliseconds.float / 1000.0
  if raw.contains("\"code\":\"1305\"") or raw.contains("\"code\":\"1302\"") or
     raw.contains("overloaded") or raw.contains("Rate limit"):
    result.rateLimited = true
    return
  if capturePath.len > 0: writeFile(capturePath, raw)
  # Detect HTTP status line if curl printed one (it normally won't with -s).
  result.status = 200
  var rec = reconInit()
  rec.feedText(raw)
  result.sawDone = rec.sawDone
  result.sawFinish = rec.sawFinish
  result.dataLines = rec.dataLines
  result.content = rec.content
  result.toolArgs = rec.totalToolArgs()
  result.toolArgsOk = rec.toolArgsValid()
  result.empty200 = rec.dataLines == 0
  result.truncated = not rec.sawDone and not rec.sawFinish and rec.dataLines > 0
  result.ok = (rec.sawDone or rec.sawFinish) and rec.dataLines > 0

# ---------------------------------------------------------------------------
# Byte-exact replay oracle: serve a captured SSE blob through a local chunked
# server into streamhttp's recv loop and assert identical reconstruction.
# Proves streamhttp's line/chunk decoder is bit-faithful to the real response,
# with no model non-determinism in the way.
# ---------------------------------------------------------------------------

type ReplayServer = ref object
  sock: Socket
  port: Port
  blob: string

proc newReplayServer(blob: string): ReplayServer =
  let s = newSocket()
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(Port(0))
  s.listen()
  let (_, p) = s.getLocalAddr()
  ReplayServer(sock: s, port: p, blob: blob)

proc replayServe(server: ReplayServer) {.thread.} =
  var client: Socket
  server.sock.accept(client)
  # Drain request up to blank line.
  var req = ""
  while true:
    let line = client.recvLine(timeout = 3000)
    if line.len == 0: break
    req &= line & "\n"
    if line.strip == "": break
  let body = server.blob
  # Wrap the raw SSE (which is already the decoded body) as one chunk, so the
  # chunked decoder in streamhttp reassembles exactly these bytes.
  let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" &
             "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
  client.send(resp)
  client.send(toHex(body.len).toLowerAscii() & "\r\n" & body & "\r\n")
  client.send("0\r\n\r\n")
  client.close()

proc replayThroughStreamhttp(blob: string): Recon =
  ## Feed `blob` (real captured SSE) into streamhttp's recv loop via a local
  ## server and reconstruct. Returns the reconstruction.
  let server = newReplayServer(blob)
  spawn replayServe(server)
  let conn = connectPlain("127.0.0.1", server.port)
  conn.readTimeoutMs = 3000
  defer: conn.close()
  conn.sendRequest("POST", "/", "127.0.0.1", body = "{}")
  discard conn.readResponseHead()
  result = reconInit()
  var line = ""
  while conn.readLine(line):
    if line.len > 0: result.feedLine(line)
  server.sock.close()

# ---------------------------------------------------------------------------
# Reporting helpers.
# ---------------------------------------------------------------------------

proc summary(r: TrialResult): string =
  if r.rateLimited: return "rate-limited"
  if r.readError.len > 0: return "ERR: " & r.readError
  let tag =
    if r.truncated: "TRUNC"
    elif r.empty200: "EMPTY200"
    elif r.ok: "OK"
    else: "INCOMPLETE"
  &"{r.mode}:{tag} status={r.status} done={r.sawDone} finish={r.sawFinish} " &
   &"dataLines={r.dataLines} secs={r.secs.formatFloat(ffDecimal, 2)}"

proc contentSample(r: TrialResult): string =
  let src = if r.mode == "tool": r.toolArgs else: r.content
  let s = src.replace("\n", "\\n")
  if s.len > 100: s[0 ..< 100] & "…" else: s

# ---------------------------------------------------------------------------
# Capture helper: get one clean genuine-200 SSE blob for the replay oracle.
# Best-effort against rate limits; returns "" if the endpoint won't cooperate.
# ---------------------------------------------------------------------------

proc captureClean(mode, bodyStr, capPath: string): bool =
  for i in 1..40:
    let cu = runCurl(mode, bodyStr, capturePath = capPath)
    if cu.rateLimited:
      sleep(rand(800 .. 2200)); continue
    if cu.ok and cu.dataLines > 0:
      return true
    if cu.readError.len > 0:
      sleep(rand(400 .. 1200))
  false

# ---------------------------------------------------------------------------
# Byte-exact replay oracle — the deterministic, network-independent proof of
# perfect SSE reception. Mandatory: runs whenever a capture exists.
# ---------------------------------------------------------------------------

proc runReplayOracle(mode, capPath: string): bool =
  ## Returns true if the oracle ran and passed, false if skipped (no capture).
  ## FATAL (quit 1) on a real mismatch — that is a streamhttp bug.
  let label = &"[{mode}/replay]"
  if not fileExists(capPath):
    echo "SKIP " & label & " no capture (endpoint saturated — environmental)"
    return false
  let raw = readFile(capPath)
  if raw.len == 0:
    echo "SKIP " & label & " empty capture"; return false
  var expected = reconInit()
  expected.feedText(raw)
  if expected.dataLines == 0:
    echo "SKIP " & label & " capture had no data lines"; return false
  let actual = replayThroughStreamhttp(raw)
  template fail(msg: string) =
    echo "FAIL " & label & " " & msg
    echo "  expected done=" & $expected.sawDone & " finish=" & $expected.sawFinish &
         " dataLines=" & $expected.dataLines & " content=" &
         expected.content.replace("\n","\\n").substr(0,80)
    echo "  actual   done=" & $actual.sawDone & " finish=" & $actual.sawFinish &
         " dataLines=" & $actual.dataLines & " content=" &
         actual.content.replace("\n","\\n").substr(0,80)
    quit(1)
  if actual.content != expected.content:
    fail "content mismatch (streamhttp lost/altered bytes)"
  if actual.totalToolArgs() != expected.totalToolArgs():
    fail "tool-call arguments mismatch (streamhttp lost deltas)"
  if actual.reasoning != expected.reasoning:
    fail "reasoning mismatch"
  if actual.sawDone != expected.sawDone or actual.sawFinish != expected.sawFinish:
    fail "completion-signal mismatch"
  if actual.dataLines != expected.dataLines:
    fail "data-line count mismatch (" & $actual.dataLines & " vs " & $expected.dataLines & ")"
  echo "PASS " & label & " byte-exact vs captured HTTP response " &
       "(content=" & $expected.content.len & "B toolArgs=" & $expected.totalToolArgs().len &
       "B reasoning=" & $expected.reasoning.len & "B)"
  true

# ---------------------------------------------------------------------------
# Live trials — best-effort against rate limits. Never a false FAIL on account
# of the free tier being saturated; a hard FAIL only on genuine transport bugs.
# ---------------------------------------------------------------------------

const GenuineTarget = 5   # genuine 200 trials we want per mode

proc gatherMode(mode, bodyStr: string):
    tuple[sh: seq[TrialResult], cu: seq[TrialResult]] =
  result.sh = @[]
  result.cu = @[]
  var attempts = 0
  var consecutiveRateLimit = 0
  while result.sh.len < GenuineTarget and attempts < 80:
    inc attempts
    let sh = runStreamhttp(mode, bodyStr)
    if sh.rateLimited:
      inc consecutiveRateLimit
      echo &"  [{mode}/streamhttp] attempt {attempts}: rate-limited — backoff"
      # If the endpoint is saturated, stop burning time. The replay oracle
      # (run separately) is the deterministic proof; live trials are bonus.
      if consecutiveRateLimit >= 12:
        echo &"  [{mode}] endpoint saturated after {attempts} attempts — " &
             "live trials skipped (environmental), replay oracle is authoritative"
        return
      sleep(rand(800 .. 2500)); continue
    consecutiveRateLimit = 0
    if sh.status != 200:
      echo &"  [{mode}/streamhttp] attempt {attempts}: " & summary(sh)
      sleep(rand(400 .. 1200)); continue
    result.sh.add sh
    echo &"  [{mode}/streamhttp] attempt {attempts}: " & summary(sh)
    echo &"     content: {contentSample(sh)}"
    let cu = runCurl(mode, bodyStr)
    if not cu.rateLimited:
      result.cu.add cu
      echo &"  [{mode}/curl]        attempt {attempts}: " & summary(cu)
    else:
      echo &"  [{mode}/curl]        attempt {attempts}: rate-limited (paired)"
    sleep(rand(200 .. 700))

proc assertModeCorrectness(mode: string;
                           sh, cu: openArray[TrialResult]): bool =
  ## Core correctness gate. For every genuine 200 via streamhttp: zero read
  ## errors, completion (DONE/finish), no empty-200, no truncation, data
  ## integrity (sentinel present / tool args valid JSON). Returns false (SKIP)
  ## when no trials could be collected due to saturation.
  let label = &"[{mode}]"
  template fail(msg: string) =
    echo "FAIL " & label & " " & msg; quit(1)
  if sh.len == 0:
    echo "SKIP " & label & " no genuine 200 trials (endpoint saturated) — " &
         "replay oracle is the authoritative check"
    return false
  var bad = 0
  for t in sh:
    if t.readError.len > 0:
      echo "FAIL " & label & " read error in a 200 trial: " & t.readError
      inc bad
    if t.empty200:
      echo "FAIL " & label & " empty 200 (zero data lines)"; inc bad
    if t.truncated:
      echo "FAIL " & label & " truncated 200 (no DONE/finish): " & contentSample(t)
      inc bad
    if not (t.sawDone or t.sawFinish):
      echo "FAIL " & label & " incomplete (no completion signal)"; inc bad
  if bad > 0:
    fail $bad & " trial(s) failed perfect-reception checks"
  for t in sh:
    if mode == "out":
      if OutMarker notin t.content:
        echo "FAIL " & label & " marker missing from content: " & contentSample(t)
        quit(1)
    else:
      if not t.toolArgsOk:
        echo "FAIL " & label & " tool args not valid JSON: " & contentSample(t)
        quit(1)
      if ToolCmd notin t.toolArgs:
        echo "FAIL " & label & " expected command missing from tool args"; quit(1)
  if cu.len > 0:
    let cuComplete = cu.filterIt(it.ok).len
    if cuComplete > 0 and sh.filterIt(it.ok).len == 0:
      fail "curl completed but streamhttp never did — transport bug"
  echo "PASS " & label & " " & $sh.len & " genuine 200(s) received perfectly"
  true

proc runMode(mode, bodyStr: string) =
  echo ""
  echo "===================================================================="
  echo "MODE: " & mode & "  (model=" & Model & ")"
  echo "===================================================================="
  let capPath = getTempDir() / "sse_correctness_" & mode & ".sse"
  # 1) Capture one clean response for the replay oracle (best-effort).
  if not fileExists(capPath) or readFile(capPath).len == 0:
    echo "  capturing ground-truth response for replay oracle…"
    if not captureClean(mode, bodyStr, capPath):
      echo "  capture: endpoint saturated — oracle will SKIP (environmental)"
  # 2) Replay oracle — mandatory whenever a capture exists.
  discard runReplayOracle(mode, capPath)
  # 3) Live trials — best-effort, SKIP cleanly on saturation.
  let (sh, cu) = gatherMode(mode, bodyStr)
  discard assertModeCorrectness(mode, sh, cu)

proc main() =
  if getEnv(KeyEnv).len == 0:
    echo "FATAL: set " & KeyEnv; quit(1)
  randomize()
  echo "streamhttp SSE correctness driver: " & Model & " @ " & Host
  echo "target: " & $GenuineTarget & " genuine 200(s) per mode, perfect reception"
  echo "oracle: byte-exact replay of a captured HTTP response (deterministic)"
  runMode("out", bodyOut())
  runMode("tool", bodyTool())
  echo ""
  echo "===================================================================="
  echo "Reception checks complete. (PASS lines = perfect; SKIP = environmental"
  echo "rate-limiting; any FAIL = a genuine streamhttp bug.)"
  echo "===================================================================="

main()
