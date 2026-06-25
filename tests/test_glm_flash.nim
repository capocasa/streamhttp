## Standalone end-to-end test of streamhttp against the real z.ai GLM-4.7-Flash
## streaming endpoint. Drives the actual streamhttp TLS recv loop with a real
## SSE response and measures whether 200 responses complete cleanly.
##
## IMPORTANT: z.ai's free tier rate-limits aggressively (HTTP 429, code 1305
## "service may be temporarily overloaded"). A 429 is a *legitimate* short
## response — the server sends the error body then closes. It is NOT a
## streamhttp bug. This driver retries on 429 with backoff and only counts
## genuine HTTP 200 streaming responses as testable trials.
##
## A 200 that arrives but whose body never reaches `data: [DONE]` (and never
## emits a `finish_reason`) is a genuine truncation — the real bug this test
## exists to catch.
##
## Run:
##   GLM_API_KEY=<key> nim c -d:ssl -d:release --path:src -r tests/test_glm_flash.nim

import std/[json, monotimes, os, random, strformat, strutils, times]
import streamhttp

const
  KeyEnv = "GLM_API_KEY"
  Host = "api.z.ai"
  Path = "/api/paas/v4/chat/completions"
  Model = "glm-4.7-flash"
  Marker = "SENTINEL_OK"

type RunResult = object
  status: int
  lines: int
  sawDone: bool
  sawFinish: bool
  sawMarker: bool
  truncated: bool
  rateLimited: bool
  timedOut: bool
  secs: float
  errMsg: string
  contentSample: string

proc runOne(key: string): RunResult =
  var conn = connectTls(Host, caFile = "")
  conn.readTimeoutMs = 5000
  defer: conn.close()

  let body = $(%*{
    "model": Model,
    "stream": true,
    "messages": [{
      "role": "user",
      "content": "Reply with exactly one word: " & Marker &
                  ". Do not add anything else."
    }]
  })

  try:
    conn.sendRequest("POST", Path, Host, {
      "Authorization": "Bearer " & key,
      "Content-Type": "application/json",
      "Accept": "text/event-stream"
    }, body)
  except CatchableError as e:
    result.errMsg = "sendRequest failed: " & e.msg
    return

  let resp =
    try: conn.readResponseHead()
    except CatchableError as e:
      result.errMsg = "readResponseHead failed: " & e.msg
      return
  result.status = resp.status

  if resp.status == 429:
    # Drain the body so the connection can close cleanly, then surface as a
    # rate-limit (not a failure).
    var line = ""
    while conn.readLine(line): discard
    result.rateLimited = true
    return

  if resp.status != 200:
    var line = ""
    var b: seq[string]
    while conn.readLine(line): b.add line
    result.errMsg = "HTTP " & $resp.status & ": " & b.join(" ")
    return

  # ---- Genuine 200 streaming response: this is what we're testing. ----
  let t0 = getMonoTime()
  var accContent = ""

  while not result.timedOut:
    var line = ""
    let ok =
      try: conn.readLine(line)
      except StreamTimeoutError:
        let elapsed = (getMonoTime() - t0).inSeconds
        if elapsed > 60: result.timedOut = true; false
        else: true
      except CatchableError as e:
        result.errMsg = "readLine error: " & e.msg
        false
    if not ok:
      if not result.timedOut: break
      continue
    if line.len == 0: continue
    result.lines.inc
    if line.startsWith("data: "):
      let payload = line["data: ".len .. ^1]
      if payload.strip == "[DONE]":
        result.sawDone = true
        break
      try:
        let j = parseJson(payload)
        let choices = j{"choices"}
        if choices != nil and choices.kind == JArray and choices.len > 0:
          let fr = choices[0]{"finish_reason"}
          if fr != nil and fr.kind == JString and fr.getStr.len > 0:
            result.sawFinish = true
          let delta = choices[0]{"delta"}
          if delta != nil and delta.kind == JObject:
            let c = delta{"content"}.getStr("")
            if c.len > 0: accContent &= c
      except CatchableError:
        discard

  result.secs = (getMonoTime() - t0).inMilliseconds.float / 1000.0
  result.contentSample = if accContent.len > 120:
    accContent[0 ..< 120] & "…" else: accContent
  result.sawMarker = Marker in accContent
  # The real bug: a 200 that streamed some lines but never reached completion.
  result.truncated = not result.sawDone and not result.sawFinish and
    result.lines > 0

proc main() =
  let key = getEnv(KeyEnv)
  if key.len == 0:
    echo "FATAL: set " & KeyEnv; quit(1)
  randomize()
  echo "streamhttp real-TLS driver: " & Model & " @ " & Host
  echo "============================================================"
  var ok = 0
  var trunc = 0
  var errs = 0
  var rateLimited = 0
  const Target = 10   # genuine 200 responses we want to verify
  var attempts = 0
  while ok + trunc < Target and attempts < 60:
    inc attempts
    let r = runOne(key)
    if r.rateLimited:
      inc rateLimited
      echo &"[429 ] attempt {attempts}: rate-limited (code 1305) — backoff"
      sleep(rand(800 .. 2500))
      continue
    if r.status != 200:
      inc errs
      echo &"[ERR ] attempt {attempts}: " & r.errMsg
      sleep(rand(500 .. 1500))
      continue
    let tag = if r.truncated: "FAIL"
              elif r.sawDone: "PASS"
              else: "????"
    if r.truncated: inc trunc else: inc ok
    let statusStr =
      if r.timedOut: "TIMEOUT"
      elif r.truncated: "TRUNC"
      elif r.sawDone: "OK"
      else: "NO-DONE"
    echo &"[{tag}] attempt {attempts}: 200 {statusStr} lines={r.lines} " &
         &"done={r.sawDone} finish={r.sawFinish} marker={r.sawMarker} " &
         &"secs={r.secs.formatFloat(ffDecimal, 2)}"
    if r.errMsg.len > 0: echo "       err: " & r.errMsg
    echo "       content: " & r.contentSample.replace("\n", "\\n")
  echo "============================================================"
  echo &"genuine 200s: {ok} complete, {trunc} truncated, " &
       &"{errs} other errors, {rateLimited} rate-limited (skipped)"
  if trunc > 0: quit(1)

main()
