version       = "0.4.1"
author        = "capocasa"
description   = "Tiny synchronous streaming HTTP/1.1 client. Reads chunked bodies as they arrive."
license       = "MIT"
srcDir        = "src"

requires "nim >= 2.0.0"

task test, "Run the deterministic local test suite (excludes live-API drivers)":
  # The two live-API drivers in this dir (test_glm_flash, test_sse_correctness)
  # hit api.z.ai and `quit(1)` if GLM_API_KEY is unset. They are not part of
  # `nimble test` and the dev runs them by hand:
  #   GLM_API_KEY=... nim c -r tests/test_glm_flash.nim
  #   GLM_API_KEY=... nim c -r tests/test_sse_correctness.nim
  # Keep the list explicit (no `tests/*.nim` glob) so adding a new live-API
  # test by mistake can't quietly break CI.
  exec "sh -c 'set -e; for t in tests/test_streamhttp.nim tests/test_handshake_timeout.nim tests/test_send_dead_tls.nim tests/test_connect_interrupt.nim; do nim c -r \"$t\"; done'"
