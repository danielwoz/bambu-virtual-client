# Manual end-to-end "wire smoke"

`wire_smoke.py` is a stdlib-only Python 3 script that exercises the
full discovery → MQTT-connect path of the virtual-client against a
real `bambu_bridge` process. It is intentionally **NOT** registered
with ctest — run it by hand when you want to know that the wire path
still talks.

## What it does

1. SIGTERMs any leftover `bambu_bridge` so we own the listening
   sockets.
2. Spawns `bambu_bridge --bridge-only [--config-dir <path>]` in the
   background, logging stdout+stderr to `/tmp/bvc_wire_smoke_bridge.log`.
3. Waits for the bridge to be ready by **TCP-probing** the
   per-device MQTT/FTPS/VTun ports (the same readiness pattern used by
   `BambuStudio-bridge/tests/e2e/bridge_integration.py` — no log
   grepping).
4. Sends a fake SSDP `NOTIFY ssdp:alive` packet to the bridge's
   `SsdpListener` on UDP/2021 (broadcast + unicast + best-effort
   multicast). The byte format matches
   `BambuStudio-bridge/src/bambu_bridge/server/SsdpResponder.cpp::
   build_notify_headers` so the listener's `NT`-contains-"bambulab-com"
   filter accepts it.
5. Invokes `bambu_virtual_cli connect <bind-ip> <virtual-sn> <access>`
   with a short `--idle-seconds` and asserts the process exits
   cleanly — which only happens when `VirtualMqttClient::connect_printer`
   returned 0 **and** the on-local-connect callback fired with
   `state == 0` (MQTT CONNACK accepted). See `VirtualMqttCli.cpp`
   around line 210.
6. Sends SIGINT to the bridge and waits up to 10 s for a clean exit.

## Exit codes

| rc  | meaning                                                                |
| --- | ---------------------------------------------------------------------- |
| 0   | full path worked — CLI got a CONNACK against the bridge's MQTT broker. |
| 1   | a measurable step failed (port didn't come up, CLI returned non-zero, etc.). |
| 77  | environment can't run this smoke (broadcast/multicast blocked, binary missing) — treat as skip. |

## Prereqs

* a built `bambu_bridge` binary (`BambuStudio --bridge-only` will also
  work — same entry point).
* a built `bambu_virtual_cli` binary from this repo
  (`build/bambu_virtual_cli` after a default cmake build).
* a printer entry the bridge can route to. The cleanest way is to
  point `--printer-config` at a config dir that the bridge picks up
  via `--config-dir`, with at least one Bambu printer registered
  whose real serial matches `--real-sn` and whose access code
  matches `--access-code`. Without this, the bridge's
  `SsdpListener` will hear the NOTIFY but log "printer we don't
  track yet" and drop it, and the CLI's MQTT CONNECT will fail
  authentication.
* loopback broadcast on UDP/2021 must be allowed by the kernel/sandbox.

## Usage

```bash
# Quick smoke from the repo root:
python3 tests/e2e/wire_smoke.py \
    --bridge-binary /path/to/BambuStudio-bridge/build/src/bambu-studio \
    --virtual-cli-binary ./build/bambu_virtual_cli \
    --printer-config ~/.config/BambuStudio \
    --real-sn   0300A2B0123456 \
    --virtual-sn FFFF0A2B0123456 \
    --access-code 18b1a572
```

If you're running the bridge on a non-default MQTT port (i.e. you
passed `--mqtt-port-base N` to the bridge), forward the same value:

```bash
... --mqtt-port 8884 --ftps-port 39991 --vtun-port 39999 ...
```

Use `--help` for the full flag list.

## Files touched at runtime

* `/tmp/bvc_wire_smoke_bridge.log` — the bridge's stdout+stderr for
  the run. Inspect after a FAIL.

## Why this isn't in ctest

* it spawns a long-lived networking daemon;
* it depends on broadcast UDP working on the host's interfaces;
* it needs binary paths the build doesn't predict.

The hermetic unit tests in `tests/CMakeLists.txt` cover the
in-process invariants (framing, JSON contract, store persistence,
FTPS loopback). This file lives one tier above those — it's a
"does the bridge actually talk to my CLI on this host today?" check
the operator runs once per network/config change.
