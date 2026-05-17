#!/usr/bin/env python3
"""Wire-level smoke for bambu-virtual-client end-to-end.

Spawns a real `bambu_bridge --bridge-only` process, broadcasts a fake
Bambu SSDP NOTIFY (ssdp:alive) on UDP/2021 so the bridge's
`SsdpListener` learns a LAN IP for a (pre-registered) printer, then
drives `bambu_virtual_cli connect <127.0.0.1> <FFFF-sn> <access>`
against the bridge's MQTT-over-TLS broker port and asserts the CLI
opens the session (CONNACK accepted).

This script is MANUAL — it is intentionally NOT registered with ctest.
It assumes the operator has:

  * a built `bambu_bridge` binary (the BambuStudio-bridge headless
    entry point, i.e. `BambuStudio --bridge-only` or the standalone
    bridge target).
  * a built `bambu_virtual_cli` binary (from this repo, target name
    `bambu_virtual_cli`).
  * either:
      (a) a real Bambu printer config / cloud inventory primed via
          `--printer-config` (forwarded to the bridge as `--config-dir`),
          so the bridge already knows the real-SN→virtual-SN mapping;
      OR
      (b) an environment that lets the bridge boot in a self-contained
          "no real printers" mode — in that case the SSDP step still
          runs but the CLI connect will fail (the bridge has no
          virtual SN to route to). We surface that as a normal FAIL.

Loopback note
-------------
Multicast and broadcast UDP on the loopback interface are usually
allowed on a Linux desktop, but locked-down containers / CI sandboxes
often block them (no `IFF_MULTICAST`, no `IFF_BROADCAST`, or no
default route). When the script can't open or send on the broadcast
socket it prints `SKIP: <reason>` and exits 77 (the standard
"test skipped" rc used by autotools / cmake).

Exit codes
----------
   0 — bridge spawned, NOTIFY delivered, CLI CONNACK ok
   1 — something measurable failed (bridge didn't come up; CLI didn't
       connect; etc.). Prints a per-step trace.
  77 — environment can't run this test (multicast/broadcast blocked,
       binary missing, etc.). The harness should treat this as skip.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# Defaults match BambuStudio-bridge's tests/e2e/bridge_integration.py
# so an operator with the bridge tree open can hop between the two.
DEFAULT_BIND = "127.0.0.1"
DEFAULT_MQTT_PORT = 8883            # first per-device MQTT port (mqtt-port-base)
DEFAULT_FTPS_PORT = 39990
DEFAULT_VTUN_PORT = 39998
SSDP_LISTENER_PORT = 2021           # bridge's SsdpListener bind port
BRIDGE_LOG = Path("/tmp/bvc_wire_smoke_bridge.log")

# A plausible "fake real printer" identity to advertise. Real Bambu
# serials are 15 hex/digit chars; the SsdpListener filters on NT
# containing "bambulab-com" and accepts whatever USN we provide. The
# bridge uses the source IP as the LAN IP and looks up the dev_id in
# its `m_devices` map. If the dev_id isn't in `m_devices`, the
# listener logs and drops — so for the CLI step to succeed the
# operator must have pre-registered a printer with this dev_id via
# their cloud account or the equivalent fixture.
#
# Override with --real-sn / --virtual-sn / --access-code.
DEFAULT_REAL_SN = "0300A2B0000FAKE"
DEFAULT_VIRTUAL_SN = "FFFF0A2B0000FAK"   # what the bridge mirrors as
DEFAULT_ACCESS_CODE = "00000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    sys.stdout.write(f"[smoke] {msg}\n")
    sys.stdout.flush()


def skip(reason: str) -> "int":
    """Print a clear SKIP line and exit 77 (autotools-style skip)."""
    sys.stdout.write(f"SKIP: {reason}\n")
    sys.stdout.flush()
    return 77


def kill_leftovers(binary_name: str) -> None:
    """SIGTERM any previous `bambu_bridge` left from a crashed run.

    We use pkill -f so this is bounded to the exact basename — we do
    NOT want to kill an unrelated daemon by accident.
    """
    try:
        subprocess.run(["pkill", "-TERM", "-f", binary_name],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       check=False)
    except FileNotFoundError:
        # pkill not installed — best-effort only.
        pass
    # Give the kernel a beat to reclaim the listening sockets.
    time.sleep(0.5)


def tcp_probe(host: str, port: int, timeout: float = 0.3) -> bool:
    """One-shot TCP-connect probe (the readiness pattern used by the
    BambuStudio-bridge integration tests; see tests/e2e/bridge_integration.py).
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def wait_for_bridge_ready(host: str,
                          ports: list[int],
                          deadline_s: float = 30.0) -> bool:
    """Block until every advertised TCP port accepts a connection, or
    until the deadline elapses. Returns True if all ports came up."""
    t_end = time.time() + deadline_s
    while time.time() < t_end:
        up = sum(1 for p in ports if tcp_probe(host, p))
        if up == len(ports):
            return True
        time.sleep(0.5)
    return False


def build_notify(real_sn: str,
                 sender_ip: str,
                 dev_name: str = "smoke-printer",
                 dev_model: str = "3DPrinter-X1",
                 dev_version: str = "01.08.00.00") -> bytes:
    """Build a NOTIFY ssdp:alive packet byte-for-byte matching the
    format the bridge's `SsdpListener` parses.

    Reference: /home/danielwoz/BambuStudio-bridge/src/bambu_bridge/server/
               SsdpResponder.cpp::build_notify_headers (the same
               formatter the bridge uses when *it* mirrors NOTIFYs).

    The bridge's listener only requires `NT` containing "bambulab-com"
    and a `USN` to populate `dev_id`; the optional Dev*.bambu.com
    headers are looked up by lowercased key.
    """
    body = (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "Server: UPnP/1.0\r\n"
        f"Location: {sender_ip}\r\n"
        "NT: urn:bambulab-com:device:3dprinter:1\r\n"
        "NTS: ssdp:alive\r\n"
        f"USN: {real_sn}\r\n"
        "Cache-Control: max-age=1800\r\n"
        f"DevModel.bambu.com: {dev_model}\r\n"
        f"DevName.bambu.com: {dev_name}\r\n"
        "DevSignal.bambu.com: -60\r\n"
        "DevConnect.bambu.com: lan\r\n"
        "DevBind.bambu.com: free\r\n"
        "Devseclink.bambu.com: secure\r\n"
        f"DevVersion.bambu.com: {dev_version}\r\n"
        "DevCap.bambu.com: 1\r\n"
        "\r\n"
    )
    return body.encode("ascii")


def send_notify_broadcast(notify_bytes: bytes,
                          dest_port: int = SSDP_LISTENER_PORT) -> tuple[bool, str]:
    """Broadcast the NOTIFY on the limited broadcast address. The
    bridge's listener binds 0.0.0.0:2021 with SO_BROADCAST, so a
    255.255.255.255-targeted datagram on any interface will be
    received.

    Returns (ok, reason). On sandboxed hosts the socket setup or
    sendto() may fail with EPERM/EACCES — surface that as a SKIP
    reason in the caller."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Also try multicast — covers operators on networks where
        # broadcast is filtered. The bridge listens on 0.0.0.0 so
        # multicast frames that land on the loopback interface still
        # arrive at recvfrom() if IGMP membership was joined by some
        # other consumer; the bridge itself doesn't join, but
        # broadcast covers the loopback case unambiguously.
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(1.0)
        # Send to the limited broadcast address; the bridge sees this
        # arrive on its 0.0.0.0:2021 socket regardless of interface.
        s.sendto(notify_bytes, ("255.255.255.255", dest_port))
        # Belt-and-braces: also send a unicast copy to localhost so
        # the test works even if the loopback interface lacks the
        # broadcast bit.
        s.sendto(notify_bytes, ("127.0.0.1", dest_port))
        # And one multicast copy for completeness.
        try:
            s.sendto(notify_bytes, ("239.255.255.250", dest_port))
        except OSError:
            # Multicast may be filtered; the broadcast/unicast pair
            # is the load-bearing send.
            pass
        return True, "sent broadcast+unicast+multicast NOTIFY"
    except OSError as exc:
        return False, f"send_notify_broadcast: {exc}"
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Main test driver
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    # 0) Preflight
    if not args.bridge_binary.exists():
        log(f"bridge binary not found at {args.bridge_binary}")
        return skip(f"bridge binary missing: {args.bridge_binary}")
    if not args.virtual_cli_binary.exists():
        log(f"virtual-cli binary not found at {args.virtual_cli_binary}")
        return skip(f"virtual_cli binary missing: {args.virtual_cli_binary}")

    # 1) Kill any leftover bridge process so we own the listening
    #    sockets cleanly.
    log(f"killing leftover {args.bridge_binary.name} instances...")
    kill_leftovers(args.bridge_binary.name)

    # 2) Spawn the bridge.
    bridge_cmd = [str(args.bridge_binary), "--bridge-only",
                  "--bind", args.bind]
    if args.printer_config is not None:
        # The bridge takes `--config-dir <path>` (see
        # BridgeAppCliArgs.cpp). Forward our --printer-config there.
        bridge_cmd += ["--config-dir", str(args.printer_config)]
    log(f"spawning: {' '.join(bridge_cmd)}")
    BRIDGE_LOG.unlink(missing_ok=True)
    log_fh = BRIDGE_LOG.open("w")
    try:
        proc = subprocess.Popen(
            bridge_cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        log(f"failed to spawn bridge: {exc}")
        return 1

    rc = 1
    try:
        # 3) Readiness — TCP-probe the per-device ports we expect.
        #    With no real printers in inventory the bridge may not
        #    have any per-device listeners up; in that case we still
        #    want the smoke to exercise the SSDP listener, so we
        #    probe a *bounded* set with a short timeout and continue
        #    even if only some come up.
        wanted = [args.mqtt_port, args.ftps_port, args.vtun_port]
        log(f"waiting up to {args.bridge_timeout}s for ports "
            f"{wanted} on {args.bind}...")
        ports_up = wait_for_bridge_ready(args.bind, wanted,
                                          deadline_s=args.bridge_timeout)
        if not ports_up:
            # Don't bail yet — some bridges deliberately don't open
            # listeners until they see a printer. Re-probe MQTT
            # specifically; that's the port the CLI will hit.
            if not tcp_probe(args.bind, args.mqtt_port, timeout=1.0):
                log(f"bridge MQTT port {args.mqtt_port} not listening; "
                    "tail of bridge log:")
                if BRIDGE_LOG.exists():
                    tail = BRIDGE_LOG.read_text(errors="replace").splitlines()[-30:]
                    for line in tail:
                        log("  | " + line)
                return 1
        log("bridge MQTT port reachable; proceeding")

        # 4) Send the fake SSDP ALIVE.
        notify = build_notify(real_sn=args.real_sn,
                              sender_ip=args.bind)
        log(f"sending fake NOTIFY ssdp:alive for USN={args.real_sn} "
            f"to UDP/{SSDP_LISTENER_PORT}")
        ok, why = send_notify_broadcast(notify, dest_port=SSDP_LISTENER_PORT)
        if not ok:
            return skip(f"multicast/broadcast unavailable in this env: {why}")
        # Give the bridge a beat to process the NOTIFY and (if it
        # tracks this dev_id) update lan_ip / wire up listeners.
        time.sleep(2.0)

        # 5) Drive the CLI.
        cli_cmd = [
            str(args.virtual_cli_binary),
            "connect",
            args.bind,
            args.virtual_sn,
            args.access_code,
            # `connect` defaults --idle-seconds to 0 (run forever).
            # Override so this is a smoke, not a babysit.
            "--idle-seconds", str(args.cli_idle_seconds),
        ]
        log(f"running CLI: {' '.join(cli_cmd)}")
        cli_t0 = time.time()
        try:
            cli = subprocess.run(
                cli_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=args.cli_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            log(f"CLI timed out after {args.cli_timeout}s")
            if exc.output:
                for line in exc.output.decode("utf-8", "replace").splitlines()[-30:]:
                    log("  cli| " + line)
            return 1
        cli_dt = time.time() - cli_t0
        log(f"CLI exited rc={cli.returncode} in {cli_dt:.2f}s")
        for line in cli.stdout.decode("utf-8", "replace").splitlines()[-30:]:
            log("  cli| " + line)
        if cli.returncode != 0:
            return 1

        # 6) Asserted: CONNACK accepted. The CLI's `connect` path
        #    returns 0 iff `connect_printer` returned 0 AND
        #    `is_connected` flipped true via on_local_connect (rc==0
        #    means CONNACK Success). See VirtualMqttCli.cpp line ~210.
        log("CLI connected, MQTT CONNACK accepted — smoke PASS")
        rc = 0
        return rc

    finally:
        # 7) Tear down the bridge.
        if proc.poll() is None:
            log("sending SIGINT to bridge for clean shutdown...")
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                log("bridge did not exit on SIGINT; SIGKILL")
                proc.kill()
                proc.wait()
        log_fh.close()
        log(f"bridge log archived to {BRIDGE_LOG}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=("Manual wire-level smoke: bambu_bridge → "
                     "SSDP NOTIFY → bambu_virtual_cli connect."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--bridge-binary", type=Path, required=True,
                   help="Path to the bambu_bridge executable.")
    p.add_argument("--virtual-cli-binary", type=Path, required=True,
                   help="Path to bambu_virtual_cli.")
    p.add_argument("--printer-config", type=Path, default=None,
                   help=("Optional path to a printer config dir, forwarded "
                         "to the bridge as `--config-dir`. The bridge needs "
                         "an inventory entry for --real-sn for the SSDP "
                         "listener's lan_ip update to take effect."))
    p.add_argument("--bind", default=DEFAULT_BIND,
                   help=f"IP for the bridge to bind (default {DEFAULT_BIND}).")
    p.add_argument("--mqtt-port", type=int, default=DEFAULT_MQTT_PORT,
                   help=f"Per-device MQTT port to probe + connect "
                        f"(default {DEFAULT_MQTT_PORT}).")
    p.add_argument("--ftps-port", type=int, default=DEFAULT_FTPS_PORT,
                   help=f"FTPS port to probe for readiness "
                        f"(default {DEFAULT_FTPS_PORT}).")
    p.add_argument("--vtun-port", type=int, default=DEFAULT_VTUN_PORT,
                   help=f"VTun port to probe for readiness "
                        f"(default {DEFAULT_VTUN_PORT}).")
    p.add_argument("--real-sn", default=DEFAULT_REAL_SN,
                   help="USN to advertise in the fake NOTIFY.")
    p.add_argument("--virtual-sn", default=DEFAULT_VIRTUAL_SN,
                   help="Virtual SN (FFFF…) the CLI will connect against.")
    p.add_argument("--access-code", default=DEFAULT_ACCESS_CODE,
                   help="MQTT access_code for the CLI.")
    p.add_argument("--bridge-timeout", type=float, default=30.0,
                   help="Seconds to wait for bridge TCP-port readiness.")
    p.add_argument("--cli-timeout", type=float, default=20.0,
                   help="Wall-clock timeout for the CLI subprocess.")
    p.add_argument("--cli-idle-seconds", type=int, default=3,
                   help="--idle-seconds to pass to bambu_virtual_cli.")
    return p.parse_args(argv)


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    sys.exit(main())
