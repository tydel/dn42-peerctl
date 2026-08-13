#!/usr/bin/env python3
"""
peerctl.py - manage dn42 WireGuard + BIRD2 peer configs from one YAML file.

Source of truth:  /etc/dn42/peers.yaml
Generates:
  - /etc/dn42/dn42-loopback.sh             (creates the dn42 dummy interface + addresses)
  - /etc/systemd/system/dn42-loopback.service  (runs the above at boot, before bird/wg)
  - /etc/sysctl.d/95-dn42.conf             (ip forwarding + loose rp_filter)
  - /etc/modules-load.d/wireguard.conf     (load the wireguard kernel module at boot)
  - /etc/systemd/system/dn42-roa.{service,timer}  (keeps ROA tables fresh, see
    https://dn42.eu/howto/BGP-communities and community_filters.conf, which
    reject anything that fails ROA validation)
  - /etc/wireguard/wg-<peername>.conf      (one interface per peer)
  - /etc/bird/peers/<peername>.conf        (BIRD2 protocol block, with
    per-peer BGP communities for latency/bandwidth/crypto/topology/
    packetloss - see peers.yaml.example and community_filters.conf)
Reloads/enables:
  - dn42-loopback.service                 (systemd, persists across reboot)
  - dn42-roa.timer                        (systemd, persists across reboot)
  - wg-quick@wg-<peername>.service        (systemd, persists across reboot)
  - bird via `birdc configure`            (live reload, no session drop)

Usage:
  peerctl.py bootstrap             # one-time: system interfaces, forwarding, sysctls
  peerctl.py list
  peerctl.py add <name>            # interactive prompts, appends to peers.yaml
  peerctl.py remove <name>         # removes from peers.yaml, tears down configs
  peerctl.py apply                 # bootstrap + regenerate all configs + reload (idempotent)
  peerctl.py apply --peer <name>   # regenerate/reload just one peer (skips bootstrap)
  peerctl.py status                # show wg + bird session status for all peers

Run `apply` any time you hand-edit peers.yaml. This script never guesses -
it only ever produces output derived directly from peers.yaml, so peers.yaml
stays the single point of truth and is what you back up / put in git.
"""
import argparse
import os
import subprocess
import sys
import yaml

CONFIG_DIR = "/etc/dn42"
PEERS_FILE = os.path.join(CONFIG_DIR, "peers.yaml")
WG_DIR = "/etc/wireguard"
BIRD_PEERS_DIR = "/etc/bird/peers"
LOOPBACK_SCRIPT = os.path.join(CONFIG_DIR, "dn42-loopback.sh")
LOOPBACK_UNIT = "/etc/systemd/system/dn42-loopback.service"
SYSCTL_FILE = "/etc/sysctl.d/95-dn42.conf"
MODULES_FILE = "/etc/modules-load.d/wireguard.conf"
ROA_V4_FILE = "/etc/bird/roa_dn42.conf"
ROA_V6_FILE = "/etc/bird/roa_dn42_v6.conf"
ROA_SERVICE = "/etc/systemd/system/dn42-roa.service"
ROA_TIMER = "/etc/systemd/system/dn42-roa.timer"
ROA_V4_URL = "https://dn42.burble.com/roa/dn42_roa_bird2_4.conf"
ROA_V6_URL = "https://dn42.burble.com/roa/dn42_roa_bird2_6.conf"


def load_peers():
    if not os.path.exists(PEERS_FILE):
        sys.exit(f"error: {PEERS_FILE} not found. Copy peers.yaml.example there first.")
    with open(PEERS_FILE) as f:
        return yaml.safe_load(f) or {}


def save_peers(data):
    with open(PEERS_FILE, "w") as f:
        yaml.dump(data, f, sort_keys=False, default_flow_style=False)


def wg_privkey():
    keyfile = os.path.join(WG_DIR, "privkey")
    if not os.path.exists(keyfile):
        sys.exit(f"error: {keyfile} missing. Generate with:\n  wg genkey | tee {keyfile} | wg pubkey")
    with open(keyfile) as f:
        return f.read().strip()


def render_wg_conf(peer, my_privkey):
    wg = peer["wg"]
    address = wg["address"]
    if wg.get("link_local"):
        # explicit link-local instead of relying on the kernel's
        # auto-assigned EUI-64 address - needed if you want a stable,
        # predictable %iface neighbor address in bird.
        address = f"{address}, {wg['link_local']}"

    lines = [
        "# Managed by peerctl.py - do not edit by hand, edit /etc/dn42/peers.yaml",
        "[Interface]",
        f"PrivateKey = {my_privkey}",
        f"ListenPort = {wg['listen_port']}",
        f"Address = {address}",
        "",
        "[Peer]",
        f"PublicKey = {wg['pubkey']}",
        f"AllowedIPs = {wg['peer_address']}, fe80::/64",
    ]
    if wg.get("endpoint"):
        lines.append(f"Endpoint = {wg['endpoint']}")
    lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"


DEFAULT_COMMUNITY = {
    # conservative fallback if a peer has no `community:` block: worst-of
    # values so it never gets preferred over a peer with real measurements.
    "latency": 9,
    "bandwidth": 21,
    "crypto": 31,
    "topology": 89,
    "packetloss": 91,
}


def render_bird_conf(peer):
    bgp = peer["bgp"]
    comm = {**DEFAULT_COMMUNITY, **peer.get("community", {})}
    community_args = ", ".join(
        str(comm[k]) for k in ("latency", "bandwidth", "crypto", "topology", "packetloss")
    )

    extra = ""
    if bgp.get("multihop"):
        extra += "    multihop 64;\n"
    if bgp.get("bfd"):
        extra += "    bfd graceful;\n    bfd { interval 10s; };\n"
    if bgp.get("extended_messages"):
        extra += "    enable extended messages on;\n"

    header = f"""# Managed by peerctl.py - do not edit by hand, edit /etc/dn42/peers.yaml
# BGP communities per https://dn42.eu/howto/BGP-communities:
#   latency={comm['latency']} bandwidth={comm['bandwidth']} crypto={comm['crypto']}
#   topology={comm['topology']} packetloss={comm['packetloss']}
"""
    import_export = f"""            import where dn42_import_filter({community_args});
            export where dn42_export_filter({community_args});"""

    mode = bgp.get("mode", "enh")  # "enh" (default) or "dual"

    if mode == "enh":
        # Single MP-BGP session over the IPv6 (usually link-local) neighbor,
        # carrying IPv4 routes too via RFC 8950 extended next hop - no
        # separate IPv4 session or IPv4 tunnel address needed.
        return header + f"""protocol bgp {peer['name']} from dnpeers {{
    description "{peer.get('description', peer['name'])}";
    neighbor {bgp['neighbor']} as {peer['asn']};
{extra}    ipv4 {{
        extended next hop on;
{import_export}
    }};
    ipv6 {{
{import_export}
    }};
}}
"""

    # mode == "dual": two independent sessions, one per address family.
    # Requires both bgp.neighbor (IPv4) and bgp.neighbor_v6 (IPv6, usually
    # link-local with %iface) to be set in peers.yaml.
    neighbor_v6 = bgp.get("neighbor_v6")
    if not neighbor_v6:
        sys.exit(f"error: peer {peer['name']} has bgp.mode: dual but no bgp.neighbor_v6 set")

    return header + f"""protocol bgp {peer['name']} from dnpeers {{
    description "{peer.get('description', peer['name'])}";
    neighbor {bgp['neighbor']} as {peer['asn']};
{extra}    ipv4 {{
{import_export}
    }};
}}

protocol bgp {peer['name']}_v6 from dnpeers {{
    description "{peer.get('description', peer['name'])} (v6)";
    neighbor {neighbor_v6} as {peer['asn']};
{extra}    ipv6 {{
{import_export}
    }};
}}
"""


def render_loopback_script(config):
    lb = config.get("loopback", {})
    ipv4 = lb.get("ipv4")
    ipv6 = lb.get("ipv6")
    if not ipv4 and not ipv6:
        sys.exit("error: peers.yaml needs a top-level 'loopback: {ipv4: ..., ipv6: ...}' block")

    lines = [
        "#!/bin/sh",
        "# Managed by peerctl.py - do not edit by hand, edit /etc/dn42/peers.yaml",
        "# Idempotent: safe to run on every boot / every `peerctl.py apply`.",
        "set -e",
        "ip link show dn42 >/dev/null 2>&1 || ip link add dn42 type dummy",
    ]
    if ipv4:
        lines.append(f"ip addr replace {ipv4} dev dn42")
    if ipv6:
        lines.append(f"ip -6 addr replace {ipv6} dev dn42")
    lines.append("ip link set dn42 up")
    return "\n".join(lines) + "\n"


def render_loopback_unit():
    return f"""# Managed by peerctl.py - do not edit by hand, edit /etc/dn42/peers.yaml
[Unit]
Description=dn42 loopback (dummy) interface
Before=network-online.target bird.service
DefaultDependencies=no
After=sysinit.target
Wants=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={LOOPBACK_SCRIPT}

[Install]
WantedBy=multi-user.target
"""


def render_sysctl_conf():
    return """# Managed by peerctl.py - do not edit by hand, edit /etc/dn42/peers.yaml
# Required for dn42: this box routes transit traffic between peers, and
# dn42 traffic is frequently asymmetric (packet arrives on one tunnel,
# reply goes out another) so strict reverse-path filtering drops it.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
"""


def render_modules_load():
    return "# Managed by peerctl.py\nwireguard\n"


def render_roa_service():
    return f"""# Managed by peerctl.py
[Unit]
Description=Update DN42 ROA tables

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -sfSLR -o {ROA_V4_FILE} -z {ROA_V4_FILE} {ROA_V4_URL}
ExecStart=/usr/bin/curl -sfSLR -o {ROA_V6_FILE} -z {ROA_V6_FILE} {ROA_V6_URL}
ExecStart=/usr/sbin/birdc configure
"""


def render_roa_timer():
    return """# Managed by peerctl.py
[Unit]
Description=Update DN42 ROA tables periodically

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
AccuracySec=1m

[Install]
WantedBy=timers.target
"""


def bootstrap(config):
    """Set up everything below the per-peer level: loopback iface, forwarding,
    rp_filter, wireguard kernel module, ROA table auto-refresh. Idempotent -
    safe to rerun (e.g. every `peerctl.py apply`)."""
    write_file(LOOPBACK_SCRIPT, render_loopback_script(config))
    os.chmod(LOOPBACK_SCRIPT, 0o755)
    write_file(LOOPBACK_UNIT, render_loopback_unit())
    write_file(SYSCTL_FILE, render_sysctl_conf())
    write_file(MODULES_FILE, render_modules_load())
    write_file(ROA_SERVICE, render_roa_service())
    write_file(ROA_TIMER, render_roa_timer())

    # dn42_import_filter() in community_filters.conf rejects everything
    # until these exist at least once - seed them if missing so the very
    # first `apply` doesn't leave bird with empty ROA tables.
    for path in (ROA_V4_FILE, ROA_V6_FILE):
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "a").close()

    sh(["modprobe", "wireguard"], check=False)
    sh(["sysctl", "--system"], check=False)
    sh(["systemctl", "daemon-reload"], check=False)
    sh(["systemctl", "enable", "--now", "dn42-loopback.service"], check=False)
    sh(["systemctl", "enable", "--now", "dn42-roa.timer"], check=False)
    sh(["systemctl", "start", "dn42-roa.service"], check=False)


def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    print(f"wrote {path}")


def sh(cmd, check=True):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check)


def apply_peer(peer, my_privkey, config):
    name = peer["name"]
    ifname = f"wg-{name}"

    write_file(os.path.join(WG_DIR, f"{ifname}.conf"), render_wg_conf(peer, my_privkey))
    write_file(os.path.join(BIRD_PEERS_DIR, f"{name}.conf"), render_bird_conf(peer))

    os.chmod(os.path.join(WG_DIR, f"{ifname}.conf"), 0o600)

    # enable so it survives reboot, then (re)start to apply now
    sh(["systemctl", "enable", f"wg-quick@{ifname}"], check=False)
    sh(["systemctl", "restart", f"wg-quick@{ifname}"], check=False)


def reload_bird():
    print("reloading bird...")
    sh(["birdc", "configure"], check=False)


def cmd_bootstrap(args, config):
    bootstrap(config)
    print("bootstrap done: dn42-loopback.service + dn42-roa.timer enabled, "
          "forwarding + rp_filter set, wireguard module loaded.")


def cmd_apply(args, config):
    peers = config.get("peers", [])
    if args.peer:
        peers = [p for p in peers if p["name"] == args.peer]
        if not peers:
            sys.exit(f"no such peer: {args.peer}")
    else:
        # full apply also (re)confirms the base system setup is in place
        bootstrap(config)
    my_privkey = wg_privkey()
    for peer in peers:
        apply_peer(peer, my_privkey, config)
    reload_bird()
    print("done.")


def cmd_list(args, config):
    for peer in config.get("peers", []):
        comm = {**DEFAULT_COMMUNITY, **peer.get("community", {})}
        comm_str = f"lat={comm['latency']} bw={comm['bandwidth']} crypto={comm['crypto']}"
        print(f"{peer['name']:20} AS{peer['asn']:<12} wg-{peer['name']:<20} :{peer['wg']['listen_port']:<7} {comm_str}")


def cmd_add(args, config):
    name = args.name
    if any(p["name"] == name for p in config.get("peers", [])):
        sys.exit(f"peer {name} already exists")
    print(f"Adding peer '{name}' - answer prompts (edit peers.yaml directly for bulk changes):")
    asn = input("Their ASN (e.g. 4242421234): ").strip()
    endpoint = input("Their WG endpoint host:port (blank if they dial you): ").strip()
    pubkey = input("Their WG public key: ").strip()
    listen_port = input("Local WG listen port for this peer: ").strip()
    peer_address = input("Point-to-point address for their side (e.g. 172.22.1.X/32): ").strip()
    my_address = input("Point-to-point address for your side (e.g. 172.22.1.1/32): ").strip()
    link_local = input("Explicit link-local for this tunnel (blank = kernel auto EUI-64, e.g. fe80::1/64): ").strip()
    neighbor = input("BGP neighbor address (e.g. fe80::1%wg-" + name + "): ").strip()
    ext_msgs = (input("Enable extended messages? [Y/n]: ").strip().lower() or "y") == "y"

    print("\nLink-characteristic BGP communities - see")
    print("https://dn42.eu/howto/BGP-communities#peering-link-characteristics")
    print("(blank = worst-case default, safe to leave and tune later)")
    latency = input("  latency bracket (1-9, e.g. 3 = 7.3-20ms) [9]: ").strip() or "9"
    bandwidth = input("  bandwidth bracket (21-29, e.g. 24 = >=100mbit) [21]: ").strip() or "21"
    crypto = input("  crypto bracket (31-36, e.g. 35 = WG+PSK) [31]: ").strip() or "31"
    topology = input("  topology bracket (81-89, e.g. 83 = tunnel) [83]: ").strip() or "83"
    packetloss = input("  packet loss bracket (91-94, e.g. 91 = ~0%) [91]: ").strip() or "91"

    peer = {
        "name": name,
        "description": f"AS{asn} - {name}",
        "asn": int(asn),
        "wg": {
            "listen_port": int(listen_port),
            "endpoint": endpoint,
            "pubkey": pubkey,
            "address": my_address,
            "peer_address": peer_address,
            "link_local": link_local,
        },
        "bgp": {
            "mode": "enh",  # MP-BGP over IPv6 + extended next hop, single session
            "neighbor": neighbor,
            "multihop": False,
            "bfd": False,
            "extended_messages": ext_msgs,
        },
        "community": {
            "latency": int(latency),
            "bandwidth": int(bandwidth),
            "crypto": int(crypto),
            "topology": int(topology),
            "packetloss": int(packetloss),
        },
    }
    config.setdefault("peers", []).append(peer)
    save_peers(config)
    print(f"added {name} to {PEERS_FILE}. Run `peerctl.py apply --peer {name}` to bring it up.")


def cmd_remove(args, config):
    name = args.name
    peers = config.get("peers", [])
    remaining = [p for p in peers if p["name"] != name]
    if len(remaining) == len(peers):
        sys.exit(f"no such peer: {name}")
    config["peers"] = remaining
    save_peers(config)

    ifname = f"wg-{name}"
    sh(["systemctl", "disable", "--now", f"wg-quick@{ifname}"], check=False)
    for path in [os.path.join(WG_DIR, f"{ifname}.conf"), os.path.join(BIRD_PEERS_DIR, f"{name}.conf")]:
        if os.path.exists(path):
            os.remove(path)
            print(f"removed {path}")
    reload_bird()
    print(f"removed peer {name}.")


def cmd_status(args, config):
    for peer in config.get("peers", []):
        ifname = f"wg-{peer['name']}"
        print(f"\n=== {peer['name']} (AS{peer['asn']}) ===")
        sh(["wg", "show", ifname], check=False)
    print("\n=== BIRD BGP sessions ===")
    sh(["birdc", "show", "protocols"], check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("bootstrap")
    sub.add_parser("list")

    p_add = sub.add_parser("add")
    p_add.add_argument("name")

    p_rm = sub.add_parser("remove")
    p_rm.add_argument("name")

    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--peer", help="only apply this one peer")

    sub.add_parser("status")

    args = parser.parse_args()
    config = load_peers()

    {
        "bootstrap": cmd_bootstrap,
        "list": cmd_list,
        "add": cmd_add,
        "remove": cmd_remove,
        "apply": cmd_apply,
        "status": cmd_status,
    }[args.cmd](args, config)


if __name__ == "__main__":
    main()
