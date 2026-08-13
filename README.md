# dn42-peerctl

Manage WireGuard tunnels + BIRD2 BGP sessions to dn42 peers from one YAML
file, with reboot-persistent systemd services.

## How it works

```
/etc/dn42/peers.yaml        <- single source of truth, put this in git
        |
        v  peerctl.py apply
        |
        +--> dn42-loopback.service           (dummy "dn42" iface + your registered IPs)
        +--> /etc/sysctl.d/95-dn42.conf       (ip forwarding, loose rp_filter)
        +--> /etc/modules-load.d/wireguard.conf
        +--> dn42-roa.timer                   (keeps ROA tables fresh, every 15 min)
        |
        +--> /etc/wireguard/wg-<peer>.conf   (one WG interface per peer)
        |        enabled via: systemctl enable wg-quick@wg-<peer>
        |
        +--> /etc/bird/peers/<peer>.conf     (BIRD2 protocol block, tagged
                 with per-peer latency/bandwidth/crypto/topology/packetloss
                 BGP communities, calling dn42_import_filter()/
                 dn42_export_filter() from community_filters.conf)
                 pulled in by: include "peers/*.conf"; in bird.conf
```

Everything under `/etc/wireguard/wg-*.conf`, `/etc/bird/peers/*.conf`,
`/etc/dn42/dn42-loopback.sh`, and the sysctl/modules-load/ROA-timer files
above is generated — never hand-edit those, edit `peers.yaml` and re-run
`apply`. `bird.conf` and `community_filters.conf` stay hand-maintained; see
`bird-main-example.conf` and `community_filters.conf` for what to install.

`peerctl.py apply` (no `--peer` flag) always re-confirms the base system
setup first — the dn42 loopback interface, IP forwarding, and reverse-path
filtering — before touching any peer. That base setup is what was missing
before: WireGuard tunnels and BGP sessions can't come up without it:

- **`dn42` dummy interface** — carries your registered dn42 loopback
  address(es), independent of any single tunnel. BIRD's `router id` and your
  advertised routes depend on this existing.
- **IP forwarding** (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`) —
  without it the kernel won't route packets between peer tunnels at all.
- **Loose reverse-path filtering** (`rp_filter = 2`) — dn42 traffic is
  routinely asymmetric (arrives via one peer's tunnel, replies go out
  another's); the kernel's default strict `rp_filter` silently drops that.
- **`wireguard` kernel module load** — harmless no-op on kernels where it's
  built in, required on older/minimal ones.
- **ROA tables** (`dn42_roa`/`dn42_roa_v6`, refreshed by `dn42-roa.timer`) —
  `community_filters.conf`'s `dn42_import_filter()` rejects any route that
  doesn't ROA-validate, so without a populated table every peer's import
  would be empty.

## BGP communities

Per-peer link-characteristic communities from
[dn42.eu/howto/BGP-communities](https://dn42.eu/howto/BGP-communities) are
set in each peer's `community:` block in `peers.yaml`:

```yaml
community:
  latency: 3        # (64511,1-9)   round-trip latency bracket
  bandwidth: 24      # (64511,21-29) min(up,down) bandwidth bracket
  crypto: 35         # (64511,31-36) encryption strength
  topology: 83       # (64511,81-89) physical / IXP / tunnel / vIX
  packetloss: 91     # (64511,91-94) packet loss bracket
```

`peerctl.py add` prompts for these (with worst-case defaults if you skip
them); `apply` writes them into the peer's `import where`/`export where`
clauses, which call `dn42_import_filter()`/`dn42_export_filter()` from
`community_filters.conf`. Those functions do three things: ROA-validate the
route, tag it with the community values, and (on export) set `bgp_med` so
downstream routers prefer your lower-latency/higher-bandwidth/stronger-
crypto paths.

Two values are set once, globally, in `peers.yaml` (not per peer) and only
tag routes you originate, never transited ones:

```yaml
region: 41      # (64511,41-57)     e.g. 41 = Europe
country: 1276   # (64511,1000-1999) ISO-3166-1 numeric + 1000, e.g. 1276 = Germany
```

Full bracket tables (latency ranges, bandwidth thresholds, region/country
codes) are on the wiki page linked above — don't guess link
latency/bandwidth by hand for long: the wiki links two small tools
(`bgp-community.rb`, `dn42-comgen.c`) that measure a link and print the
right `dn42_import_filter(...)` call for you.

**Don't skip the ROA tables.** `dn42_import_filter()` calls `roa_check()`
against `dn42_roa`/`dn42_roa_v6` — those are populated by `dn42-roa.timer`
(enabled by `bootstrap`), which pulls from `dn42.burble.com`'s public ROA
feed every 15 minutes. If that timer isn't running, every peer's import
filter rejects everything.

## WireGuard link-local addresses & BGP session modes

Each peer's `wg.link_local` (optional) pins an explicit IPv6 link-local
address on that peer's WireGuard interface, instead of relying on the
kernel's auto-assigned EUI-64 address:

```yaml
wg:
  address: 172.22.1.1/32
  link_local: fe80::1/64
```

This matters because `bgp.neighbor` typically references that same address
with a `%wg-<peer>` suffix (e.g. `fe80::1%wg-examplepeer1`) — pinning it
means the neighbor address in `peers.yaml` stays correct even if the kernel
would otherwise pick a different EUI-64 address after an interface rebuild.
Leave it blank to just use the kernel default.

Each peer's `bgp.mode` picks the BGP session layout, matching the two
approaches on [dn42.eu/howto/Bird2](https://dn42.eu/howto/Bird2#setting-up-peers):

- **`enh`** (default) — a single MP-BGP session over the peer's IPv6
  (usually link-local) address, carrying both IPv4 and IPv6 routes via
  RFC 8950 extended next hop (`extended next hop on;` in the `ipv4 {}`
  channel). One session, one neighbor address (`bgp.neighbor`), no IPv4
  tunnel address strictly required. This is what `peerctl.py add` sets up.
- **`dual`** — two independent BGP sessions, one per address family:
  `bgp.neighbor` (their IPv4 tunnel address) for the IPv4 session, and
  `bgp.neighbor_v6` for the IPv6 session. Use this for peers that don't
  support/want extended next hop.

`bgp.extended_messages: true` adds `enable extended messages on;` to either
mode, letting BIRD send larger BGP UPDATE messages (fewer messages for
peers carrying a lot of prefixes/communities) — safe to enable as long as
your peer's BGP daemon also supports it (most modern ones do).

## One-time setup

```bash
sudo mkdir -p /etc/dn42 /etc/bird/peers
sudo cp peers.yaml.example /etc/dn42/peers.yaml
sudo cp peerctl.py /usr/local/bin/peerctl.py
sudo chmod +x /usr/local/bin/peerctl.py
pip3 install pyyaml --break-system-packages   # or apt install python3-yaml

# Your server's own WireGuard identity (shared across all peer interfaces)
wg genkey | sudo tee /etc/wireguard/privkey | wg pubkey | sudo tee /etc/wireguard/pubkey
sudo chmod 600 /etc/wireguard/privkey

# Merge bird-main-example.conf's structure into your real /etc/bird.conf,
# filling in OWNAS/OWNIP/OWNNET/DN_REGION_* from your registry objects,
# and install community_filters.conf as /etc/bird/community_filters.conf.
sudo cp community_filters.conf /etc/bird/community_filters.conf

sudo peerctl.py bootstrap   # dn42 loopback iface, forwarding, rp_filter, wg module, ROA timer
sudo systemctl enable --now bird
```

Edit `/etc/dn42/peers.yaml`: set `loopback.ipv4`/`loopback.ipv6` and
`own_networks` to your registered dn42 addresses, set `region`/`country`,
then replace the two example peers with real ones (pubkeys, endpoints,
ASNs, addresses, and link-characteristic `community:` values from the dn42
registry / your peering agreement).

## Day-to-day use

```bash
peerctl.py add examplepeer3      # interactive prompt, appends to peers.yaml
peerctl.py apply                 # regenerate + reload everything
peerctl.py apply --peer examplepeer3   # just one peer, faster
peerctl.py remove examplepeer3   # tears down WG iface, removes bird block
peerctl.py list                  # summary of configured peers
peerctl.py status                # live wg + bird session state
```

Or skip the interactive prompt and bulk-edit `peers.yaml` directly (better
for adding several peers at once, or if you want the file to be a clean git
diff) — then just run `peerctl.py apply`.

## Persistence across reboot/restart

- `dn42-loopback.service` is a systemd oneshot unit (`enable`d, ordered
  `Before=bird.service`) that recreates the `dn42` dummy interface and its
  addresses on every boot — this is what was missing before: without it
  there's no stable interface for BIRD's router id or your advertised
  routes to hang off of after a reboot.
- Forwarding and `rp_filter` are set via `/etc/sysctl.d/95-dn42.conf`, which
  systemd applies automatically on every boot (`sysctl --system`).
- Each peer's WireGuard interface is a normal `wg-quick@wg-<peer>` systemd
  unit, enabled on `apply` — comes up automatically on boot, same as any
  other systemd service, no cron or custom init scripts needed.
- `bird` itself should be `systemctl enable --now bird` once; it reads
  `peers/*.conf` on every start/reload, so it always reflects the current
  `peers.yaml` state without any extra persistence work.
- Put `/etc/dn42/peers.yaml` (and `bird.conf`) in a private git repo. That's
  your actual backup/rollback mechanism — the generated files in
  `/etc/wireguard` and `/etc/bird/peers` are disposable and get regenerated
  by `apply` on a fresh box.

## Adding a peer, end to end

1. Get their ASN, WG pubkey, endpoint (if any), and agreed link-local/point-
   to-point addresses from the dn42 registry entry or your peering chat.
2. `peerctl.py add <name>` (or add a block to peers.yaml by hand).
3. `peerctl.py apply --peer <name>`.
4. `peerctl.py status` — confirm `wg show` sees a recent handshake and
   `birdc show protocols` shows the session as `Established`.
5. Commit `peers.yaml` to git.

## Notes / things to adjust for your setup

- `bird-main-example.conf`'s `dnpeers` template filters are a fallback for
  peers that skip the `community:` block; real per-peer filtering goes
  through `dn42_import_filter()`/`dn42_export_filter()` in
  `community_filters.conf` (ROA + communities + MED), driven by
  `peers.yaml`.
- `AllowedIPs` in the generated WG config only covers the point-to-point
  /32 and `fe80::/64` for link-local BGP — that's deliberate, dn42 routing
  is handled by BGP/BIRD, not by widening AllowedIPs.
- If you'd rather not run one WireGuard interface per peer, the script's
  render functions are the only two places (`render_wg_conf`,
  `render_bird_conf`) that would need to change to move to a single
  multi-peer `wg0` with `AllowedIPs`-based routing instead — happy to adapt
  it if you want that model.


## Disclaimer

- This script/system was coded using Claude.  Use at your own risk, don't 
  assume some(one|thing) else tested it extensively.
