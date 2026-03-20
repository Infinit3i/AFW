# AFW Feature Roadmap

> **When all features below are complete, destroy this directory.**

## Interactive Connection Control (Little Snitch for Linux)

### Phase 1: eBPF Connection Tracking
- [x] Add new eBPF kprobe on `tcp_v4_connect` (and `udp_sendmsg` for UDP)
- [x] Capture: PID, comm, destination IP, destination port, protocol
- [x] New `ConnectionEvent` struct in `afw-common`
- [x] New perf buffer channel for connection events (separate from exec/exit)
- [x] Daemon receives connection events alongside process events

### Phase 2: Unknown App Detection
- [ ] When a connection event arrives for an app NOT in the config, flag it as "unknown"
- [ ] Track unknown connection attempts: deduplicate by (comm, dest_port, protocol)
- [ ] Aggregate ports per unknown app over a short time window (~5 seconds)
- [ ] After the window, produce a summary: "app 'foo' tried 443/tcp, 80/tcp, 8443/tcp"
- [ ] Since default policy is drop, the connection is already blocked — no action needed to deny

### Phase 3: Desktop Notification
- [ ] Send notification via `notify-send` / D-Bus when unknown app is detected
- [ ] Notification shows: app name, binary, ports it tried to access
- [ ] Action buttons: **Allow Once** / **Always Allow** / **Deny**
- [ ] Fallback: if no desktop session, log to journal and allow CLI approval via `afw approve <name>`
- [ ] Rate-limit notifications to prevent spam (max 1 per app per 30 seconds)

### Phase 4: User Response Handling
- [ ] **Allow Once**: add temporary nft rules for this app (removed on app exit or daemon restart)
- [ ] **Always Allow**: save app config to `/etc/afw/conf.d/user_approved.toml` and reload
- [ ] **Deny**: log the denial, do nothing (default-drop handles it)
- [ ] `afw approve <name>` CLI command for headless/SSH use
- [ ] `afw deny <name>` CLI command to permanently block (add to deny list)
- [ ] `afw pending` CLI command to show apps waiting for approval

## Future Ideas (not scoped yet)
- Per-app IP/CIDR allow/deny lists
- Per-app bandwidth/rate limiting via nftables meters
- TUI dashboard with real-time traffic view
- Process ancestry verification (check full parent chain, not just comm)
- Binary hash verification before trusting comm name
