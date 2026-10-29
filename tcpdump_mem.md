# tcpdump — Memory Sheet

Commands and techniques learned during the *420-B01-HU tcpdump lab* (Ébénisterie Gatineau).
Reusable for any traffic-analysis lab.

---

## 1. Before capturing — find your interface

| Command | What it does |
|---|---|
| `ip -br a` | Brief list of interfaces, state (UP/DOWN) and IPs. Pick the one that's `UP` with a real IP (not `lo`). |
| `sudo tcpdump -D` | Interfaces tcpdump can capture on. `any` = all interfaces at once. |

> `lo` = loopback (127.0.0.1), never leaves the machine. `nflog`, `nfqueue`, `dbus-*`, `bluetooth-monitor` = system pseudo-interfaces, not the network.

---

## 2. Core options

| Option | Effect | Notes |
|---|---|---|
| `-i eth0` | Capture interface | Required for live capture |
| `-n` | No name resolution (IPs **and** ports stay numeric) | **Always use it.** See §8 |
| `-c 10` | Stop after 10 packets | tcpdump exits cleanly and flushes output |
| `-r file.pcap` | Read a capture file | **No sudo needed** |
| `-w file.pcap` | Write raw packets to a file (binary pcap) | Shows nothing on screen while capturing |
| `-A` | Show payload in ASCII | Read HTTP headers, cleartext credentials |
| `-X` | Show payload in hex + ASCII | For binary protocols |
| `-tttt` | Full timestamp: date + time | `2026-10-13 10:00:00.000000` |
| `-e` | Show MAC addresses | Layer 2 |
| `-v`, `-vv` | More header detail | TTL, IP ID, checksums, DNS details |
| `-l` | Line-buffered output | **Required when piping live capture to `tee`/`grep`** (see §8) |

> `-nr file.pcap` = `-n -r file.pcap` (options can be combined).

---

## 3. Live capture

```bash
# 10 packets, no name resolution
sudo tcpdump -i eth0 -n -c 10

# Only DNS and HTTP, saved to a text file at the same time
sudo tcpdump -i eth0 -n -l 'port 53 or port 80' | tee capture.txt

# Same with payload in ASCII (see Host:, User-Agent:, page content)
sudo tcpdump -i eth0 -n -l -A 'port 53 or port 80' | tee capture-ascii.txt

# HTTPS: payload is encrypted, only DNS + TLS metadata (SNI, ALPN) readable
sudo tcpdump -i eth0 -n -l -A 'port 53 or port 443' | tee https.txt

# Record 30 seconds to a pcap file, then stop automatically
sudo timeout 30 tcpdump -i eth0 -n -w ma_capture.pcap
```

> Tip: use a **second terminal** to generate traffic (`ping 8.8.8.8`, `curl -s http://example.com > /dev/null`) while the first one captures.

---

## 4. Reading a pcap file — overview

```bash
# Number of packets
tcpdump -nr file.pcap | wc -l

# First / last packet (start and end of capture)
tcpdump -nr file.pcap -tttt | head -1
tcpdump -nr file.pcap -tttt | tail -1

# Quick look at the first 10 packets
tcpdump -nr file.pcap | head

# Top talkers (source IPs by packet count)
tcpdump -nr file.pcap ip | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head
```

**How the top-talkers pipeline works:**
| Step | Role |
|---|---|
| `ip` | BPF filter: IPv4 packets only |
| `awk '{print $3}'` | Field 3 = source `IP.port` (e.g. `192.168.50.35.61337`) |
| `cut -d. -f1-4` | Keep the first 4 dot-separated parts = IP without port |
| `sort \| uniq -c` | Group identical lines and count them |
| `sort -rn` | Sort by count, highest first |
| `head` | Top 10 |

> Swap `$3` for `$5` to count **destination** IPs instead (field 5 ends with `:` — add `| tr -d :`).

---

## 5. DNS analysis

```bash
# All domains queried, with counts
tcpdump -nr file.pcap 'udp dst port 53' | awk '{print $8}' | sort | uniq -c | sort -rn

# Queries for a specific domain
tcpdump -nr file.pcap 'port 53' | grep 'domain.net'

# All DNS responses sent to one host
tcpdump -nr file.pcap 'src port 53 and dst host 192.168.50.35'

# Match responses to queries by transaction ID
tcpdump -nr file.pcap 'port 53' | grep -E '34718|35997|26680'
```

**Reading a DNS line:**
```
time       IP src.port        > dst.53:   ID+  TYPE? name.              (len)
10:00:41.2 IP 192.168.50.35.62786 > 192.168.50.10.53: 34718+ A? 0-izgecr33mr.cdn-maj-update.net. (49)
  $1      $2        $3          $4    $5            $6     $7        $8

10:00:41.2 IP 192.168.50.10.53 > 192.168.50.35.62786: 34718 1/0/0 A 198.51.100.66 (96)
                                                       ID   ans/auth/add  answer
```
- **Field `$8` = the queried name** (on queries only).
- `A?` = IPv4 query, `AAAA?` = IPv6, `PTR?` = reverse lookup.
- **Responses don't repeat the name** (without `-v`) → match them to the query with the **transaction ID** (`34718+` in query = `34718` in response).
- `NXDomain` = name does not exist.

**Red flags in DNS:**
- Domain that matches no known service of the organization, often imitating a legit one (`cdn-maj-update.net` → "mise à jour").
- **Numbered / random-looking subdomains** (`0-xxxx.`, `1-xxxx.`…) → DNS **exfiltration** (data encoded in subdomains).
- Queries at a **regular interval** → automated, not human.

---

## 6. BPF filters (capture/read filters)

**Always put filters in single quotes** `'...'` so the shell doesn't interpret them.

| Filter | Matches |
|---|---|
| `host 1.2.3.4` | To or from that IP |
| `src host 1.2.3.4` / `dst host 1.2.3.4` | From / to that IP |
| `net 192.168.50.0/24` | A whole subnet |
| `port 53` / `src port 53` / `dst port 53` | A port (either direction / source / destination) |
| `portrange 1-1024` | A port range |
| `tcp`, `udp`, `icmp`, `ip` | A protocol |
| `and`, `or`, `not` | Combine. Use parentheses for clarity: `'host A and (port 80 or port 443)'` |

### ICMP types
```bash
tcpdump -nr file.pcap 'icmp[icmptype] == icmp-echo'       # requests (type 8)
tcpdump -nr file.pcap 'icmp[icmptype] == icmp-echoreply'  # replies  (type 0)
```
`icmp[icmptype]` = the "type" byte of the ICMP header (same as `icmp[0]`).

| Type | Name | Meaning |
|---|---|---|
| 8 | `icmp-echo` | Ping request |
| 0 | `icmp-echoreply` | Ping reply |
| 3 | `icmp-unreach` | Destination unreachable |
| 11 | `icmp-timxceed` | TTL exceeded (traceroute) |

### TCP flags
```bash
# EXACTLY SYN (connection attempts only)
'tcp[tcpflags] == tcp-syn'

# AT LEAST SYN and ACK (SYN-ACK = port open) — mask version, more robust
'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# Any packet with RST set
'tcp[tcpflags] & tcp-rst != 0'
```
- `==` → the flag byte must be **exactly** that value.
- `& mask == mask` → those bits must **all be set**, others ignored.
- `& flag != 0` → that bit is set (whatever else is set).

**Flag bits:**
```
 CWR ECE URG ACK PSH RST SYN FIN
 128  64  32  16   8   4   2   1      → SYN-ACK = 2 + 16 = 18
```

**How tcpdump displays flags:**
| Display | Flags | Meaning |
|---|---|---|
| `[S]` | SYN | "I want to connect" |
| `[S.]` | SYN-ACK | Port **open** |
| `[.]` | ACK | Acknowledgement |
| `[P.]` | PSH-ACK | Data being sent |
| `[F.]` | FIN-ACK | Polite close |
| `[R]` / `[R.]` | RST / RST-ACK | Port **closed** or connection killed |

---

## 7. Recognizing attacks

### Ping sweep (host discovery)
- One source sends ICMP echo to a **sequential range** of IPs (`.1`, `.2`, `.3`…).
- Very fast and regular (e.g. 30 requests in 0.58 s, one every 20 ms).
- `length 8` = bare ICMP header, no data → **scanning tool** (a normal ping sends 32/56 bytes).
- Same ICMP `id`, `seq` incrementing → one program, one loop.
- Hosts that send `echo reply` = **alive**, now known to the attacker.

```bash
tcpdump -nr file.pcap 'icmp[icmptype] == icmp-echo'            # who sweeps, which range
tcpdump -nr file.pcap 'icmp[icmptype] == icmp-echo' | wc -l    # how many
tcpdump -nr file.pcap 'icmp[icmptype] == icmp-echoreply'      # who answers
```

### Port scan (SYN scan)
- One source sends **SYN** to many ports of one target, very fast (e.g. 18 ports in 51 ms).
- **nmap SYN scan (`-sS`) signature:** **fixed source port** for every probe + **`win 1024`**. Normal OS connections use `win 64240` (Linux/Windows) and a new source port each time.
- Ports in **random order** → nmap shuffles them by default.
- Answer `[S.]` = **open**, answer `[R.]` = **closed**, no answer = **filtered** (firewall).

```bash
# The scan's SYNs
tcpdump -nr file.pcap 'src host ATTACKER and tcp[tcpflags] == tcp-syn'

# Count them (isolate by fixed source port)
tcpdump -nr file.pcap 'src host ATTACKER and dst host TARGET and src port 61337 and tcp[tcpflags] == tcp-syn' | wc -l

# Open ports = SYN-ACK from target back to the scan's source port
tcpdump -nr file.pcap 'src host TARGET and dst host ATTACKER and dst port 61337 and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# Closed ports = RST from the target (closed ports answer [R.], so use the mask, not == tcp-rst)
tcpdump -nr file.pcap 'src host TARGET and dst port 61337 and tcp[tcpflags] & tcp-rst != 0' | wc -l

# The attacker's RSTs sent right after each SYN-ACK (half-open scan proof)
tcpdump -nr file.pcap 'src host ATTACKER and dst host TARGET and src port 61337 and tcp[tcpflags] & tcp-rst != 0'
```

**Sanity check:** open + closed = ports tested (e.g. 5 + 13 = 18). Ports with no reply at all = **filtered**.

**Why the attacker sends RST after SYN-ACK — half-open (stealth) scan:**
```
Attacker ── SYN ─────> Target
Attacker <── SYN-ACK ─ Target   ← port open: answer obtained
Attacker ── RST ─────> Target   ← cut, never sends the final ACK
```
- **Stealth:** connection never established → the application (FTP/RDP/SMB) isn't notified and usually logs nothing. Only network monitoring sees it.
- **Speed:** one packet out, one back per port.
- **No half-open connections** left on the target (no slowdown, fewer alerts).
- nmap crafts its own packets, so the attacker's kernel doesn't know the connection and also answers the SYN-ACK with a RST.
- The RST's `seq` = the `ack` value from the SYN-ACK, so the target accepts it.

**OS hints from the TCP window (`win`):** `win 8192` in replies → typical **Windows** host. `win 64240` → normal Linux/Windows client stack. `win 1024` → nmap-crafted probe.

### Common ports cheat sheet
| Port | Service | Port | Service |
|---|---|---|---|
| 21 | FTP (control) | 443 | HTTPS |
| 22 | SSH | 445 | SMB (Windows shares) |
| 23 | Telnet | 993 | IMAPS |
| 25 | SMTP | 1433 | MS SQL |
| 53 | DNS | 3306 | MySQL |
| 80 | HTTP | 3389 | RDP |
| 110 | POP3 | 5900 | VNC |
| 135 | MS RPC | 8080 | HTTP alt / proxies / C2 |
| 139 | NetBIOS | 143 | IMAP |

---

## 8. Gotchas & errors met

| Problem | Cause | Fix |
|---|---|---|
| Without `-n`: names instead of IPs, slow output, extra packets | tcpdump does **reverse DNS (PTR) lookups** itself → pollutes the capture | Always use `-n` |
| `\| tee file.txt` gives an **empty file** after Ctrl+C | Output is **block-buffered** in a pipe; Ctrl+C kills it before flushing | Add **`-l`** (line-buffered), or use `-w file.pcap` then `-r` |
| `-c 10 \| tee` worked fine without `-l` | `-c` makes tcpdump exit normally and flush | — |
| `tcpdump: Unable to write output: Broken pipe` | `head` closed the pipe after N lines | Harmless, ignore |
| `head: unrecognized option '--1'` | Typo | `head -1` (one dash) |
| awk prints nothing | `Print` with capital P → awk sees an empty variable | `print` (lowercase), awk is case-sensitive |
| Shell shows `>` and waits | Unbalanced quotes, e.g. `'{'print $3}'` | `'{print $3}'` |
| `cat file.pcap` shows garbage | pcap is **binary** | `tcpdump -r file.pcap` |
| Live capture needs `sudo`, reading doesn't | Capture touches the network interface; `-r` only reads a file | `sudo` only for live capture |
| `Command 'tcpdump' not found` | Typo (`tcpdmpdump`…) | Retype |
| `sudo tee` not needed | You own the current folder | Plain `tee` |

---

## 9. HTTP vs HTTPS — what an analyst can see

| | HTTP (port 80) | HTTPS (port 443) |
|---|---|---|
| DNS query | Cleartext | Cleartext |
| IP, port, timing, size | Visible | Visible |
| URL, `Host:`, `User-Agent:` | **Cleartext** with `-A` | Encrypted |
| Page content | **Cleartext** | Encrypted |
| Domain name | In `Host:` | In the **SNI** of the TLS Client Hello (cleartext) |
| ALPN (`h2`, `http/1.1`) | — | Cleartext in Client Hello |

---

## 10. Investigation method (checklist)

1. **Overview:** packet count, start/end time (`-tttt`), top talkers → spot the abnormal host.
2. **DNS:** list all queried domains → spot unknown/fake domains, numbered subdomains, who queries them, what IP they resolve to.
3. **Recon:** ICMP echo (ping sweep), SYN floods to one host (port scan) → who, which range/ports, what's open.
4. **Cleartext credentials:** HTTP POST, FTP (`USER`/`PASS`), Telnet → `-A` on the right port.
5. **C2 / exfiltration:** regular connections to an external IP (beaconing), odd ports, odd User-Agent, encoded DNS subdomains.
6. **Extract evidence:** `-w evidence.pcap` with a filter on the malicious IP.
7. **Report:** timeline, IOCs (IP, domain, port, User-Agent, accounts), prioritized recommendations.

> **Always note the exact command** next to each answer: it counts as much as the answer.

---

## 11. Cleartext credentials — HTTP forms

```bash
# 1. Who talks HTTP? (tcpdump shows the method/status at the end of the line: GET, POST, 200 OK, 302 Found)
tcpdump -nr file.pcap 'tcp port 80'

# 2. Read the payload of one conversation
tcpdump -nr file.pcap -A 'host CLIENT and host SERVER and tcp port 80'

# Shortcut: jump straight to form bodies / credential-looking fields
tcpdump -nr file.pcap -A 'tcp port 80' | grep -iE 'POST|user|login|pass|mot|pwd'
```

**How to read a login:**
- `GET /login-page` → `200 OK` = form sent to the browser (look at `<input name=...>` to learn field names).
- **`POST /login-page`** = form submitted. The **body is the last line after the empty line**: `field1=value1&field2=value2`.
- `302 Found` + `Location: /home` = redirect → **login usually succeeded**.
- `Set-Cookie: PHPSESSID=...` = **session cookie**, in cleartext too → session hijacking possible.

**URL encoding** (`application/x-www-form-urlencoded`): `%XX` = ASCII char with hex code XX.

| Code | Char | Code | Char |
|---|---|---|---|
| `%21` | `!` | `%26` | `&` |
| `%20` or `+` | space | `%3D` | `=` |
| `%40` | `@` | `%3F` | `?` |
| `%23` | `#` | `%2F` | `/` |
| `%24` | `$` | `%0D%0A` | CR LF (Return) |

```bash
# Decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('Erable2026%21'))"
printf '\x21\n'
```

**Other cleartext protocols to check the same way with `-A`:** FTP (21: `USER`/`PASS`), Telnet (23), POP3 (110: `USER`/`PASS`), IMAP (143: `LOGIN`), SMTP AUTH (25, base64), HTTP Basic auth (`Authorization: Basic` = base64 of `user:pass`).

**Tip:** `grep -- "-nf"` → `--` tells grep "end of options" so a pattern starting with `-` isn't read as an option.

---

## 12. FTP — credentials, files, data channel

FTP = **cleartext**, **two channels**: control (**port 21**) + data (dynamic port).

```bash
# Control channel: tcpdump prints FTP commands/replies at the end of each line (no -A needed)
tcpdump -nr file.pcap 'tcp port 21'

# Data channel: port computed from the 227 reply
tcpdump -nr file.pcap 'tcp port 50001'

# Data content (if readable / text file)
tcpdump -nr file.pcap -A 'tcp port 50001'
```

| Client command | Meaning | Server code | Meaning |
|---|---|---|---|
| `USER x` | Username | `220` | Server ready |
| `PASS x` | **Password (cleartext)** | `331` | Password required |
| `PASV` | Ask for passive data port | **`230`** | **Login OK** |
| `RETR f` | **Download** file | `530` | Login failed |
| `STOR f` | **Upload** file | **`227`** | **Passive mode: IP + port** |
| `LIST` | Directory listing | `150` | Data transfer starting |
| `QUIT` | Disconnect | `226` | Transfer complete |
| | | `221` | Goodbye |

**Passive-mode port calculation:**
```
227 Entering Passive Mode (192,168,50,20,195,81)
                           h1  h2  h3 h4  p1  p2
IP   = h1.h2.h3.h4 = 192.168.50.20
port = p1 × 256 + p2 = 195 × 256 + 81 = 50001
```
(16-bit port split in two bytes: p1 = high byte, p2 = low byte.)
Active mode equivalent: client sends `PORT h1,h2,h3,h4,p1,p2` — same formula.

**What to report:** account + password, `230` = valid, file name (`RETR`) + sensitivity, size on the data channel (`[P.] length N`), timing vs other events.
**Sanity check timelines:** data channel must open *after* the `227` reply. If not → simulated capture artefact (mention it).

---

## 13. DNS exfiltration — reassemble & decode

**How DNS tunnelling works:** malware encodes stolen data (base32), slices it into chunks, and queries `N-chunk.attacker-domain.tld`. The internal DNS server doesn't know the name → forwards it to the **attacker's DNS server**, which collects the chunks. DNS is almost never blocked, so data leaves through the company's own resolver.

**Why base32, not base64:** DNS names are case-insensitive and allow only letters, digits, `-`. Base32 = `A–Z` + `2–7` only → survives DNS. Base64 (mixed case, `+`, `/`) would break.

```bash
# Extract chunks in order
tcpdump -nr file.pcap 'udp dst port 53' | awk '{print $8}' | grep -E '^[0-9]+-' | sort -n | cut -d. -f1 | cut -d- -f2

# Glue into one string (+ count chars)
... | tr -d '\n'; echo
... | tr -d '\n' | wc -c

# Decode (base32 needs UPPERCASE)
echo "chunks" | tr a-z A-Z | base32 -d; echo

# If "base32: invalid input" → add '=' padding up to a multiple of 8 chars
echo "chunks===" | tr a-z A-Z | base32 -d; echo
```

| Tool | Does |
|---|---|
| `grep -E '^[0-9]+-'` | Lines starting with digits + dash (`^` = start of line, `+` = one or more) |
| `sort -n` | **Numeric** sort (`2` before `10`). Plain `sort` is alphabetical (`10` before `2`) |
| `cut -d. -f1` | Split on `.`, keep field 1 |
| `cut -d- -f2` | Split on `-`, keep field 2 |
| `cut -d. -f1-4` | Keep fields 1 **to** 4 (e.g. IP without port) |
| `tr a-z A-Z` | Lowercase → uppercase |
| `tr -d '\n'` | **Delete** line breaks |
| `base32 -d` / `base64 -d` | Decode |

**Padding:** base32 works in blocks of 8 chars → pad with `=` up to a multiple of 8 (37 → 40 = `===`). Base64: blocks of 4.

**Recognize the encoding:** only `A–Z 2–7` (+`=`) → base32 · `A–Z a–z 0–9 + /` (+`=`) → base64 · only `0–9 a–f` → hex (`xxd -r -p`).

### `;` vs `|` — common trap
- `|` (pipe) sends the **output** of the left command into the right one.
- `;` just runs commands **one after the other**, nothing is passed.
- So `cmd | tr -d '\n'; echo | wc -c` = run `cmd | tr` (prints the string), **then** run `echo | wc -c` separately (counts the empty line → `1`). Output looks like `...zx21` — that `1` is not part of the string!
- Put `; echo` only at the **very end**, just to get a clean new line.

---

## 14. C2 & beaconing

**C2 (Command & Control):** channel the malware uses to check in with the attacker and receive orders. **Beaconing** = calling home at a regular interval ("I'm alive — any orders?").

```bash
# 1. New connections to the suspect IP, full timestamps → compute intervals
tcpdump -nr file.pcap -tttt 'host C2_IP and tcp[tcpflags] == tcp-syn'

# 2. What the victim sends (data packets only = PSH flag)
tcpdump -nr file.pcap -A 'src host VICTIM and dst host C2_IP and tcp[tcpflags] & tcp-push != 0'

# 3. Server replies — compare SIZES first (works even on encrypted traffic)
tcpdump -nr file.pcap 'src host C2_IP and tcp[tcpflags] & tcp-push != 0'

# 4. Read a normal reply vs the odd one (parentheses group the 'or'!)
tcpdump -nr file.pcap -A 'src host C2_IP and (dst port 53004 or dst port 53005) and tcp[tcpflags] & tcp-push != 0'

# Quick interval calc (seconds since previous packet)
tcpdump -nr file.pcap -ttt 'host C2_IP and tcp[tcpflags] == tcp-syn'
```
> `-ttt` = time **delta** since the previous printed packet → beacon intervals read directly.

**Beacon red flags:**
| Clue | Example |
|---|---|
| Regular interval (+ small **jitter**) | every ~30 s ± 0.4 s |
| Odd port for web | `8080` to an internet IP |
| Bot ID / counter in URL | `/maj/check?id=ATELIER-35&n=5` |
| Fake / outdated **User-Agent**, identical every time | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` = IE6 on XP |
| Sequential source ports | 53000, 53001, 53002… |
| Same reply size most of the time, **one different** | 42 bytes `NOOP` vs 48 bytes `CMD:whoami` |

**User-Agent decoding:** `Windows NT 5.1` = XP · `6.1` = 7 · `10.0` = 10/11 · `MSIE 6.0` = IE6 (2001). Modern browsers: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/... Edg/...`.

**C2 reply vocabulary:** `NOOP` = no operation (nothing to do). `CMD:<x>` = run command x. `whoami` = attacker checking privileges (typical first post-exploitation command → hands-on-keyboard).

**BPF precedence:** always wrap `or` in parentheses: `'host A and (port 1 or port 2)'`.
**URL params:** `?` starts parameters, `&` separates them (terminal fonts can make `&` look like `6`).

---

## 15. Extracting evidence (filtered pcap)

Combine **`-r` + filter + `-w`**: read the original, keep only matching packets, write a new pcap.

```bash
# Everything to/from the C2 (both directions)
tcpdump -nr original.pcap -w preuve_c2.pcap 'host 198.51.100.66'

# Other examples
tcpdump -nr original.pcap -w preuve_ftp.pcap 'host 192.168.50.20 and (port 21 or port 50001)'
tcpdump -nr original.pcap -w preuve_attacker.pcap 'host 192.168.50.35'
tcpdump -nr original.pcap -w preuve_dns.pcap 'port 53 and host 192.168.50.35'

# Verify
ls -l preuve_c2.pcap
tcpdump -nr preuve_c2.pcap | head
tcpdump -nr preuve_c2.pcap | wc -l
```
- No `sudo` needed (files only). Nothing prints while writing.
- `host X` = both directions; `src host X` / `dst host X` = one direction only.

**Sanity-check the count:** a short, complete TCP exchange with one request + one response =
`SYN, SYN-ACK, ACK, request, ACK, response, ACK, FIN, FIN, ACK` = **10 packets**.
→ 8 beacons × 10 = 80. Cross-check with top-talker counts (C2 sent 4 per beacon × 8 = 32 ✓).

**Why extract:** smaller file to hand over, keeps other users' traffic private, reusable for re-analysis and reports.

**Optional — hash the evidence** (prove it wasn't modified later):
```bash
sha256sum preuve_c2.pcap
```
