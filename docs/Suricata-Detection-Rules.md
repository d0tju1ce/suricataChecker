# Suricata detection rules – suricataChecker

Files: `config\suricata\suricata.yaml`, `config\suricata\threshold.config` · Suricata **8.0.7** ·
rules deployed to `C:\Program Files\Suricata\rules` · **51,350 active rules** (as of 2026-11-02)

## Source (what the configuration is based on)

| Part | Template / source | Licence |
|---|---|---|
| `suricata.yaml` | **the default `suricata.yaml` from the Suricata 8.0.7 installer for Windows** (OISF, <https://suricata.io>) – the file was taken over as a whole and changed only in the points below; the original is backed up on the PC as `C:\Program Files\Suricata\suricata.yaml.original` | GPLv2 |
| ET Open rules | **Proofpoint Emerging Threats Open** for Suricata 8 – <https://rules.emergingthreats.net/open/suricata-8.0.0/emerging.rules.tar.gz>, downloaded by `Install-SuricataConfig.ps1` | BSD / GPLv2 (per rule) |
| Built-in rules | protocol anomaly rules shipped with the Suricata installation (`*-events.rules`, `files.rules`) – OISF | GPLv2 |
| `threshold.config` | custom – suppression of the noise found while deploying on this PC | – |

The rules are **not hand-written** – the detection logic comes entirely from ET Open and OISF. The project only
decides **which rule sets are loaded** and **what is suppressed**.

## Changes against the default `suricata.yaml`

| Setting | Default | Changed to | Reason |
|---|---|---|---|
| `rule-files` | a list of ET sets (some of them do not exist in the package), built-in rules commented out | 48 ET Open sets + 21 built-in sets | load only existing files; enable the detection of protocol anomalies |
| skipped ET sets | – | `emerging-hunting`, `-games`, `-inappropriate`, `-retired`, `-deleted`, `botcc.portgrouped` | high false positive rate / outdated / duplicate |
| skipped built-in rules | – | `dnp3-events`, `enip-events`, `modbus-events` | industrial protocols whose parsers are disabled (the rules could not be loaded) |
| `pcap: checksum-checks` | `auto` | `no` | a host sensor sees outgoing packets before the network card computes the checksum (offload) |
| `stream: checksum-validation` | `yes` | `no` | the same – otherwise thousands of false *invalid checksum* alerts |
| `eve-log: community-id` | `false` | `true` | correlation with Zeek, SIEM and other tools |
| `eve-log: alert: tagged-packets` | `yes` | `no` | tagged packets are packet content (base64) – eve.json is readable by every user |
| `threshold-file` | commented out | `C:\Program Files\Suricata\threshold.config` | noise suppression |

Changes made when deploying the rules (`Install-SuricataConfig.ps1`):

- rules with the `file.magic` keyword are commented out (9 rules) – the Windows build of Suricata has no libmagic and Suricata 8 would otherwise refuse to load the whole set.

## Suppressed rules (`threshold.config`)

| SID | Signature | Reason |
|---|---|---|
| 2200002 | SURICATA IPv4 total length smaller than header size | Large Send Offload – outgoing packets captured before segmentation have length 0 |
| 2200121 | SURICATA Ethertype unknown | Hyper-V / LLDP / proprietary L2 frames |
| 2260001 | SURICATA Applayer Wrong direction first Data | pcap on a Windows host captures outgoing TLS data before the handshake |

> 💡 On this PC a large part of the alerts is **ET INFO Windows Update P2P Activity (SID 2027766)** – sharing of
> Windows updates in the network (Delivery Optimization). If you do not want to see it, add the line
> `suppress gen_id 1, sig_id 2027766` to `threshold.config` and run `Install-SuricataConfig.ps1`.

## Loaded rule sets

Column **Disabled** = rules commented out in the file already by the author (ET ships them disabled –
outdated or noisy) or because of `file.magic`.

### ET Open (Proofpoint Emerging Threats)

| File | Loaded | Active | Disabled | Content |
|---|---|---:|---:|---|
| `botcc.portgrouped.rules` | **no** | 0 | 0 | the same as botcc, grouped by ports (duplicate) |
| `botcc.rules` | yes | 5 | 0 | IP addresses of known botnet C&C servers |
| `ciarmy.rules` | yes | 299 | 0 | IP addresses with a bad reputation (CINS Army) |
| `compromised.rules` | yes | 18 | 0 | known compromised hosts |
| `drop.rules` | yes | 71 | 0 | Spamhaus DROP – stolen/abused IP ranges |
| `dshield.rules` | yes | 1 | 0 | the most active attacking networks (DShield) |
| `emerging-activex.rules` | yes | 184 | 351 | ActiveX vulnerabilities |
| `emerging-adware_pup.rules` | yes | 682 | 601 | adware and potentially unwanted programs |
| `emerging-attack_response.rules` | yes | 690 | 107 | responses of compromised systems (e.g. uid=0 output, shell banner) |
| `emerging-chat.rules` | yes | 54 | 12 | chat applications |
| `emerging-coinminer.rules` | yes | 25 | 3 | cryptocurrency mining |
| `emerging-current_events.rules` | yes | 54 | 186 | current campaigns |
| `emerging-deleted.rules` | **no** | 0 | 3466 | deleted rules (archive) |
| `emerging-dns.rules` | yes | 26 | 23 | suspicious DNS traffic |
| `emerging-dos.rules` | yes | 59 | 56 | DoS attacks |
| `emerging-dyn_dns.rules` | yes | 6096 | 25 | dynamic DNS domains |
| `emerging-exploit.rules` | yes | 1713 | 389 | exploits |
| `emerging-exploit_kit.rules` | yes | 2678 | 2801 | exploit kits |
| `emerging-file_sharing.rules` | yes | 190 | 7 | file sharing |
| `emerging-ftp.rules` | yes | 58 | 58 | FTP |
| `emerging-games.rules` | **no** | 23 | 66 | games |
| `emerging-hunting.rules` | **no** | 1391 | 105 | threat hunting (high false positive rate) |
| `emerging-icmp.rules` | yes | 14 | 91 | ICMP |
| `emerging-imap.rules` | yes | 17 | 16 | IMAP |
| `emerging-inappropriate.rules` | **no** | 1 | 25 | inappropriate content |
| `emerging-info.rules` | yes | 4550 | 810 | informational (detected applications, user agents, …) |
| `emerging-ja3.rules` | yes | 102 | 14 | JA3 TLS fingerprints of malware |
| `emerging-malware.rules` | yes | 19378 | 7681 | malware – C2 communication, payload downloads |
| `emerging-misc.rules` | yes | 21 | 40 | miscellaneous |
| `emerging-mobile_malware.rules` | yes | 1146 | 195 | mobile malware |
| `emerging-netbios.rules` | yes | 392 | 82 | NetBIOS/SMB attacks |
| `emerging-p2p.rules` | yes | 85 | 34 | P2P networks |
| `emerging-phishing.rules` | yes | 2951 | 332 | phishing |
| `emerging-pop3.rules` | yes | 9 | 11 | POP3 |
| `emerging-remote_access.rules` | yes | 87 | 2 | remote access tools (RAT, RMM) |
| `emerging-retired.rules` | **no** | 417 | 62 | retired rules |
| `emerging-rpc.rules` | yes | 83 | 34 | RPC |
| `emerging-scada.rules` | yes | 90 | 2 | SCADA/ICS |
| `emerging-scan.rules` | yes | 286 | 81 | network and vulnerability scans |
| `emerging-shellcode.rules` | yes | 57 | 120 | shellcode in traffic |
| `emerging-smtp.rules` | yes | 17 | 9 | SMTP |
| `emerging-snmp.rules` | yes | 16 | 17 | SNMP |
| `emerging-sql.rules` | yes | 191 | 120 | SQL injection |
| `emerging-ta_abused_services.rules` | yes | 120 | 5 | legitimate services abused by attackers |
| `emerging-telnet.rules` | yes | 8 | 2 | Telnet |
| `emerging-tftp.rules` | yes | 13 | 7 | TFTP |
| `emerging-user_agents.rules` | yes | 280 | 57 | suspicious user agents |
| `emerging-voip.rules` | yes | 16 | 5 | VoIP/SIP |
| `emerging-web_client.rules` | yes | 475 | 331 | attacks on web clients (browsers) |
| `emerging-web_server.rules` | yes | 721 | 185 | attacks on web servers |
| `emerging-web_specific_apps.rules` | yes | 6095 | 880 | attacks on specific web applications |
| `emerging-worm.rules` | yes | 9 | 10 | worms |
| `threatview_CS_c2.rules` | yes | 22 | 0 | Cobalt Strike C2 servers (Threatview.io) |
| `tor.rules` | yes | 808 | 0 | Tor exit nodes |

### Built-in Suricata rules (OISF) – protocol anomalies

| File | Loaded | Active | Disabled | Content |
|---|---|---:|---:|---|
| `app-layer-events.rules` | yes | 6 | 1 | APP-LAYER protocol anomalies |
| `decoder-events.rules` | yes | 117 | 4 | DECODER protocol anomalies |
| `dhcp-events.rules` | yes | 2 | 0 | DHCP protocol anomalies |
| `dnp3-events.rules` | **no** | 8 | 0 | DNP3 protocol anomalies |
| `dns-events.rules` | yes | 11 | 0 | DNS protocol anomalies |
| `enip-events.rules` | **no** | 2 | 0 | ENIP protocol anomalies |
| `files.rules` | yes | 0 | 33 | templates for checking transferred files (type, hash, storing) – shipped disabled, enabled manually |
| `ftp-events.rules` | yes | 5 | 0 | FTP protocol anomalies |
| `http2-events.rules` | yes | 21 | 1 | HTTP2 protocol anomalies |
| `http-events.rules` | yes | 56 | 4 | HTTP protocol anomalies |
| `ipsec-events.rules` | yes | 14 | 0 | IPSEC protocol anomalies |
| `kerberos-events.rules` | yes | 2 | 0 | KERBEROS protocol anomalies |
| `modbus-events.rules` | **no** | 8 | 0 | MODBUS protocol anomalies |
| `mqtt-events.rules` | yes | 13 | 0 | MQTT protocol anomalies |
| `nfs-events.rules` | yes | 3 | 0 | NFS protocol anomalies |
| `ntp-events.rules` | yes | 2 | 0 | NTP protocol anomalies |
| `quick-events.rules` | yes | 3 | 0 | QUIC protocol anomalies (the file name is spelled like this in the original) |
| `rfb-events.rules` | yes | 5 | 0 | RFB protocol anomalies |
| `smb-events.rules` | yes | 19 | 0 | SMB protocol anomalies |
| `smtp-events.rules` | yes | 15 | 8 | SMTP protocol anomalies |
| `ssh-events.rules` | yes | 3 | 0 | SSH protocol anomalies |
| `stream-events.rules` | yes | 59 | 8 | STREAM protocol anomalies |
| `tls-events.rules` | yes | 30 | 0 | TLS protocol anomalies |
| `websocket-events.rules` | yes | 2 | 0 | WEBSOCKET protocol anomalies |

## Highlighting in suricataChecker

The **EDR – Events** page highlights alerts by severity: **1** (and `drop` events) – light beige row with dark text,
**2** – darker beige row, **3 and lower** – dark row with beige text.
