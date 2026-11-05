# SuricataChecker v. 1.2.0

A portable Windows tool for **running and reviewing the Suricata IDS on a Windows host**. It installs and sets up
Npcap, Suricata, the configuration, the ET Open rules and the Suricata service in one window, checks their state at
every start and lets you browse, filter and analyze the alerts and events in `eve.json`.

The supplied configuration turns Suricata into a host IDS: the default Suricata 8.0 configuration adapted for a
Windows host, the Proofpoint Emerging Threats Open rules and the protocol anomaly rules of OISF.

## Highlights

- **One setup window**: checks Npcap, Suricata, the configuration, the rules and the service, and installs or fixes
  whatever is missing in one go.
- **Verified installers**: Npcap and Suricata come only from the official download pages and run only after the
  signature of the publisher and the SHA-256 have been checked.
- **Portable**: no installation, a single signed exe; settings are kept per computer, so the folder can be moved.
- **Runs as a standard user**: administrator rights (UAC) only for actions that change Suricata.
- **False positive marks and a knowledge base** of confirmed false positives.
- **Optional AI analysis** of the events (Claude or ChatGPT) with masking of local identities.

## Requirements

- Windows 10/11 or Windows Server 2016+ (64-bit)
- .NET Framework 4.8 (included in Windows 10 1903+ / Windows 11)
- Administrator rights for the setup, the configuration test and the service restart
- Internet access for the setup (installers, ET Open rules)

## Download

Download everything at once:

- **ZIP**: on the repository page click **Code → Download ZIP**, or use
  [main.zip](https://github.com/d0tju1ce/suricataChecker/archive/refs/heads/main.zip).
  Before extracting, unblock the archive (right-click → Properties → **Unblock**), or run:

  ```powershell
  Unblock-File "$env:USERPROFILE\Downloads\suricataChecker-main.zip"
  ```

- **Git**:

  ```powershell
  git clone https://github.com/d0tju1ce/suricataChecker.git
  ```

These files must stay together in one folder:

| File | Purpose |
|---|---|
| `SuricataChecker-<version>.exe` | desktop app |
| `config\suricata\` | Suricata configuration (`suricata.yaml`, `threshold.config`) |
| `config\Install-SuricataConfig.ps1` | deploys the configuration, the ET Open rules and the Suricata service |
| `suricataChecker.settings.xml` | settings of each computer (created automatically) |
| `marks.json` | false positive marks and the knowledge base (created on the first mark) |

Keep the folder where only administrators can change it (e.g. `C:\Program Files\suricataChecker`), not on a share or
a USB stick everyone can write to – its configuration is deployed into the Suricata service running as LocalSystem.

## Usage

### First start – Suricata setup

Start `SuricataChecker-<version>.exe`. At every start the app checks Suricata on the computer (read-only, no network):

| Check | Why |
|---|---|
| Npcap in the *WinPcap API-compatible Mode* | without `wpcap.dll` in System32 neither Suricata nor its service can start |
| Suricata installed | |
| Configuration deployed | `suricata.yaml` and `threshold.config` in the Suricata folder are the ones in `config\suricata` |
| ET Open rules present | the Suricata installer does not include them |
| Suricata service registered and running | the Suricata installer does not create the service |

If everything is fine, the app opens directly. Otherwise the **Suricata setup** window opens first: it shows the state
of each part and preselects what is needed; updates (newer Suricata / Npcap, fresh ET Open rules) are offered
unticked. **Install and set up** does everything in one go and shows the progress:

- **Npcap / Suricata**: the newest installer is downloaded from `npcap.com` / `openinfosecfoundation.org` and verified
  before it runs; the installer opens with its own window.
- **Configuration, rules and service**: `Install-SuricataConfig.ps1` downloads the ET Open rules, tests the
  configuration and the rules (`suricata -T`) while Suricata keeps running, backs up, deploys, registers the service on
  the selected network adapter and starts it. On any error the backup is restored.

As a standard user the button starts the app again as administrator (UAC). The check at start can be turned off in
the window (e.g. on a computer that only reads an `eve.json` of another one). Later: **Settings → Set up Suricata**.

### Desktop app

- **Overview** shows the state of Suricata: installation, service, process, Npcap, configuration, rules and `eve.json`.
- **EDR – Events** lists the events from `eve.json`. Filter by event type, time, severity, IP (exact address, CIDR or
  prefix) and full text (prefix `!` excludes, e.g. `!2027766`). Alerts are highlighted by severity; click a row for the
  event detail. **Export CSV**, **AI analyzer** and auto-refresh (reads only the new lines of `eve.json`).
- Right-click an alert → **Mark as false positive**: the row stays, greyed out. The app then offers to hide all alerts
  of the same signature (with an extra warning for severity 1–2). **Show hidden false positives** shows them again.
  Marks are kept in `marks.json`, separately for each computer, and affect only the app – to stop Suricata from
  raising an alert, suppress its SID in `config\suricata\threshold.config` and deploy it.
- **Knowledge base**: false positives proposed by the AI analyzer are saved only after you confirm them
  (**Apply verdicts**), with a scope (same hosts, same destination or the whole signature) and a reason. Matching
  alerts, also future ones, are greyed out.
- **Settings**: **Set up Suricata**, **Test configuration** (`suricata -T`), **Restart Suricata service**, the false
  positives and the knowledge base, the AI analyzer.

Settings in `suricataChecker.settings.xml` (one entry per computer, saved with **Save settings** and when the app is
closed):

| Setting | Meaning |
|---|---|
| `SuricataConfigPath` | `suricata.yaml` used by the app (found automatically) |
| `SuricataEvePath` | `eve.json` to read (found automatically from the configuration) |
| `MaxEvents` | maximum number of events shown |
| `EveMaxMegabytes` | how many MB are read from the end of `eve.json` |
| `AutoRefresh`, `RefreshSeconds` | automatic refresh of the events and its interval |

### Install script

The setup window runs `config\Install-SuricataConfig.ps1`; it can also be run by hand (PowerShell as administrator):

```powershell
powershell -ExecutionPolicy Bypass -File .\config\Install-SuricataConfig.ps1             # configuration + rules + service
powershell -ExecutionPolicy Bypass -File .\config\Install-SuricataConfig.ps1 -RulesOnly  # rules update only
```

| Parameter | Meaning |
|---|---|
| `-SuricataDir` | Suricata installation folder (default `C:\Program Files\Suricata`) |
| `-Interface` | capture interface (`\Device\NPF_{GUID}` or an IP address); default: the adapter of the existing service, on the first run the adapter with the best default route |
| `-RulesOnly` | update only the rules and restart the service |
| `-Yes` | unattended run, no questions |

## AI analyzer

The **AI analyzer** button sends the selected or shown events to **Claude** (Anthropic API) or **ChatGPT** (OpenAI
API) over HTTPS and shows the analysis: verdict and severity, findings with MITRE ATT&CK IDs, likely benign alerts,
recommended actions and tuning suggestions. Follow-up questions continue the conversation; **Save report** writes it
as Markdown.

1. Create an API key at [console.anthropic.com](https://console.anthropic.com) or
   [platform.openai.com](https://platform.openai.com). The API is billed per use; a ChatGPT Plus / Claude Pro
   subscription does not include API access.
2. **Settings → AI analyzer**: paste the key, **Save key**, **Test connection**, choose the model.

The key is stored in the Windows Credential Manager of the current user on the computer, never in the app folder.

| What happens to the data | |
|---|---|
| Grouping | identical events are sent once with a count, long values are shortened |
| Masking (on by default) | local identities (computer, domain and user names, internal IP addresses and other identifiers) are replaced with pseudonyms; the answer is shown with the real values |
| Secrets | passwords, tokens, API keys and private keys are always removed, also from your questions |
| Never sent | packet payloads and HTTP bodies |
| Preview | **Preview data** shows exactly what will be sent |

The AI can be wrong – use the answer as a lead for your own investigation.

## What is monitored

| Source | Content |
|---|---|
| ET Open – malware and C2 | malware, mobile malware, C2, worms, phishing, botnet C&C IPs, compromised hosts, Spamhaus DROP, DShield, CINS Army |
| ET Open – attacks | exploits, exploit kits, shellcode, web server, web client and web application attacks, SQL, scans, DoS, attack responses |
| ET Open – policy and info | remote access tools, abused services, P2P, file sharing, coin miners, dynamic DNS, TOR, suspicious DNS, user agents, JA3 |
| OISF built-in rules | protocol anomalies (decoder, stream, HTTP, TLS, DNS, SMB, … `*-events.rules`) |
| `threshold.config` | suppression of noise typical of a Windows host (offload, unknown ethertypes, …) |

The full list of the loaded rule sets, the changes against the default configuration and the suppressed rules is in
[docs/Suricata-Detection-Rules.md](docs/Suricata-Detection-Rules.md).

## Configuration

| File | Content |
|---|---|
| `config\suricata\suricata.yaml` | Suricata 8.0 configuration (IDS mode, ET Open, EVE JSON log without packet content) |
| `config\suricata\threshold.config` | suppressed and rate-limited alerts |
| `config\Install-SuricataConfig.ps1` | deployment: rules download, test, backup, deploy, service |

Change the configuration (e.g. `HOME_NET`) in `config\suricata` and deploy it with **Set up Suricata** – a file edited
directly in `C:\Program Files\Suricata` is reported as different and the setup offers to overwrite it.
Setting up Suricata by hand: [docs/Suricata-Setup-Guide.md](docs/Suricata-Setup-Guide.md).

## Digital signature

`SuricataChecker-<version>.exe` and `Install-SuricataConfig.ps1` are signed with a self-signed certificate:

| | |
|---|---|
| Subject | `CN=SuricataChecker Code Signing` |
| SHA1 thumbprint | `E5E4693EEFC36DDFB6C21F7C442F79244332EA50` |
| Valid until | 3 Nov 2031 |
| Public certificate | `cert\SuricataChecker.cer` (the private key is not in the repository) |

Verify the signature:

```powershell
Get-AuthenticodeSignature .\SuricataChecker-*.exe, .\config\Install-SuricataConfig.ps1
```

To make Windows report the signature as `Valid`, import the certificate once (PowerShell as administrator):

```powershell
Import-Certificate -FilePath .\cert\SuricataChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\SuricataChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

Without the import the status is `UnknownError` (untrusted), but you can still check the thumbprint.

## Building from source

The source code is in `src\`. Run `src\build.cmd`; it needs the .NET SDK. The build compiles the exe, copies it to the
app folder as `SuricataChecker-<version>.exe` (version from `src\SuricataChecker.csproj`), removes older versions, checks
the syntax of the install script and signs the exe and the script. Signing is skipped if the code signing certificate
is not present.

`src\make_dist.ps1` then builds the distribution package `dist\SuricataChecker-<version>.zip` (+ `.sha256`). It checks
the version, the signatures and the install script, and leaves out local data: `suricataChecker.settings.xml`,
`marks.json`, `src\` and `dist\`.

## Known limitations

- Suricata on Windows captures with Npcap; the free Npcap may be used on up to 5 systems – a company deployment needs
  an Npcap OEM licence.
- The Windows build of Suricata has no libmagic: rules with `file.magic` are commented out when deploying.
- The ET Open rules are checked against the MD5 checksum published next to them (detects a damaged download); their
  authenticity rests on the HTTPS connection to `rules.emergingthreats.net`.
- The rules are updated on demand (**Set up Suricata** or `-RulesOnly`), not automatically.
- `eve.json` is not rotated by Suricata on Windows; the app reads only the last `EveMaxMegabytes` of it.
- More noise on computers with many updates and cloud services (e.g. Windows Update P2P) – suppress it in
  `threshold.config`.

## Roadmap

- Scheduled update of the ET Open rules
- Rotation and archiving of `eve.json`
- Charts of alerts over time and top signatures
- Export of the knowledge base and of suppressions to `threshold.config`

## Changelog

### 1.2.0

- **Suricata setup** window: checks Npcap, Suricata, the configuration, the rules and the service at every start and
  installs or fixes whatever is missing in one go (official installers verified by signature and SHA-256).
- Npcap without the WinPcap API-compatible Mode and missing rule files are detected before Suricata is started.
- Knowledge base of false positives confirmed from the AI analysis.
- The exe carries its version in the name; settings are saved automatically when the app is closed.
- Fixes from a code review: syntax check of the install script in the build, time range change with auto-refresh,
  thread safety of the marks, permission checks of the folders above the app and Suricata folders.

### 1.1.0

Security and robustness fixes based on a code review.

- Links in AI answers open only as http(s) after confirmation.
- Masking of identities carried by network protocols; secrets removed from the data and the questions.
- The install script tests the new configuration before stopping Suricata, backs up and restores on error.
- `suricata.exe` is started only from protected locations; IP filter matches exact addresses and CIDR ranges.
- `src\make_dist.ps1` builds a clean distribution ZIP without local data.

### 1.0.0

First public release.

## Sources

- Open Information Security Foundation: [Suricata](https://suricata.io) and its documentation
- Proofpoint: [Emerging Threats Open](https://rules.emergingthreats.net) rules
- [Npcap](https://npcap.com) packet capture library

## License

The code is licensed under the MIT License (see `LICENSE`). The embedded Nunito Sans font is licensed under the
SIL Open Font License 1.1 (`src\Fonts\OFL.txt`). Suricata and the ET Open rules are not part of the repository; they
are downloaded during the setup under their own licences.
