# suricataChecker

Portable Windows monitor for the **Suricata** IDS: it sets up Npcap, Suricata, the ET Open rules and the Suricata
service in one window, shows the state of Suricata and lets you browse, filter and analyze the events in `eve.json`.

- No installation – a single signed exe, requires only .NET Framework 4.8 (part of Windows 10 / 11)
- Runs as the current user; administrator rights only for actions that change Suricata (UAC on demand)
- Optional AI analysis of the events (Claude or ChatGPT) with masking of local identities
- False positive marks and a local knowledge base of confirmed false positives

## Contents

| Path | Description |
|---|---|
| `SuricataChecker-<version>.exe` | the application |
| `config\suricata\suricata.yaml` | Suricata 8.0 configuration (IDS, ET Open, Windows host) |
| `config\suricata\threshold.config` | suppression of false positive alerts |
| `config\Install-SuricataConfig.ps1` | deploys the configuration, the ET Open rules and the Suricata service |
| `docs\Suricata-Setup-Guide.md` | setting up Suricata on a new PC (also the manual procedure) |
| `docs\Suricata-Detection-Rules.md` | overview of the rule sets, changes and their source |
| `assets\` | logo (PNG 256 / 512 / 1024) and the icon |
| `cert\SuricataChecker.cer` | public code signing certificate |
| `src\` | source code (C#, WinForms, .NET Framework 4.8) and build scripts |

## Quick start

1. Copy the folder to the PC – preferably to a folder only administrators can change
   (e.g. `C:\Program Files\suricataChecker`), not to a share or a USB stick everyone can write to.
2. Start `SuricataChecker-<version>.exe`.
3. If Suricata is not ready yet, the **Suricata setup** window opens first (see below). Otherwise the application opens
   directly on the *EDR – Events* page.

Settings are stored next to the exe in `suricataChecker.settings.xml`, separately for each computer, so the folder can
be moved as a whole. Changes on the Settings page are saved with **Save settings** and automatically when the
application is closed. Unexpected errors are written to `%LOCALAPPDATA%\suricataChecker\error.log`.

## Setting up Suricata

At start the application checks (read-only, no network):

| Check | Why |
|---|---|
| Npcap in the *WinPcap API-compatible Mode* | without `wpcap.dll` in System32 Suricata and its service cannot start |
| Suricata installed | |
| Configuration deployed | `suricata.yaml` and `threshold.config` in the Suricata folder are the ones in `config\suricata` |
| ET Open rules present | the Suricata installer does not include them |
| Suricata service registered and running | the Suricata installer does not create the service |

When something is missing, the **Suricata setup** window shows the state of each part and preselects what is needed;
updates (newer Suricata / Npcap, fresh ET Open rules) are offered unticked. **Install and set up** does everything in
one go and shows the progress:

- **Npcap / Suricata** – the newest official installer is downloaded from `npcap.com` /
  `openinfosecfoundation.org` and verified before it runs (valid Authenticode signature of the publisher, known
  SHA-256 for the tested versions); the installer opens with its own window.
- **Configuration, rules and service** – `config\Install-SuricataConfig.ps1` downloads the ET Open rules, tests the
  configuration and the rules (`suricata -T`) while Suricata keeps running, backs up, deploys, registers the service
  on the selected network adapter and starts it. On any error the backup is restored.

Administrator rights are needed – as a standard user the button starts the application again with UAC. The check at
start can be turned off in the window (e.g. on a PC that only reads an `eve.json` of another one). Later:
*Settings → Set up Suricata*.

> Change the configuration (e.g. `HOME_NET`) in `config\suricata` and deploy it with *Set up Suricata* –
> a file edited directly in `C:\Program Files\Suricata` is reported as different and the setup offers to overwrite it.

The script can also be run by hand (PowerShell as administrator):

```powershell
powershell -ExecutionPolicy Bypass -File config\Install-SuricataConfig.ps1             # everything
powershell -ExecutionPolicy Bypass -File config\Install-SuricataConfig.ps1 -RulesOnly  # rules update only
```

## Pages

| Page | What it does |
|---|---|
| **Overview** | state of Suricata: installation, service, process, Npcap, configuration, rules, `eve.json` |
| **EDR – Events** | events from `eve.json` with filters (event type, time, severity, IP / CIDR, full text, `!` to exclude), alerts highlighted by severity, event detail, CSV export, AI analyzer, auto-refresh |
| **Settings** | paths to `suricata.yaml` and `eve.json`, limits, auto-refresh; *Set up Suricata*, *Test configuration*, *Restart Suricata service*; false positives and knowledge base; AI analyzer |

## False positives

- Right click on an alert → **Mark as false positive** – the row stays, greyed out. The application then offers to
  hide all alerts of the same signature (with an extra warning for severity 1–2 alerts).
  **Show hidden false positives** shows them again.
- Marks are stored in `marks.json` next to the exe, separately for each computer. They only change what
  suricataChecker shows – to stop Suricata from raising an alert, suppress its SID in `config\suricata\threshold.config`
  and deploy it.
- **Knowledge base** – false positives proposed by the AI analyzer are saved only after you confirm them
  (*Apply verdicts*), with a scope (same hosts, same destination or the whole signature) and a reason. Matching alerts,
  also future ones, are greyed out. Remove an assessment with a right click or on the Settings page.

## AI analyzer

The **AI analyzer** button sends the selected or shown events to **Claude** (Anthropic API) or **ChatGPT** (OpenAI API)
over HTTPS and shows the analysis: verdict and severity, findings with MITRE ATT&CK IDs, likely benign alerts,
recommended actions and tuning suggestions. Follow-up questions continue the conversation; **Save report** writes it
as Markdown.

Setup (*Settings → AI analyzer*):

1. Create an API key at [console.anthropic.com](https://console.anthropic.com) or
   [platform.openai.com](https://platform.openai.com). The API is billed per use; a ChatGPT Plus / Claude Pro
   subscription does not include API access.
2. Paste the key, **Save key**, **Test connection**, choose the model.

The key is stored in the Windows Credential Manager of the current user on this computer – never in the application
folder.

What is sent:

- Identical events are grouped and sent once with a count; long values are shortened.
- **Masking** (on by default) replaces local identities – computer, domain and user names, internal IP addresses and
  other identifiers – with pseudonyms before sending; the answer is shown with the real values. Public IPs, domains
  and signatures are sent, the analysis needs them.
- **Secrets** (passwords, tokens, API keys, private keys) are always removed, also from your questions. Packet
  payloads and HTTP bodies are never sent.
- **Preview data** shows exactly what will be sent.

The AI can be wrong – use the answer as a lead for your own investigation. Reports and CSV exports contain events of
this computer; the application warns before saving them into the application folder.

## Digital signature

The exe and `Install-SuricataConfig.ps1` are signed with a self-signed code signing certificate
(SHA-256, RSA 3072, DigiCert timestamp):

| | |
|---|---|
| Subject | `CN=SuricataChecker Code Signing` |
| SHA-1 thumbprint | `E5E4693EEFC36DDFB6C21F7C442F79244332EA50` |
| Valid until | 3 Nov 2031 |
| Public certificate | `cert\SuricataChecker.cer` |

```powershell
Get-AuthenticodeSignature .\SuricataChecker-*.exe
(Get-PfxCertificate .\cert\SuricataChecker.cer).Thumbprint   # compare with the thumbprint above
```

Without importing the certificate the status is `UnknownError` (untrusted root). To make Windows report it as
`Valid`, import it once (PowerShell as administrator) – this trusts every program signed with this certificate on
that computer:

```powershell
Import-Certificate -FilePath .\cert\SuricataChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\SuricataChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

## Building from source

Requires the .NET SDK.

| Script | Does |
|---|---|
| `src\build.cmd` | builds `SuricataChecker-<version>.exe` (version from `src\SuricataChecker.csproj`), copies it to the application folder and signs it when a code signing certificate is available |
| `src\make_dist.ps1` | builds the transfer package `dist\SuricataChecker-<version>.zip` (+ `.sha256`) without local data |

## License

MIT – see [LICENSE](LICENSE). The embedded font Nunito Sans is licensed under the SIL Open Font License 1.1
(`src\Fonts\OFL.txt`).
