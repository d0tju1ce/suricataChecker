# Setting up Suricata on a new PC

This guide describes how to install **Suricata** (network intrusion detection – IDS) on Windows, how to deploy
the configuration and the rules, and how to check it with **suricataChecker**.

| | |
|---|---|
| **Target system** | Windows 10 / 11 or Windows Server 2016+ (64-bit) |
| **Tested versions** | Suricata 8.0.7, Npcap 1.85, ET Open rules for Suricata 8 |
| **Required rights** | local administrator (installation); a standard user can run the application afterwards |
| **Internet connection** | yes (installers and rules) |
| **Estimated time** | 20 minutes |

Overview of the rule sets, configuration changes and their source: [Suricata-Detection-Rules.md](Suricata-Detection-Rules.md)

---

## 1. Preparation

1. Copy the **`suricataChecker`** folder to the PC (e.g. to `C:\Tools\suricataChecker`):

   ```
   suricataChecker\
   ├─ SuricataChecker-<version>.exe       application for checking Suricata and browsing its events
   ├─ config\
   │  ├─ Install-SuricataConfig.ps1         deployment script
   │  ├─ suricata\suricata.yaml             Suricata configuration
   │  └─ suricata\threshold.config          suppression of false alerts
   └─ docs\                                 documentation
   ```

2. If the folder was transferred over the internet, unblock the files (PowerShell **as administrator**):

   ```powershell
   Get-ChildItem "C:\Tools\suricataChecker" -Recurse | Unblock-File
   ```

3. Prerequisites: .NET Framework 4.8 (for the application) and `tar.exe` (Windows 10 1803+ / Server 2019+, for the script).

---

## Recommended – everything in the application (sections 2–4 in one window)

Start **`SuricataChecker-<version>.exe`**. At start it checks Npcap (WinPcap API-compatible Mode), Suricata, the
deployed configuration, the ET Open rules and the Suricata service. If anything is missing the **Suricata setup**
window opens: it shows the state of each part, **Install and set up** (administrator – a standard user is asked for
UAC) downloads and verifies the official installers, deploys the configuration and the rules, registers and starts
the service – progress in the window. When all checks pass the application opens. Later: *Settings → Set up Suricata*.

The manual procedure follows.

## 2. Installing Npcap

Suricata on Windows captures traffic with the **Npcap** driver.

1. Download the installer from <https://npcap.com/#download>.
2. In the installer tick ☑ **Install Npcap in WinPcap API-compatible Mode** (required – Suricata looks for `wpcap.dll` in `System32`).
3. Check:

   ```powershell
   Test-Path C:\Windows\System32\wpcap.dll      # True
   ```

> ⚠ **Licence:** the free Npcap is for personal use on up to 5 systems; a company deployment needs
> an *Npcap OEM* licence (<https://npcap.com/oem/>).

## 3. Installing Suricata

1. Download the latest `Suricata-<version>-1-64bit.msi` from <https://www.openinfosecfoundation.org/download/windows/>
   (the Windows MSI is released a little later than the source release). The configuration is for the **8.0.x** series.
2. Verify the signature (publisher *Open Information Security Foundation Inc.*, `Status` = **Valid**):

   ```powershell
   Get-AuthenticodeSignature "$env:USERPROFILE\Downloads\Suricata-8.0.7-1-64bit.msi" | Format-List Status, SignerCertificate
   ```

3. Install:

   ```powershell
   msiexec /i "$env:USERPROFILE\Downloads\Suricata-8.0.7-1-64bit.msi" /qn /norestart
   & "C:\Program Files\Suricata\suricata.exe" -V      # This is Suricata version 8.0.7 RELEASE
   ```

## 4. Deploying the configuration, the rules and the service

> The Suricata installer (MSI) installs only the program – **it does not create the Windows service**. Without this
> step there is no Suricata service ("The Suricata service is not registered").
> Easiest: the setup window of suricataChecker (*Settings → **Set up Suricata***, also opened at start) runs this
> script. Manually:

```powershell
cd "C:\Tools\suricataChecker\config"
powershell -ExecutionPolicy Bypass -File .\Install-SuricataConfig.ps1
```

The script:

1. backs up the original `suricata.yaml` as `suricata.yaml.original`,
2. copies `suricata.yaml` and `threshold.config` to `C:\Program Files\Suricata`,
3. downloads the **ET Open** rules and extracts them to `C:\Program Files\Suricata\rules`,
4. comments out rules with `file.magic` (not supported by the Windows build),
5. validates the configuration (`suricata -T`),
6. registers the **Suricata** service (automatic start) on the active network interface and starts it.

Expected end of the output: `Service state: Running`.

| Parameter | Use |
|---|---|
| `-Interface "\Device\NPF_{GUID}"` / `-Interface 10.0.0.15` | choose the interface manually (several network cards, VPN) |
| `-SuricataDir "D:\Suricata"` | a different installation folder |
| `-RulesOnly` | only update the rules and restart the service |

---

## 5. Checking with suricataChecker

1. Start **`SuricataChecker-<version>.exe`**. It runs as the current user – `eve.json` is readable by every user.
   Actions on Suricata (configuration test, service restart) need administrator rights
   (**Settings → Restart as administrator**).
2. The **Overview** page must show ✔ **Suricata is installed and running**.
3. **Settings → Application** – the paths `C:\Program Files\Suricata\suricata.yaml` and `...\log\eve.json` are
   filled in automatically (or use **Auto-detect Suricata paths**).
4. **Settings → Suricata on this computer → Test configuration** runs `suricata -T` – expected result *configuration OK*.
5. **EDR – Events** page → *Type* = **All** → **Load** – `dns`, `http`, `tls`, `flow`… events are displayed.

## 6. Verifying detection (test)

```powershell
Invoke-WebRequest -UseBasicParsing http://example.com | Out-Null
```

Within 30 seconds **EDR – Events** (Type = `alert`) shows **ET INFO Windows Powershell User-Agent Usage**
(SID 2033355) or *ET INFO Observed WindowsPowerShell/5.1 User Agent Usage* (SID 2071744).

---

## 7. Maintenance

| Task | Procedure |
|---|---|
| Rules update (once a week) | `Install-SuricataConfig.ps1 -RulesOnly` |
| Hide a false alert in suricataChecker only | right click on the alert → **Mark as false positive** → confirm hiding the alerts of the same signature (marks.json, per computer; Suricata still logs them) |
| Suppress a false alert in Suricata | write the SID from the application to `threshold.config` (`suppress gen_id 1, sig_id <SID>`) → run the script |
| Restart Suricata after a change | **Settings → Restart Suricata service** (as administrator) or `Restart-Service Suricata` |
| Archive `eve.json` (not rotated) | `Stop-Service Suricata`, rename `log\eve.json`, `Start-Service Suricata` |

Automatic weekly rules update:

```powershell
$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Tools\suricataChecker\config\Install-SuricataConfig.ps1" -RulesOnly'
$t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
Register-ScheduledTask -TaskName "suricataChecker - rules update" -Action $a -Trigger $t -User SYSTEM -RunLevel Highest
```

## 8. Troubleshooting

| Symptom | Solution |
|---|---|
| The script cannot be run (*not digitally signed*) | `Unblock-File` and `-ExecutionPolicy Bypass` |
| *The configuration test failed* | the red `E:` lines show the file and the SID; comment the rule out with `#` |
| `unknown rule keyword 'file.magic'` | run the script again (it comments these rules out) |
| *wpcap.dll was not found* (suricata.exe – System Error) | Npcap is missing or installed without the WinPcap mode – install Npcap again with ☑ **Install Npcap in WinPcap API-compatible Mode** (section 2), check `Test-Path C:\Windows\System32\wpcap.dll` |
| The service starts and stops right away | `Get-Content "C:\Program Files\Suricata\log\suricata.log" -Tail 30`; check Npcap; run the script with `-Interface` |
| Thousands of *invalid checksum* / *total length smaller than header size* alerts | use the configuration from this package (validation disabled, SIDs suppressed) |
| `eve.json` does not grow | Suricata listens on an inactive interface → run the script with `-Interface` |
| Times in `eve.json` have a `+0200` offset in winter time | a bug of the Windows build of Suricata; suricataChecker shows the correct local time |

## 9. Uninstalling

```powershell
Stop-Service Suricata
& "C:\Program Files\Suricata\suricata.exe" --service-remove
Get-Package "Suricata*" | Uninstall-Package
Unregister-ScheduledTask -TaskName "suricataChecker - rules update" -Confirm:$false   # if it exists
```
