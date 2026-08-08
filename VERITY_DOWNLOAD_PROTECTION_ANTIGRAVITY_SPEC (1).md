# VERITY — DOWNLOAD PROTECTION
## Production-Style Implementation Specification for Antigravity

## 1. Objective

Implement a real browser-security layer that detects and warns about potentially dangerous file downloads initiated by websites.

Verity should:

1. Detect download events.
2. Identify filename, extension and MIME type where available.
3. Identify the source/referrer URL where available.
4. Analyze the source website with the existing Verity detectors.
5. Detect risky executable/script/installer formats.
6. Detect misleading filenames and double extensions.
7. Incorporate redirect, reputation and brand-impersonation signals.
8. Send normalized features to the existing central risk engine.
9. Warn or cancel high-risk downloads only where Chrome APIs actually allow it.
10. Never claim that an extension alone proves malware.
11. Never upload private files for scanning by default.

---

## 2. Core Security Principle

A file extension alone does NOT prove malware.

For example:

```text
setup.exe
```

may be legitimate.

Likewise:

```text
invoice.pdf
```

can still be dangerous.

Therefore:

```text
File Type
+
Filename
+
Source Website
+
Download Context
+
URL Reputation
+
Redirect Chain
+
Brand/Phishing Signals
=
Download Risk
```

The existing Verity risk engine must make the final decision.

---

## 3. Why This Feature Matters

A phishing site may attempt to install malware instead of stealing credentials:

```text
Fake browser-update website
        ↓
"Your browser is outdated"
        ↓
Download update
        ↓
Chrome_Update.exe
```

Verity should recognize the combination of:

```text
Suspicious website
+
Browser impersonation
+
Executable download
+
Misleading filename
```

and produce a high-risk warning/block decision.

---

## 4. Architecture

Do NOT create an independent security ecosystem.

Use:

```text
Chrome Downloads API
        ↓
Download Monitor
        ↓
Download Metadata Analyzer
        ↓
File Type + Filename Analysis
        ↓
Source URL Analysis
        ↓
Redirect / Brand / Reputation Context
        ↓
Existing Verity Risk Engine
        ↓
ALLOW / WARN / BLOCK
```

Suggested modules if equivalent functionality does not already exist:

```text
src/
  download/
    downloadMonitor.js
    downloadAnalyzer.js
    filenameAnalyzer.js
    fileTypeAnalyzer.js
    downloadRiskFeatures.js
    downloadPolicy.js
```

Reuse existing URL, brand, reputation, redirect and risk modules.

---

## 5. Chrome Manifest V3 API

Use the Chrome Downloads API where supported.

Relevant events include:

```javascript
chrome.downloads.onCreated
chrome.downloads.onChanged
```

The extension can use download metadata such as:

- download ID
- filename
- URL
- final URL where available
- referrer where available
- MIME type where available
- file size where available
- state
- Chrome-provided danger information where available

Inspect the current `manifest.json` first.

If required, add only:

```json
"permissions": [
  "downloads"
]
```

Do not replace existing permissions.

---

## 6. Download Event Flow

```text
Download Created
      ↓
Capture Metadata
      ↓
Identify Source URL
      ↓
Identify Final URL
      ↓
Identify Filename
      ↓
Identify Extension
      ↓
Identify MIME Type
      ↓
Analyze Source Website
      ↓
Analyze File
      ↓
Generate Risk Features
      ↓
Existing Risk Engine
      ↓
ALLOW / WARN / BLOCK
```

Do not put all logic inside the Chrome event listener.

---

## 7. Normalized Download Object

Example:

```javascript
{
  downloadId: 123,

  filename: "Chrome_Update.exe",

  url: "https://fake-update.example/download",

  finalUrl: "https://cdn.fake-update.example/Chrome_Update.exe",

  referrer: "https://fake-update.example/update",

  mimeType: "application/octet-stream",

  fileSize: 1827364,

  state: "in_progress",

  extension: ".exe"
}
```

Only retain information needed for security analysis.

Do not store downloaded file contents.

---

## 8. File-Type Classification

Create one centralized file-type utility.

Suggested categories:

```text
CRITICAL_EXECUTABLE
HIGH_RISK_SCRIPT
HIGH_RISK_INSTALLER
ARCHIVE
DOCUMENT
MEDIA
IMAGE
TEXT
UNKNOWN
```

Potential executable/installer types:

```text
.exe
.com
.scr
.msi
.msp
.cpl
.dll
```

Scripts:

```text
.bat
.cmd
.ps1
.vbs
.vbe
.js
.jse
.wsf
.wsh
.hta
.sh
```

Archives:

```text
.zip
.rar
.7z
.iso
.img
.tar
.gz
```

Documents:

```text
.pdf
.doc
.docx
.xls
.xlsx
.ppt
.pptx
```

Important:

**Do not automatically classify an extension as malicious.**

An `.exe` is a strong risk signal, not automatic proof of malware.

---

## 9. Double-Extension Detection

Detect:

```text
invoice.pdf.exe
payment.pdf.scr
document.docx.js
photo.jpg.exe
```

Example:

```javascript
{
  actualExtension: ".exe",
  apparentExtension: ".pdf",
  doubleExtension: true,
  misleadingExtension: true
}
```

A double extension combined with an executable/script should substantially increase risk.

---

## 10. Unicode / Confusable Filename Analysis

Normalize filenames before analysis:

```javascript
filename.normalize("NFKC")
```

Look for suspicious Unicode/confusable characters.

This is a supporting signal only.

Do not classify a file as malicious based solely on visual similarity.

---

## 11. Misleading Filename Detection

Examples:

```text
Bank_Statement.pdf.exe
Chrome_Update.exe
Security_Update.msi
Invoice.pdf.scr
```

Combine filename analysis with source context.

Example:

```text
fake-microsoft-update.example
        +
Microsoft_Update.exe
```

is significantly more suspicious than the same filename from a verified official domain.

---

## 12. Source Website Risk

Download Protection must analyze the website that initiated the download.

Example:

```text
trusted-software.example
        ↓
official-installer.exe
```

versus:

```text
fake-bank-login.example
        ↓
security_update.exe
```

Reuse:

```text
URL Detector
Brand Detector
Reputation
Redirect Tracker
Page/Payment Context
```

Do not duplicate those systems.

---

## 13. Redirect Integration

If a download follows a redirect chain:

```text
bit.ly/abc
    ↓
tracking.example
    ↓
fake-update.example
    ↓
update.exe
```

pass redirect signals into Download Protection:

```json
{
  "shortenerDetected": true,
  "redirectCount": 2,
  "crossDomainRedirectCount": 2,
  "sourceDomainSuspicious": true,
  "executableDownload": true
}
```

A shortener alone must never mean malicious.

---

## 14. Reputation

Reuse the existing reputation service.

Possible states:

```text
SAFE
UNKNOWN
SUSPICIOUS
PHISHING
MALICIOUS
UNAVAILABLE
```

Important:

```text
UNKNOWN != MALICIOUS
```

Do not block every download from an unknown domain.

Use reputation as one risk signal.

---

## 15. Chrome Danger Information

Chrome may expose download danger information through the Downloads API.

If Chrome reports a dangerous download, treat that as a high-priority signal.

Do not pretend Verity independently discovered it.

Use the actual API value.

Example UI:

```text
Chrome identified this download as dangerous.
Verity has restricted the download where supported.
```

Do not invent danger states.

---

## 16. Download Risk Features

Create a normalized object:

```json
{
  "analysisContext": "download",

  "executableDownload": true,
  "scriptDownload": false,
  "installerDownload": false,
  "archiveDownload": false,

  "doubleExtension": true,
  "misleadingFilename": true,

  "sourceDomainSuspicious": true,
  "sourceDomainMalicious": false,

  "brandImpersonation": true,

  "shortenerDetected": true,
  "redirectCount": 2,

  "chromeDangerState": "unknown"
}
```

Pass this to the central Verity risk engine.

---

## 17. Central Risk Engine

Do NOT create a second scoring system.

Use:

```text
Download Analyzer
       ↓
Download Risk Features
       ↓
Existing Verity Risk Engine
```

The engine should combine:

```text
Website risk
+
Download risk
+
Redirect risk
+
Brand risk
+
Reputation
+
Payment/credential context
```

into one final decision.

---

## 18. Recommended Risk Signals

Central configuration can assign relative weights.

Strong signals:

```text
Known malicious source
Known phishing source
Executable/script download from a high-risk site
Double extension + executable
Brand impersonation + executable
Chrome-confirmed dangerous download
```

Supporting signals:

```text
Shortener
Unknown domain
Multiple redirects
Suspicious filename
Archive
Unusual Unicode filename
```

Do not hardcode arbitrary scores in the UI.

---

## 19. Safe Installer

Example:

```text
official-software.example
        ↓
official-installer.exe
```

Signals:

```text
executable = true
source reputation = SAFE
brand match = valid
no suspicious redirects
no misleading filename
```

Expected:

```text
ALLOW / LOW RISK
```

Never automatically block every EXE.

---

## 20. Fake Browser Update

```text
fake-browser-update.example
        ↓
Chrome_Update.exe
```

Signals:

```text
executable = true
brand impersonation = true
source suspicious = true
misleading update filename = true
```

Expected:

```text
HIGH RISK
```

---

## 21. Double Extension Example

```text
invoice.pdf.exe
```

Signals:

```text
doubleExtension = true
executable = true
apparentExtension = ".pdf"
actualExtension = ".exe"
```

If the source is also suspicious:

```text
unknown-domain.example
        ↓
invoice.pdf.exe
```

Expected:

```text
HIGH RISK / BLOCK
```

according to the central policy.

---

## 22. Archive Example

```text
unknown.example
        ↓
invoice.zip
```

Set:

```text
archiveDownload = true
```

Do NOT automatically call it malware.

Archives can contain legitimate or malicious files.

Do not extract arbitrary archives inside the extension.

---

## 23. What NOT to Implement

Do NOT:

- upload every downloaded file to a server
- scan private files remotely without explicit consent
- claim full antivirus functionality
- block every `.exe`
- block every `.zip`
- treat every unknown domain as malicious
- treat every URL shortener as malicious
- execute downloaded files
- run downloaded scripts
- sandbox arbitrary downloaded files inside the extension
- bypass Chrome security controls

Verity is a browser download-risk protection layer, not a replacement for native OS antivirus.

---

## 24. Blocking Strategy

Chrome extension capabilities have limits.

Therefore:

### Preferred

If Chrome exposes a suitable dangerous state/action:

```text
detect
→ cancel/remove using supported API
→ show Verity warning
```

### Extension-detected high risk

Use supported Chrome download controls to cancel/remove where possible.

If the installed Chrome API does not support a desired blocking operation:

```text
DO NOT FAKE BLOCKING.
```

Instead clearly warn the user and use only actions the browser actually permits.

Antigravity must test the real API behavior in the target Chrome version.

---

## 25. Warning UI

```text
⚠️ VERITY DOWNLOAD PROTECTION

Suspicious download detected.

File:
Chrome_Update.exe

Source:
fake-browser-update.example

Detected:
✓ Executable file
✓ Browser impersonation
✓ Suspicious domain
✓ Misleading filename

Risk:
91 / 100

Recommendation:
BLOCK

[ Cancel Download ]
[ Continue ]
```

Only show controls that actually work.

---

## 26. Dangerous Download UI

```text
🛑 DANGEROUS DOWNLOAD

Verity detected a high-risk download.

File:
Bank_Security_Update.exe

Source:
fake-bank-login.example

Reasons:

✓ Suspicious source
✓ Executable download
✓ Bank impersonation
✓ Misleading update filename
✓ Suspicious redirect

DO NOT OPEN THIS FILE.

[ Close ]
```

Never display sensitive file contents.

---

## 27. Security Timeline Integration

If Verity already has a security timeline, add download events:

```text
10:42:01  🔗 Short URL detected
10:42:02  ↪ Redirect #1
10:42:03  🌐 Suspicious domain
10:42:04  📥 Executable download detected
10:42:04  🏦 Brand impersonation detected
10:42:04  🔴 Risk = 94
10:42:04  🛑 Download blocked
```

This gives judges a clear explanation of the detection chain.

---

## 28. Popup Integration

Optionally display:

```text
DOWNLOAD PROTECTION

Analyzed: 12
Warnings: 2
Blocked: 1

Last event:
🛑 Bank_Security_Update.exe
```

Keep history short and privacy-conscious.

Do not store unlimited download history.

---

## 29. Performance

Use event-driven monitoring:

```text
chrome.downloads.onCreated
chrome.downloads.onChanged
```

Use:

```text
deduplication
cached reputation
small temporary sessions
cleanup timers
```

Do not poll downloads continuously.

Do not analyze the same download repeatedly.

---

## 30. Privacy

Process only what is necessary:

```text
filename
extension
download URL
source/referrer URL
MIME type
download state
security metadata
```

Do NOT store:

```text
file contents
passwords
private document contents
personal files
```

Local filename/type/context analysis should happen locally.

---

## 31. File Content Scanning

Do NOT implement full malware scanning in this feature.

Do not pretend to provide:

```text
PE malware analysis
YARA scanning
sandbox execution
behavioral malware analysis
antivirus signature scanning
```

For this MVP use:

```text
Download Metadata
+
File Type
+
Filename
+
Source Website
+
Redirect Context
+
Reputation
+
Chrome Danger State
+
Central Risk Engine
```

This is technically realistic for a browser extension.

---

## 32. Module Responsibilities

### `downloadMonitor.js`

Responsible for:

```text
Chrome download events
session creation
metadata collection
analyzer invocation
policy invocation
UI updates
cleanup
```

### `fileTypeAnalyzer.js`

Responsible for:

```text
extension extraction
MIME classification
file category
executable detection
script detection
installer detection
archive detection
```

### `filenameAnalyzer.js`

Responsible for:

```text
Unicode normalization
extension extraction
double-extension detection
misleading extension detection
suspicious naming signals
```

### `downloadAnalyzer.js`

Responsible for combining:

```text
file type
filename
source URL
brand
reputation
redirect
Chrome danger state
```

into normalized risk features.

### `downloadPolicy.js`

Responsible for translating the central risk decision into supported browser actions.

---

## 33. End-to-End Example

User visits:

```text
fake-microsoft-security.example
```

Page says:

```text
Your browser is outdated.
Download security update.
```

User clicks.

Chrome reports:

```text
download created
```

Verity receives:

```text
filename = Chrome_Security_Update.exe
source = fake-microsoft-security.example
```

Analysis:

```text
executable = true
source suspicious = true
brand impersonation = true
misleading update filename = true
```

Central engine:

```text
HIGH RISK
```

Verity displays:

```text
🛑 DANGEROUS DOWNLOAD
```

Then use only supported Chrome download controls to cancel/restrict the download.

---

## 34. Testing Matrix

### Test 1 — Normal PDF

```text
trusted.example
 ↓
document.pdf
```

Expected:

```text
ALLOW
```

### Test 2 — Legitimate EXE

```text
official-software.example
 ↓
official-installer.exe
```

Expected:

```text
ALLOW or LOW RISK
```

### Test 3 — Fake Update

```text
fake-browser-update.example
 ↓
Chrome_Update.exe
```

Expected:

```text
HIGH RISK
```

### Test 4 — Double Extension

```text
invoice.pdf.exe
```

Expected:

```text
doubleExtension = true
```

### Test 5 — Script

```text
free-tool.example
 ↓
install.ps1
```

Expected:

```text
HIGH-RISK SCRIPT SIGNAL
```

### Test 6 — Archive

```text
unknown.example
 ↓
invoice.zip
```

Expected:

```text
archive signal
```

not automatic malware classification.

### Test 7 — Malicious Source

```text
known-malicious.example
 ↓
anything.exe
```

Expected:

```text
HIGH RISK / BLOCK
```

### Test 8 — Shortened Redirect

```text
bit.ly/abc
 ↓
fake-update.example
 ↓
update.exe
```

Expected:

```text
redirect signals
+
source risk
+
executable signal
=
HIGH RISK
```

### Test 9 — Normal Browsing

No download.

Expected:

```text
No download UI.
No unnecessary processing.
```

---

## 35. Acceptance Criteria

- [ ] Download events detected through supported Chrome APIs.
- [ ] Required Manifest V3 permission added only if necessary.
- [ ] Download metadata captured.
- [ ] File extensions analyzed.
- [ ] MIME types analyzed where available.
- [ ] Executables identified.
- [ ] Scripts identified.
- [ ] Installers identified.
- [ ] Archives identified.
- [ ] Double extensions detected.
- [ ] Misleading filenames detected.
- [ ] Unicode/confusable filename signals handled.
- [ ] Source URL analyzed.
- [ ] Final URL analyzed.
- [ ] Redirect signals reused.
- [ ] Brand signals reused.
- [ ] Reputation signals reused.
- [ ] Chrome danger state respected when available.
- [ ] Central risk engine determines final decision.
- [ ] Legitimate EXEs are not automatically blocked.
- [ ] ZIP files are not automatically classified as malware.
- [ ] Unknown domains are not automatically classified as malicious.
- [ ] High-confidence threats produce a clear warning.
- [ ] Blocking/cancellation uses only supported Chrome APIs.
- [ ] No sensitive file contents are uploaded.
- [ ] No downloaded files are executed.
- [ ] Temporary sessions are cleaned up.
- [ ] Existing Verity features continue working.

---

## 36. Judge Demonstration

Use a controlled harmless test site/file.

Example:

```text
Fake Browser Update Page
        ↓
"Download Security Update"
        ↓
Chrome_Update.exe
```

Use a harmless dummy file that does not execute malicious behavior.

Verity should display:

```text
📥 DOWNLOAD DETECTED

File:
Chrome_Update.exe

Source:
fake-browser-update.example

Detected:
✓ Executable
✓ Browser impersonation
✓ Suspicious source
✓ Update-themed filename

Risk:
92 / 100

🛑 HIGH-RISK DOWNLOAD
```

Never use actual malware for a hackathon demonstration.

---

## 37. Judge Explanation

Recommended explanation:

> "Verity does not treat every executable as malware. Instead, it evaluates the download in context. We analyze the file type and filename, identify misleading extensions, inspect the source website, reuse our reputation and brand-protection signals, incorporate redirect information, and send those features into the same central risk engine used by the rest of Verity. This lets us identify dangerous downloads without pretending that a browser extension is a full antivirus."

---

# 38. Final Antigravity Implementation Instructions

Implement Download Protection into the existing Verity codebase.

Before coding:

1. Inspect the current Manifest V3 manifest.
2. Inspect the service worker/background architecture.
3. Inspect navigation monitoring.
4. Inspect the URL detector.
5. Inspect the brand detector.
6. Inspect reputation logic.
7. Inspect redirect tracking.
8. Inspect the central risk engine.
9. Inspect the warning/block overlay.
10. Inspect popup/security timeline logic.

Then implement:

```text
Chrome Downloads API
        ↓
Download Monitor
        ↓
Metadata Extraction
        ↓
File Type Analyzer
        ↓
Filename Analyzer
        ↓
Source URL Analysis
        ↓
Redirect / Reputation / Brand Context
        ↓
Central Risk Engine
        ↓
ALLOW / WARN / BLOCK
```

Strict requirements:

- Use real Chrome Manifest V3 APIs.
- Do not simulate downloads.
- Do not fake malware detection.
- Do not fake reputation.
- Do not create a duplicate risk engine.
- Do not automatically block every executable.
- Do not automatically block every archive.
- Do not automatically classify unknown domains as malicious.
- Do not upload downloaded files to a remote server.
- Do not execute or sandbox downloaded files.
- Do not claim full antivirus functionality.
- Use supported Chrome download controls for cancellation/blocking.
- If Chrome does not support a desired action, do not pretend that it does.
- Keep every decision explainable.
- Preserve all existing Verity features.

Final architecture:

```text
                    VERITY
                       │
            ┌──────────┼──────────┐
            │          │          │
        Navigation   Search    Downloads
            │          │          │
            └──────────┼──────────┘
                       ↓
                Security Signals
                       │
        ┌──────────────┼──────────────┐
        │              │              │
       URL           Brand        Reputation
       Risk          Risk            Risk
        │              │              │
        └──────────────┼──────────────┘
                       ↓
                Download Analysis
                       │
             Filename / File Type
                       │
                 Download Context
                       │
                       ↓
                CENTRAL RISK ENGINE
                       │
              ┌────────┼────────┐
              ↓        ↓        ↓
            ALLOW     WARN     BLOCK
```

The finished feature should behave like a professional browser download-security layer while remaining technically honest about what a Chrome extension can actually control.
