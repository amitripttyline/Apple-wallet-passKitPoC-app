This application is a Spring Boot–based Apple Wallet pass platform that generates, signs, and delivers multiple pass types—Generic, Boarding Pass, Coupon, Event Ticket, and Store Card—using a single, unified backend. It exposes REST APIs that accept pass data, dynamically builds Apple-compliant `pass.json` based on the requested pass type, signs it with Apple Pass Type certificates, packages it into a `.pkpass` file, and serves it to iOS devices for direct addition to Apple Wallet. The same integration also supports pass updates and expiration through Apple’s web service APIs, enabling real-time changes such as balance updates, boarding gate changes, or offer expiry, all without requiring users to reinstall the pass.



# Apple PassKit – Backend Setup & Configuration

This document explains **end-to-end setup, configuration, and verification** required to generate and sign Apple Wallet (`.pkpass`) files from a backend service.

It covers:

* Required Apple certificates
* How to generate and export them
* Backend folder structure
* Converting `.p12` → `.pem`
* Common errors and fixes

---

## 1. Prerequisites

### Required

* macOS (recommended)
* Apple Developer Program membership ($99/year)
* Access to **Certificates, Identifiers & Profiles**
* Backend capable of signing passes (Java / Node / etc.)
* OpenSSL (macOS default or Homebrew)

---

## 2. What Certificates Are Required

Apple Wallet passes must be **signed by your backend**.

You need **three certificates/files**:

1. **Pass Type ID Certificate** (from Apple)
2. **Private Key** (generated with the certificate)
3. **Apple WWDR Certificate** (Apple intermediate CA)

These are used **only on the backend**.

---

## 3. Create Pass Type ID (Apple Developer Portal)

1. Open **Apple Developer Portal**
2. Go to **Certificates, Identifiers & Profiles**
3. Select **Identifiers** → **+**
4. Choose **Pass Type IDs**
5. Enter:

    * Description: `PassKitPOC`
    * Identifier: `pass.com.codecraft.PassKitPOC`
6. Register

⚠️ This identifier must match `pass.json` exactly.

---

## 4. Create Pass Type ID Certificate

### 4.1 Generate CSR (on Mac)

1. Open **Keychain Access**
2. Menu → **Certificate Assistant → Request a Certificate From a Certificate Authority**
3. Fill:

    * Email: Apple ID email
    * Common Name: `PassKit Pass Certificate`
    * CA Email: *(leave blank)*
4. Select:

    * ☑ Save to disk
    * ☑ Let me specify key pair information
5. Key size: **2048 bits**
6. Algorithm: **RSA**
7. Save as: `passkit.csr`

---

### 4.2 Upload CSR to Apple

1. In Developer Portal → **Certificates → +**
2. Select **Pass Type ID Certificate**
3. Choose your Pass Type ID
4. Upload `passkit.csr`
5. Download the generated `.cer`

---

### 4.3 Install Certificate

* Double-click the downloaded `.cer`
* It will install into **Keychain Access**
* You should see the certificate **with a private key beneath it**

---

## 5. Export Certificate as `.p12`

1. Open **Keychain Access → login → Certificates**
2. Find: `pass.com.codecraft.PassKitPOC`
3. Expand it (▶)
4. Select **certificate + private key**
5. Right-click → **Export**
6. Save as:

   ```
   Certificates.p12
   ```
7. Set a password (remember it)

This file contains:

* Pass certificate
* Private key

---

## 6. Download Apple WWDR Certificate

Apple Wallet requires Apple’s intermediate certificate.

### Download

```bash
curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
```

### Convert to PEM

```bash
openssl x509 -inform DER -in AppleWWDRCAG3.cer -out WWDR.pem
```

---

## 7. Backend Certificates Folder Structure

```
backend/certs/
├── Certificates.p12
├── pass-certificate.pem
├── pass-private-key.pem
├── WWDR.pem
├── verify-certificates.sh
└── README.md
```

⚠️ `pass.json` does NOT belong in this folder.

---

## 8. Convert `.p12` → PEM (macOS OpenSSL 3 Fix)

Apple `.p12` files use **legacy RC2 encryption**.
Modern OpenSSL requires the `-legacy` flag.

### Extract Certificate

```bash
openssl pkcs12 -legacy \
  -in Certificates.p12 \
  -clcerts \
  -nokeys \
  -out pass-certificate.pem
```

### Extract Private Key

```bash
openssl pkcs12 -legacy \
  -in Certificates.p12 \
  -nocerts \
  -nodes \
  -out pass-private-key.pem
```

---

## 9. Verify Certificate & Key

### Check issuer (must be Apple)

```bash
openssl x509 -in pass-certificate.pem -noout -issuer
```

Expected:

```
Apple Worldwide Developer Relations Certification Authority
```

### Verify key matches certificate

```bash
openssl x509 -noout -modulus -in pass-certificate.pem | openssl md5
openssl rsa  -noout -modulus -in pass-private-key.pem | openssl md5
```

Hashes must match.

---

## 10. Pass Template (Where `pass.json` Lives)

`pass.json` belongs in the **pass template folder**, not in `certs/`.

Example:

```
backend/pass-template/
├── pass.json
├── icon.png
├── icon@2x.png
├── logo.png
└── strip.png
```

### Required Fields in `pass.json`

```json
{
  "formatVersion": 1,
  "passTypeIdentifier": "pass.com.codecraft.PassKitPOC",
  "teamIdentifier": "ABCDE12345",
  "organizationName": "CodeCraft",
  "serialNumber": "123456",
  "description": "Demo Pass"
}
```

⚠️ `passTypeIdentifier` and `teamIdentifier` **must match the certificate**.

---

## 11. Backend vs iOS Responsibilities

| Task              | Backend | iOS |
| ----------------- | ------- | --- |
| Hold private key  | ✅       | ❌   |
| Sign pass         | ✅       | ❌   |
| Create pass.json  | ✅       | ❌   |
| Verify signature  | ❌       | ✅   |
| Trust Apple certs | ❌       | ✅   |

---

## 12. Common Errors & Fixes

### RC2 Unsupported Error

```
Algorithm (RC2-40-CBC) unsupported
```

✔ Fix: use `openssl pkcs12 -legacy`

---

### Invalid Data / Trust Chain Error

* Missing WWDR.pem
* Self-signed certificate
* Wrong Pass Type ID
* Team ID mismatch

---

## 13. Security Notes (IMPORTANT)

* ❌ Never commit `.p12` or private keys to Git
* ✔ Store secrets securely (env vars / vault)
* ✔ Backend only — never ship keys to iOS

---

## 14. Final Checklist

* [ ] Apple Developer account
* [ ] Pass Type ID created
* [ ] Certificates.p12 exported
* [ ] PEM files extracted
* [ ] WWDR.pem present
* [ ] pass.json identifiers match certificate
* [ ] Backend restarted

---

