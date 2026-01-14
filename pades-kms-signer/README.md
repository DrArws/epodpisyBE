# PAdES KMS Signer

PAdES PDF signing using **Google Cloud KMS** and **EU DSS (Digital Signature Services)**.

## Features

- **PAdES-BASELINE-T** signatures (with RFC3161 timestamp)
- Private key stored securely in **Google Cloud KMS** (never leaves KMS)
- SHA-256 digest algorithm
- RSA 4096-bit signatures
- Audit trail generation (`audit.json`)
- Self-signed certificate generated from KMS public key

## Requirements

- Java 17+
- Maven 3.6+
- Google Cloud SDK (`gcloud`)
- Access to GCP project `baconauth` with KMS permissions

## KMS Key

The signer uses the following KMS key:

```
projects/baconauth/locations/europe-west1/keyRings/E-podpisy/cryptoKeys/pdf-key/cryptoKeyVersions/1
```

Algorithm: `RSA_SIGN_PKCS1_4096_SHA256`

## Setup

### 1. Configure Google Cloud

```bash
# Set project
gcloud config set project baconauth

# Authenticate (if not in Cloud Shell)
gcloud auth application-default login

# Verify KMS access
gcloud kms keys versions describe 1 \
  --key=pdf-key \
  --keyring=E-podpisy \
  --location=europe-west1
```

### 2. Build

```bash
cd pades-kms-signer
mvn -q -DskipTests package
```

## Usage

```bash
java -jar target/pades-kms-signer.jar <input.pdf> <output.pdf> [signer-name]
```

### Examples

```bash
# Basic signing
java -jar target/pades-kms-signer.jar document.pdf signed-document.pdf

# With custom signer name
java -jar target/pades-kms-signer.jar contract.pdf contract-signed.pdf "Jan Novak"
```

## Output

### signed.pdf

The signed PDF file with:
- PAdES-BASELINE-T signature
- Embedded timestamp from TSA
- Signature reason: "Elektronicky podepsano systemem DrBacon"
- Signature location: "Czech Republic"

### audit.json

Audit trail with:

```json
{
  "session_id": "uuid",
  "document_sha256_before": "...",
  "document_sha256_after": "...",
  "kms_key_version": "projects/baconauth/...",
  "signing_time_utc": "2024-01-15T10:30:00Z",
  "tsa_url": "http://timestamp.digicert.com",
  "tsa_token_time": "2024-01-15T10:30:01Z",
  "signer_display_name": "Jan Novak",
  "signature_profile": "PAdES-BASELINE-T",
  "success": true,
  "errors": []
}
```

## Verification in Adobe Acrobat

1. Open the signed PDF in Adobe Acrobat
2. Click on the signature panel (left side)
3. You should see:
   - "Signature is valid"
   - "Document has not been modified since this signature was applied"
   - Timestamp information (if TSA was successful)

**Note:** The signature uses a self-signed certificate, so Adobe may show:
- "Signature validity is UNKNOWN" (certificate not trusted)

To trust the signature, you can add the signer's certificate to Adobe's trusted certificates list.

## TSA (Timestamp Authority)

Default TSA: `http://timestamp.digicert.com` (free, reliable)

Alternative TSAs:
- `http://timestamp.sectigo.com`
- `http://timestamp.comodoca.com`
- `http://tsa.safecreative.org`

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Input     │────▶│   PAdES     │────▶│   Output    │
│    PDF      │     │   Service   │     │    PDF      │
└─────────────┘     └──────┬──────┘     └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │  KMS Token  │
                   │  (Adapter)  │
                   └──────┬──────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    ┌───────────┐   ┌───────────┐   ┌───────────┐
    │  Google   │   │   TSA     │   │  Audit    │
    │Cloud KMS  │   │ (RFC3161) │   │   JSON    │
    └───────────┘   └───────────┘   └───────────┘
```

## Troubleshooting

### KMS Permission Denied

```
com.google.api.gax.rpc.PermissionDeniedException
```

Ensure you have the `roles/cloudkms.signerVerifier` role:

```bash
gcloud projects add-iam-policy-binding baconauth \
  --member="user:your-email@example.com" \
  --role="roles/cloudkms.signerVerifier"
```

### TSA Connection Failed

If the TSA is unreachable, the signature will still be created as PAdES-BASELINE-B (without timestamp).
The error will be recorded in `audit.json`.

### Java Version

Requires Java 17+. Check with:

```bash
java -version
```

## License

Internal use only - DrBacon E-Signing Service
