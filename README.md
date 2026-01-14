# E-Signing Service

Produkční backend služba pro elektronické podepisování dokumentů ve firemním prostředí.

## Funkce

- **Upload souborů**: Generování signed URLs pro přímý upload do GCS
- **Konverze do PDF**: LibreOffice pro kancelářské formáty, Pillow pro obrázky
- **OTP 2FA**: Twilio Verify API (SMS) s WhatsApp Messaging fallbackem
- **Podpis dokumentů**: PyMuPDF overlay podpisu na specifikované souřadnice
- **Evidence report**: Generování kontrolního listu (audit trail) v PDF
- **Multi-tenant**: Všechny operace scoped na workspace_id

## Technologie

- Python 3.11 + FastAPI + Uvicorn
- Google Cloud Storage (GCS)
- Supabase (Postgres + Auth)
- Twilio (Verify API + Messaging API)
- PyMuPDF, Pillow, reportlab
- LibreOffice headless

## Struktura projektu

```
e-signing-service/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI aplikace
│   ├── config.py            # Konfigurace + Secret Manager
│   ├── auth.py              # JWT ověření + signing tokens
│   ├── gcs.py               # GCS client
│   ├── supabase_client.py   # Supabase operace
│   ├── models.py            # Pydantic modely
│   ├── exceptions.py        # Custom exceptions
│   ├── otp/
│   │   ├── __init__.py
│   │   └── twilio_verify.py # OTP služba s fallbackem
│   ├── pdf/
│   │   ├── __init__.py
│   │   ├── convert.py       # PDF konverze
│   │   ├── sign.py          # PDF podepisování
│   │   └── evidence.py      # Evidence report generátor
│   └── utils/
│       ├── __init__.py
│       ├── logging.py       # Strukturované logování
│       ├── rate_limiter.py  # Token bucket rate limiter
│       └── security.py      # Hashing, tokeny
├── tests/
│   ├── conftest.py
│   ├── test_security.py
│   ├── test_rate_limiter.py
│   ├── test_otp.py
│   └── test_pdf_signing.py
├── Dockerfile
├── requirements.txt
├── cloudbuild.yaml
├── .env.example
└── README.md
```

## API Endpoints

### Autentizované (JWT)

| Endpoint | Metoda | Popis |
|----------|--------|-------|
| `/v1/documents/{id}/upload-url` | POST | Generování signed URL pro upload |
| `/v1/documents/{id}/convert-to-pdf` | POST | Konverze souboru do PDF |
| `/v1/documents/{id}/finalize` | POST | Finalizace dokumentu + evidence |

### Signing Sessions (magic link token)

| Endpoint | Metoda | Popis |
|----------|--------|-------|
| `/v1/signing/sessions/{token}` | GET | Metadata session (dokument, podepisující, OTP status) |
| `/v1/signing/sessions/{token}/otp/send` | POST | Odeslání OTP kódu |
| `/v1/signing/sessions/{token}/otp/verify` | POST | Ověření OTP kódu |
| `/v1/signing/sessions/{token}/complete` | POST | Podpis dokumentu |
| `/v1/signing/sessions/{token}/signed` | GET | Stav podpisu + download URL |

## Lokální vývoj

### Požadavky

- Python 3.11+
- LibreOffice (pro konverzi dokumentů)
- Google Cloud SDK (pro GCS)

### Instalace

```bash
# Klonování
cd e-signing-service

# Virtuální prostředí
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Závislosti
pip install -r requirements.txt

# LibreOffice (Ubuntu/Debian)
sudo apt-get install libreoffice-core libreoffice-writer

# Konfigurace
cp .env.example .env
# Upravte .env s vašimi credentials
```

### Spuštění

```bash
# Development server
uvicorn app.main:app --reload --port 8000

# Nebo přímo
python -m app.main
```

### Testy

```bash
# Všechny testy
pytest

# S coverage
pytest --cov=app --cov-report=html

# Konkrétní test
pytest tests/test_security.py -v
```

## Nasazení do Cloud Run

### Prerekvizity

1. GCP projekt s povolenými API:
   - Cloud Run
   - Cloud Storage
   - Secret Manager
   - Container Registry

2. Service account s oprávněními:
   - `roles/storage.admin`
   - `roles/secretmanager.secretAccessor`
   - `roles/run.invoker`

### Secrets v Secret Manager

Vytvořte secrets v GCP Secret Manager:

```bash
# Příklad
echo -n "your-value" | gcloud secrets create SUPABASE_URL --data-file=-
echo -n "your-value" | gcloud secrets create GCS_BUCKET --data-file=-
echo -n "your-value" | gcloud secrets create TWILIO_ACCOUNT_SID --data-file=-
echo -n "your-value" | gcloud secrets create TWILIO_AUTH_TOKEN --data-file=-
echo -n "your-value" | gcloud secrets create TWILIO_VERIFY_SERVICE_SID --data-file=-
echo -n "your-value" | gcloud secrets create SIGNING_TOKEN_SALT --data-file=-
```

### Ruční deployment

```bash
# Build
docker build -t gcr.io/YOUR_PROJECT/e-signing-service .

# Push
docker push gcr.io/YOUR_PROJECT/e-signing-service

# Deploy
gcloud run deploy e-signing-service \
  --image gcr.io/YOUR_PROJECT/e-signing-service \
  --region europe-west1 \
  --platform managed \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 1 \
  --timeout 300 \
  --set-env-vars "GCP_PROJECT_ID=YOUR_PROJECT,ENVIRONMENT=production"
```

### CI/CD s Cloud Build

```bash
# Trigger na push do main
gcloud builds submit --config=cloudbuild.yaml
```

## Supabase schéma

### Tabulky

```sql
-- documents
CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  status TEXT DEFAULT 'draft',
  gcs_original_path TEXT,
  gcs_pdf_path TEXT,
  gcs_signed_path TEXT,
  gcs_evidence_path TEXT,
  page_count INTEGER,
  final_hash TEXT,
  created_by UUID NOT NULL REFERENCES auth.users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- document_signers
CREATE TABLE document_signers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id),
  workspace_id UUID NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  "order" INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending',
  viewed_at TIMESTAMPTZ,
  signed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- signing_sessions
CREATE TABLE signing_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id),
  signer_id UUID NOT NULL REFERENCES document_signers(id),
  workspace_id UUID NOT NULL REFERENCES workspaces(id),
  token_hash TEXT NOT NULL UNIQUE,
  otp_channel TEXT,
  otp_fallback_used BOOLEAN DEFAULT FALSE,
  otp_verified_at TIMESTAMPTZ,
  ip_address TEXT,
  user_agent TEXT,
  signature_placement JSONB,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- document_events
CREATE TABLE document_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id),
  workspace_id UUID NOT NULL REFERENCES workspaces(id),
  signer_id UUID REFERENCES document_signers(id),
  event_type TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexy
CREATE INDEX idx_documents_workspace ON documents(workspace_id);
CREATE INDEX idx_signers_document ON document_signers(document_id);
CREATE INDEX idx_sessions_token_hash ON signing_sessions(token_hash);
CREATE INDEX idx_events_document ON document_events(document_id);
```

## Bezpečnost

- **JWT ověření**: Všechny `/v1/documents/*` endpointy vyžadují Supabase JWT
- **Signing tokeny**: Ukládány pouze jako SHA-256 hash
- **OTP**: Nikdy neukládáno v plaintext (Twilio Verify nebo hashed fallback)
- **Multi-tenant**: Každá operace kontroluje workspace_id
- **Rate limiting**: OTP endpointy limitovány na 5 požadavků / 5 minut
- **Signed URLs**: Expirace 10 minut
- **Temp soubory**: Mazány ihned po použití

## Logování

Strukturované JSON logy kompatibilní s Cloud Logging:

```json
{
  "severity": "INFO",
  "message": "Document signed by John Doe",
  "request_id": "abc-123",
  "document_id": "doc-456",
  "signer_id": "sig-789",
  "workspace_id": "ws-000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Limity Cloud Run

- **Timeout**: 300s (5 minut) pro konverze velkých souborů
- **Memory**: 1GB (LibreOffice potřebuje RAM)
- **Temp storage**: Cloud Run má limit na /tmp, streamujeme kde možno
- **Concurrency**: 80 requestů na instanci

## Licence

Proprietary - interní použití
