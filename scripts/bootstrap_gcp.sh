#!/bin/bash
# =============================================================================
# E-Signing Service - GCP Bootstrap Script
# Creates all required GCP resources for the e-signing service
# =============================================================================
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Configuration
# =============================================================================
PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${GCP_REGION:-europe-west1}"

# Runtime Service Account - jediný zdroj pravdy
RUNTIME_SA="e-signing-runtime@baconauth.iam.gserviceaccount.com"
RUNTIME_SA_NAME="e-signing-runtime"

BUCKET_NAME="${PROJECT_ID}-esign-docs"

# Secrets to create (empty - values must be filled manually)
SECRETS=(
    "SUPABASE_URL"
    "SUPABASE_JWT_SECRET"
    "GCS_BUCKET"
    "TWILIO_ACCOUNT_SID"
    "TWILIO_AUTH_TOKEN"
    "TWILIO_VERIFY_SERVICE_SID"
    "SIGNING_TOKEN_SALT"
)

# =============================================================================
# Validation
# =============================================================================
if [[ -z "$PROJECT_ID" ]]; then
    log_error "No project ID set. Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

log_info "=== E-Signing Service GCP Bootstrap ==="
log_info "Project ID: $PROJECT_ID"
log_info "Region: $REGION"
log_info "Runtime SA: $RUNTIME_SA"
log_info "Bucket: $BUCKET_NAME"
echo ""

# =============================================================================
# Enable Required APIs
# =============================================================================
log_info "Enabling required GCP APIs..."

APIS=(
    "run.googleapis.com"
    "cloudbuild.googleapis.com"
    "secretmanager.googleapis.com"
    "storage.googleapis.com"
    "containerregistry.googleapis.com"
    "artifactregistry.googleapis.com"
)

for api in "${APIS[@]}"; do
    log_info "  Enabling $api..."
    gcloud services enable "$api" --project="$PROJECT_ID" --quiet || true
done

log_info "APIs enabled successfully."
echo ""

# =============================================================================
# Create Artifact Registry Repository
# =============================================================================
log_info "Creating Artifact Registry repository..."
REPO_NAME="esign-repo"
if gcloud artifacts repositories describe "$REPO_NAME" --project="$PROJECT_ID" --location="$REGION" &>/dev/null; then
    log_warn "Artifact Registry repository '$REPO_NAME' already exists, skipping creation."
else
    gcloud artifacts repositories create "$REPO_NAME" \
        --project="$PROJECT_ID" \
        --repository-format=docker \
        --location="$REGION" \
        --description="E-Signing Service container images"
    log_info "Artifact Registry repository created."
fi

echo ""

# =============================================================================
# Verify Runtime Service Account
# =============================================================================
log_info "Checking runtime service account: $RUNTIME_SA..."

if gcloud iam service-accounts describe "$RUNTIME_SA" &>/dev/null; then
    log_info "Runtime service account exists."
else
    log_warn "Runtime service account not found. Creating..."
    gcloud iam service-accounts create "$RUNTIME_SA_NAME" \
        --project="baconauth" \
        --display-name="e-signing Cloud Run runtime" \
        --description="Runtime service account for e-signing Cloud Run service"
    log_info "Service account created."
fi

# Grant Secret Manager access
log_info "Granting secretmanager.secretAccessor role..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$RUNTIME_SA" \
    --role="roles/secretmanager.secretAccessor" \
    --condition=None \
    --quiet

echo ""

# =============================================================================
# Create Cloud Storage Bucket
# =============================================================================
log_info "Creating GCS bucket: $BUCKET_NAME..."

if gsutil ls -b "gs://$BUCKET_NAME" &>/dev/null; then
    log_warn "Bucket already exists, skipping creation."
else
    gsutil mb -p "$PROJECT_ID" -l "$REGION" -b on "gs://$BUCKET_NAME"
    log_info "Bucket created with uniform bucket-level access."
fi

# Grant Storage Admin to runtime service account (bucket-level)
log_info "Granting storage.objectAdmin role on bucket..."
gsutil iam ch "serviceAccount:${RUNTIME_SA}:roles/storage.objectAdmin" "gs://$BUCKET_NAME"

# Create folder structure (by creating placeholder objects)
log_info "Creating bucket folder structure..."
for prefix in uploads pdf signed evidence; do
    echo "" | gsutil cp - "gs://$BUCKET_NAME/${prefix}/.keep" 2>/dev/null || true
done
log_info "Folder structure created: uploads/, pdf/, signed/, evidence/"

echo ""

# =============================================================================
# Create Secrets in Secret Manager
# =============================================================================
log_info "Creating secrets in Secret Manager..."

for secret in "${SECRETS[@]}"; do
    if gcloud secrets describe "$secret" --project="$PROJECT_ID" &>/dev/null; then
        log_warn "  Secret $secret already exists, skipping."
    else
        # Create secret with empty initial value
        echo -n "PLACEHOLDER_VALUE" | gcloud secrets create "$secret" \
            --project="$PROJECT_ID" \
            --replication-policy="automatic" \
            --data-file=-
        log_info "  Created secret: $secret"
    fi
done

# Create GCS_BUCKET secret with actual bucket name
log_info "Setting GCS_BUCKET secret value to: $BUCKET_NAME"
echo -n "$BUCKET_NAME" | gcloud secrets versions add "GCS_BUCKET" \
    --project="$PROJECT_ID" \
    --data-file=-

echo ""

# =============================================================================
# Summary
# =============================================================================
log_info "=== Bootstrap Complete ==="
echo ""
log_info "Configured resources:"
echo "  - Runtime SA: $RUNTIME_SA"
echo "  - GCS Bucket: gs://$BUCKET_NAME"
echo "  - Secrets: ${SECRETS[*]}"
echo ""
log_warn "=== MANUAL STEPS REQUIRED ==="
echo ""
echo "Fill in the following secrets in Secret Manager:"
echo "  https://console.cloud.google.com/security/secret-manager?project=$PROJECT_ID"
echo ""
echo "  SUPABASE_URL          - Your Supabase project URL (https://xxx.supabase.co)"
echo "  SUPABASE_JWT_SECRET   - Supabase JWT secret (from Project Settings > API)"
echo "  TWILIO_ACCOUNT_SID    - Twilio Account SID"
echo "  TWILIO_AUTH_TOKEN     - Twilio Auth Token"
echo "  TWILIO_VERIFY_SERVICE_SID - Twilio Verify Service SID (create in Twilio Console)"
echo "  SIGNING_TOKEN_SALT    - Random string for signing token generation (min 32 chars)"
echo ""
echo "GCS_BUCKET is already set to: $BUCKET_NAME"
echo ""
log_info "Next step: Run ./scripts/deploy_cloudrun.sh to deploy the service"
