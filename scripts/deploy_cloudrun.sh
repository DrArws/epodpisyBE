#!/bin/bash
# =============================================================================
# E-Signing Service - Cloud Run Deployment Script
# Builds Docker image and deploys to Cloud Run
# =============================================================================
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# =============================================================================
# Configuration
# =============================================================================
PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${GCP_REGION:-europe-west1}"
SERVICE_NAME="esign-api"

# Runtime Service Account - jediný zdroj pravdy
RUNTIME_SA="e-signing-runtime@baconauth.iam.gserviceaccount.com"

IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/esign-repo/e-signing-service"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# CORS origins for production
ALLOWED_ORIGINS="https://drbacon.cz,https://podpisy.lovable.app"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# =============================================================================
# Validation
# =============================================================================
if [[ -z "$PROJECT_ID" ]]; then
    log_error "No project ID set. Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

# Check if runtime service account exists
if ! gcloud iam service-accounts describe "$RUNTIME_SA" &>/dev/null; then
    log_error "Runtime service account $RUNTIME_SA not found."
    log_error "Create it with: gcloud iam service-accounts create e-signing-runtime --display-name='e-signing Cloud Run runtime'"
    exit 1
fi

log_info "=== E-Signing Service Cloud Run Deployment ==="
log_info "Project ID: $PROJECT_ID"
log_info "Region: $REGION"
log_info "Service: $SERVICE_NAME"
log_info "Runtime SA: $RUNTIME_SA"
log_info "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# =============================================================================
# Build Docker Image
# =============================================================================
log_step "Building Docker image..."

cd "$PROJECT_ROOT"

# Configure Docker for Artifact Registry
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

# Build image
docker build \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -t "${IMAGE_NAME}:$(date +%Y%m%d-%H%M%S)" \
    .

log_info "Docker image built successfully."
echo ""

# =============================================================================
# Push to Container Registry
# =============================================================================
log_step "Pushing image to Google Container Registry..."

docker push "${IMAGE_NAME}:${IMAGE_TAG}"

log_info "Image pushed successfully."
echo ""

# =============================================================================
# Deploy to Cloud Run
# =============================================================================
log_step "Deploying to Cloud Run..."

gcloud run deploy "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --image="${IMAGE_NAME}:${IMAGE_TAG}" \
    --platform=managed \
    --service-account="$RUNTIME_SA" \
    --allow-unauthenticated \
    --memory=1Gi \
    --cpu=1 \
    --timeout=300 \
    --concurrency=10 \
    --min-instances=0 \
    --max-instances=10 \
    --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},ENVIRONMENT=production,ALLOWED_ORIGINS=${ALLOWED_ORIGINS}" \
    --set-secrets="SUPABASE_URL=SUPABASE_URL:latest,SUPABASE_JWT_SECRET=SUPABASE_JWT_SECRET:latest,GCS_BUCKET=GCS_BUCKET:latest,TWILIO_ACCOUNT_SID=TWILIO_ACCOUNT_SID:latest,TWILIO_AUTH_TOKEN=TWILIO_AUTH_TOKEN:latest,TWILIO_VERIFY_SERVICE_SID=TWILIO_VERIFY_SERVICE_SID:latest,SIGNING_TOKEN_SALT=SIGNING_TOKEN_SALT:latest"

log_info "Cloud Run deployment complete."
echo ""

# =============================================================================
# Get Service URL
# =============================================================================
log_step "Retrieving service URL..."

SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --format='value(status.url)')

log_info "Service URL: $SERVICE_URL"
echo ""

# =============================================================================
# Health Check
# =============================================================================
log_step "Performing health check..."

echo "Waiting 10 seconds for service to stabilize..."
sleep 10

HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "${SERVICE_URL}/health" || echo "FAILED")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
BODY=$(echo "$HEALTH_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "200" ]]; then
    log_info "Health check PASSED"
    echo "Response: $BODY"
else
    log_error "Health check FAILED (HTTP $HTTP_CODE)"
    echo "Response: $BODY"
fi

echo ""

# =============================================================================
# Service Account Verification
# =============================================================================
log_step "Verifying service account assignment..."

DEPLOYED_SA=$(gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --format="value(spec.template.spec.serviceAccountName)")

if [[ "$DEPLOYED_SA" != "$RUNTIME_SA" ]]; then
    log_error "Service account mismatch!"
    log_error "Expected: $RUNTIME_SA"
    log_error "Actual:   $DEPLOYED_SA"
    exit 1
fi

log_info "Service account verified: $DEPLOYED_SA"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=========================================="
echo -e "${GREEN}=== DEPLOYMENT COMPLETE ===${NC}"
echo "=========================================="
echo ""
echo "=== FRONTEND INTEGRATION DATA ==="
echo ""
echo "Cloud Run service name: $SERVICE_NAME"
echo "Region: $REGION"
echo "BASE URL: $SERVICE_URL"
echo ""
echo "Health check:"
echo "  GET ${SERVICE_URL}/health"
echo "  Expected response: {\"status\": \"healthy\", \"version\": \"1.0.0\"}"
echo ""
echo "Set in frontend environment:"
echo "  VITE_SIGNING_API_BASE_URL=${SERVICE_URL}"
echo ""
echo "Allowed CORS origins:"
echo "  - https://drbacon.cz"
echo "  - https://podpisy.lovable.app"
echo ""
echo "Public endpoints (no JWT required):"
echo "  GET  ${SERVICE_URL}/v1/signing/sessions/{token}"
echo "  POST ${SERVICE_URL}/v1/signing/sessions/{token}/otp/send"
echo "  POST ${SERVICE_URL}/v1/signing/sessions/{token}/otp/verify"
echo "  POST ${SERVICE_URL}/v1/signing/sessions/{token}/complete"
echo "  GET  ${SERVICE_URL}/v1/signing/sessions/{token}/signed"
echo ""
echo "Internal endpoints (Authorization: Bearer <Supabase JWT>):"
echo "  POST ${SERVICE_URL}/v1/documents/{id}/upload-url"
echo "  POST ${SERVICE_URL}/v1/documents/{id}/convert-to-pdf"
echo "  POST ${SERVICE_URL}/v1/documents/{id}/finalize"
echo ""
echo "=========================================="
