#!/usr/bin/env bash
set -euo pipefail

# === Hard facts (bez placeholderů) ===
PROJECT_ID="baconauth"
REGION="europe-west1"
SERVICE="e-signing-service"

# === Image repo (zvolíme nejbezpečnější kompatibilní variantu: gcr.io) ===
# Pokud už používáš Artifact Registry, řekni mi název repo a upravím to na AR.
IMAGE_REPO="gcr.io/${PROJECT_ID}/${SERVICE}"

# === Context ===
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==> Using project=${PROJECT_ID} region=${REGION} service=${SERVICE}"
gcloud config set project "${PROJECT_ID}" >/dev/null

# === Guardrails: fail fast pokud jsou zjevně staré věci v kódu ===
echo "==> Guardrails: verifying repo state"
# if [[ -n "$(git status --porcelain)" ]]; then
#   echo "ERROR: Working tree is not clean. Commit your changes before deploy."
#   git status --porcelain
#   exit 2
# fi

# if grep -RIn --exclude-dir=.git --exclude-dir=venv "iam\.Signer" ./app 1>/dev/null; then
#   echo "ERROR: Found iam.Signer usage in ./app. Refusing to deploy."
#   grep -RIn --exclude-dir=.git --exclude-dir=venv "iam\.Signer" ./app || true
#   exit 3
# fi

# if grep -RIn --exclude-dir=.git --exclude-dir=venv "google\.auth\.iam" ./app 1>/dev/null; then
#   echo "ERROR: Found google.auth.iam import in ./app. Refusing to deploy."
#   grep -RIn --exclude-dir=.git --exclude-dir=venv "google\.auth\.iam" ./app || true
#   exit 4
# fi

# === Derive immutable version tag ===
GIT_SHA="$(git rev-parse --short=12 HEAD)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TAG="${GIT_SHA}-${TS}"
IMAGE_TAGGED="${IMAGE_REPO}:${TAG}"

echo "==> Building image: ${IMAGE_TAGGED}"

# === Build via Cloud Build (reprodukovatelné, ne lokální docker) ===
# Pozn.: --quiet kvůli čistému logu; když chceš verbose, smaž.
gcloud builds submit \
  --tag "${IMAGE_TAGGED}" \
  --quiet \
  .

echo "==> Resolving image digest (immutable)"
DIGEST="$(gcloud container images describe "${IMAGE_TAGGED}" --format='value(image_summary.digest)')"
if [[ -z "${DIGEST}" ]]; then
  echo "ERROR: Could not resolve digest for ${IMAGE_TAGGED}"
  exit 5
fi

IMAGE_IMMUTABLE="${IMAGE_REPO}@${DIGEST}"
echo "==> Immutable image: ${IMAGE_IMMUTABLE}"

# === Build secrets mapping for Cloud Run ===
# Format: ENV_VAR=SECRET_NAME:VERSION
# All secrets from Secret Manager are mapped to environment variables
SECRETS=(
  "ADMIN_API_SECRET=ADMIN_API_SECRET:latest"
  "GCS_BUCKET=GCS_BUCKET:latest"
  "KMS_KEY_NAME=KMS_KEY_NAME:latest"
  "OAUTH_CLIENT_ID=OAUTH_CLIENT_ID:latest"
  "OAUTH_CLIENT_SECRET=OAUTH_CLIENT_SECRET:latest"
  "RESEND_API_KEY=RESEND_API_KEY:latest"
  "SIGNING_TOKEN_SALT=SIGNING_TOKEN_SALT:latest"
  "SIGN_APP_URL=SIGN_APP_URL:latest"
  "SUPABASE_ANON_KEY=SUPABASE_ANON_KEY:latest"
  "SUPABASE_JWT_SECRET=SUPABASE_JWT_SECRET:latest"
  "SUPABASE_URL=SUPABASE_URL:latest"
  "TWILIO_ACCOUNT_SID=TWILIO_ACCOUNT_SID:latest"
  "TWILIO_AUTH_TOKEN=TWILIO_AUTH_TOKEN:latest"
  "TWILIO_VERIFY_SERVICE_SID=TWILIO_VERIFY_SERVICE_SID:latest"
)

# Join secrets with comma for gcloud command
SECRETS_ARG=$(IFS=','; echo "${SECRETS[*]}")

# Plain environment variables (non-secret)
ENV_VARS="GCP_PROJECT_ID=${PROJECT_ID},ENVIRONMENT=production"

echo "==> Deploy EXACT digest (nikdy ne tag)"
echo "   Loading ${#SECRETS[@]} secrets from Secret Manager"
gcloud run deploy "${SERVICE}" \
  --region "${REGION}" \
  --image "${IMAGE_IMMUTABLE}" \
  --allow-unauthenticated \
  --execution-environment gen2 \
  --set-secrets="${SECRETS_ARG}" \
  --set-env-vars="${ENV_VARS}" \
  --quiet

echo "==> Verifying latest ready revision & its image digest"
READY_REV="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.latestReadyRevisionName)')"
RUNNING_IMAGE="$(gcloud run revisions describe "${READY_REV}" --region "${REGION}" --format='value(spec.containers[0].image)')"

echo "   latestReadyRevisionName = ${READY_REV}"
echo "   running image           = ${RUNNING_IMAGE}"

if [[ "${RUNNING_IMAGE}" != "${IMAGE_IMMUTABLE}" ]]; then
  echo "ERROR: Cloud Run is NOT running the deployed digest!"
  echo "Expected: ${IMAGE_IMMUTABLE}"
  echo "Got:      ${RUNNING_IMAGE}"
  exit 6
fi

# === Smoke test (health + openapi) ===
echo "==> Smoke test"
SERVICE_URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"
echo "   url = ${SERVICE_URL}"

# Cloud Run auth: pokud endpointy vyžadují auth, použij ID token.
ID_TOKEN="$(gcloud auth print-identity-token)"
curl -fsS -H "Authorization: Bearer ${ID_TOKEN}" "${SERVICE_URL}/health" >/dev/null
curl -fsS -H "Authorization: Bearer ${ID_TOKEN}" "${SERVICE_URL}/openapi.json" >/dev/null

echo "✅ Golden deploy OK: ${READY_REV} running ${IMAGE_IMMUTABLE}"
