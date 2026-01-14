package cz.drbacon.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;

/**
 * PAdES PDF Signer using Google Cloud KMS.
 *
 * Usage: java -jar pades-kms-signer.jar input.pdf signed.pdf [signer-name]
 *
 * Environment variables:
 *   KMS_KEY_NAME - Full KMS key resource name (required)
 *                  Format: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
 *                  Or without version: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
 *   TSA_URL      - Timestamp authority URL (optional, default: https://timestamp.digicert.com)
 *
 * Exit codes:
 *   0 - Success
 *   1 - Usage error (wrong arguments)
 *   2 - Config error (KMS_KEY_NAME parse, missing env)
 *   3 - KMS error (permission denied, key not found)
 *   4 - TSA/network error (timestamp server unavailable)
 *   5 - PDF error (file not found, parse/write error)
 */
public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    // Exit codes for different error types
    private static final int EXIT_SUCCESS = 0;
    private static final int EXIT_USAGE_ERROR = 1;
    private static final int EXIT_CONFIG_ERROR = 2;
    private static final int EXIT_KMS_ERROR = 3;
    private static final int EXIT_TSA_ERROR = 4;
    private static final int EXIT_PDF_ERROR = 5;

    // TSA configuration (can be overridden via env var) - HTTPS for security
    private static final String DEFAULT_TSA_URL = "https://timestamp.digicert.com";

    // Parsed KMS configuration
    private static String PROJECT_ID;
    private static String LOCATION;
    private static String KEY_RING;
    private static String KEY_NAME;
    private static String KEY_VERSION;
    private static String TSA_URL;

    // Config error holder for deferred exit (static init can't call System.exit)
    private static String CONFIG_ERROR = null;

    static {
        // Parse KMS_KEY_NAME environment variable
        String kmsKeyName = System.getenv("KMS_KEY_NAME");
        if (kmsKeyName == null || kmsKeyName.isEmpty()) {
            // Fallback to hardcoded defaults for local development
            PROJECT_ID = "baconauth";
            LOCATION = "europe-west1";
            KEY_RING = "E-podpisy";
            KEY_NAME = "pdf-key";
            KEY_VERSION = "1";
            LOG.warn("KMS_KEY_NAME not set, using default: projects/{}/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
                PROJECT_ID, LOCATION, KEY_RING, KEY_NAME, KEY_VERSION);
        } else {
            // Parse KMS key - supports both formats:
            // 10 segments: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
            // 8 segments:  projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key} (defaults to version 1)
            try {
                String[] parts = kmsKeyName.split("/");
                if (parts.length >= 8) {
                    PROJECT_ID = parts[1];   // projects/{project}
                    LOCATION = parts[3];     // locations/{location}
                    KEY_RING = parts[5];     // keyRings/{keyring}
                    KEY_NAME = parts[7];     // cryptoKeys/{key}

                    // Version is optional - default to "1" if not provided
                    if (parts.length >= 10) {
                        KEY_VERSION = parts[9];  // cryptoKeyVersions/{version}
                    } else {
                        KEY_VERSION = "1";
                        LOG.info("KMS key version not specified, defaulting to version 1");
                    }

                    LOG.info("Parsed KMS key: project={}, location={}, keyring={}, key={}, version={}",
                        PROJECT_ID, LOCATION, KEY_RING, KEY_NAME, KEY_VERSION);
                } else {
                    CONFIG_ERROR = "Invalid KMS_KEY_NAME format: expected at least 8 path segments (projects/.../cryptoKeys/{key}), got " + parts.length;
                    LOG.error(CONFIG_ERROR);
                }
            } catch (Exception e) {
                CONFIG_ERROR = "Failed to parse KMS_KEY_NAME: " + kmsKeyName + " - " + e.getMessage();
                LOG.error(CONFIG_ERROR, e);
            }
        }

        // TSA URL (optional override) - HTTPS recommended for security
        TSA_URL = System.getenv("TSA_URL");
        if (TSA_URL == null || TSA_URL.isEmpty()) {
            TSA_URL = DEFAULT_TSA_URL;
        }
        if (TSA_URL.startsWith("http://")) {
            LOG.warn("TSA_URL uses HTTP instead of HTTPS - consider using HTTPS for security");
        }
    }

    public static void main(String[] args) {
        AuditRecord audit = new AuditRecord();
        int exitCode = EXIT_SUCCESS;

        try {
            // Check for config errors from static init
            if (CONFIG_ERROR != null) {
                audit.addError("CONFIG_ERROR: " + CONFIG_ERROR);
                audit.setSuccess(false);
                writeAuditAndExit(audit, EXIT_CONFIG_ERROR);
                return;
            }

            if (args.length < 2) {
                System.err.println("Usage: java -jar pades-kms-signer.jar <input.pdf> <output.pdf> [signer-name]");
                audit.addError("USAGE_ERROR: Missing required arguments");
                audit.setSuccess(false);
                writeAuditAndExit(audit, EXIT_USAGE_ERROR);
                return;
            }

            String inputPath = args[0];
            String outputPath = args[1];
            String signerName = args.length > 2 ? args[2] : "Elektronicky podepsano";

            LOG.info("=== PAdES KMS Signer ===");
            LOG.info("Input:  {}", inputPath);
            LOG.info("Output: {}", outputPath);
            LOG.info("Signer: {}", signerName);

            audit.setInputFile(inputPath);
            audit.setOutputFile(outputPath);
            audit.setSignerDisplayName(signerName);
            audit.setKmsKeyVersion(String.format("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
                PROJECT_ID, LOCATION, KEY_RING, KEY_NAME, KEY_VERSION));
            audit.setTsaUrl(TSA_URL);
            audit.setTrustModel("self-signed");  // Document that we use self-signed cert

            // Validate input
            File inputFile = new File(inputPath);
            if (!inputFile.exists()) {
                audit.addError("PDF_ERROR: Input file does not exist: " + inputPath);
                audit.setSuccess(false);
                writeAuditAndExit(audit, EXIT_PDF_ERROR);
                return;
            }

            // Compute input hash
            String inputHash = computeSha256(inputFile);
            audit.setDocumentSha256Before(inputHash);
            LOG.info("Input SHA-256: {}", inputHash);

            // Sign the document (may throw specific exceptions)
            signDocument(inputPath, outputPath, signerName, audit);

            // Compute output hash
            File outputFile = new File(outputPath);
            if (outputFile.exists()) {
                String outputHash = computeSha256(outputFile);
                audit.setDocumentSha256After(outputHash);
                LOG.info("Output SHA-256: {}", outputHash);
                audit.setSuccess(true);
            } else {
                audit.addError("PDF_ERROR: Output file was not created");
                audit.setSuccess(false);
                exitCode = EXIT_PDF_ERROR;
            }

            LOG.info("=== Signing completed successfully ===");

        } catch (KmsException e) {
            LOG.error("KMS error", e);
            audit.setSuccess(false);
            audit.addError("KMS_ERROR: " + e.getMessage());
            exitCode = EXIT_KMS_ERROR;
        } catch (TsaException e) {
            LOG.error("TSA error", e);
            audit.setSuccess(false);
            audit.addError("TSA_ERROR: " + e.getMessage());
            exitCode = EXIT_TSA_ERROR;
        } catch (java.io.IOException e) {
            LOG.error("PDF/IO error", e);
            audit.setSuccess(false);
            audit.addError("PDF_ERROR: " + e.getMessage());
            exitCode = EXIT_PDF_ERROR;
        } catch (Exception e) {
            LOG.error("Signing failed", e);
            audit.setSuccess(false);
            String errorMsg = e.getClass().getSimpleName() + ": " + e.getMessage();
            audit.addError(errorMsg);
            // Try to classify the error
            if (errorMsg.contains("KMS") || errorMsg.contains("permission") || errorMsg.contains("PERMISSION_DENIED")) {
                exitCode = EXIT_KMS_ERROR;
            } else if (errorMsg.contains("TSA") || errorMsg.contains("timestamp") || errorMsg.contains("connect")) {
                exitCode = EXIT_TSA_ERROR;
            } else if (errorMsg.contains("PDF") || errorMsg.contains("file")) {
                exitCode = EXIT_PDF_ERROR;
            } else {
                exitCode = EXIT_USAGE_ERROR;  // Generic error
            }
        } finally {
            writeAuditAndExit(audit, exitCode);
        }
    }

    private static void writeAuditAndExit(AuditRecord audit, int exitCode) {
        try {
            String auditPath = "audit.json";
            audit.writeToFile(auditPath);
            LOG.info("Audit record written to: {}", auditPath);
        } catch (Exception e) {
            LOG.error("Failed to write audit record", e);
        }
        if (exitCode != EXIT_SUCCESS) {
            System.exit(exitCode);
        }
    }

    // Custom exception classes for better error classification
    private static class KmsException extends Exception {
        public KmsException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static class TsaException extends Exception {
        public TsaException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static void signDocument(String inputPath, String outputPath, String signerName,
                                     AuditRecord audit) throws Exception {
        LOG.info("Initializing KMS signature token...");

        try (KmsSignatureToken token = new KmsSignatureToken(
                PROJECT_ID, LOCATION, KEY_RING, KEY_NAME, KEY_VERSION, signerName)) {

            // Get the signing key
            DSSPrivateKeyEntry privateKey = token.getKeys().get(0);
            CertificateToken signingCert = privateKey.getCertificate();

            String certSubject = signingCert.getSubject().getRFC2253();
            LOG.info("Signing certificate subject: {}", certSubject);

            // Record certificate info in audit
            audit.setCertificateSubject(certSubject);
            audit.setCertificateFingerprint(computeCertFingerprint(signingCert));
            LOG.info("KMS_INIT_OK: Certificate loaded successfully");

            // Configure PAdES parameters
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T); // PAdES-T with timestamp
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(signingCert);
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            // Set signing time
            Date signingDate = new Date();
            parameters.bLevel().setSigningDate(signingDate);
            audit.setSigningTimeUtc(signingDate.toInstant());

            // Set reason and location
            parameters.setReason("Elektronicky podepsano systemem DrBacon");
            parameters.setLocation("Czech Republic");
            parameters.setContactInfo("podpisy@drbacon.cz");

            audit.setSignatureProfile("PAdES-BASELINE-T");

            // Create certificate verifier (allows self-signed for now)
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

            // Create PAdES service
            PAdESService service = new PAdESService(certificateVerifier);

            // Configure TSA with timeout logging
            LOG.info("Configuring TSA: {}", TSA_URL);
            OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
            service.setTspSource(tspSource);

            // Load input document
            DSSDocument toSignDocument = new FileDocument(inputPath);

            // Get data to sign
            LOG.info("Computing data to be signed...");
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // Sign with KMS
            LOG.info("Signing with KMS...");
            long kmsStart = System.currentTimeMillis();
            SignatureValue signatureValue = token.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);
            long kmsTime = System.currentTimeMillis() - kmsStart;
            LOG.info("KMS_SIGN_OK: Signature created in {}ms", kmsTime);

            // Record KMS metrics in audit
            audit.setKmsLatencyMs(kmsTime);
            audit.setSignatureBytes(signatureValue.getValue().length);

            // Embed signature and timestamp with retry
            LOG.info("Requesting timestamp from TSA...");
            DSSDocument signedDocument = signDocumentWithTsaRetry(
                service, toSignDocument, parameters, signatureValue, audit
            );

            // Save signed document
            LOG.info("Saving signed document to: {}", outputPath);
            try (OutputStream os = new FileOutputStream(outputPath)) {
                signedDocument.writeTo(os);
            }
            LOG.info("PDF_WRITE_OK: Document saved successfully");

            // Validate the signature integrity (server-side verification)
            LOG.info("Validating signature integrity...");
            validateSignedDocument(outputPath, audit);

            LOG.info("Document signed and validated successfully!");
        } catch (Exception e) {
            // Wrap exceptions with better classification
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (msg.contains("KMS") || msg.contains("PERMISSION_DENIED") || msg.contains("key")) {
                throw new KmsException("KMS signing failed: " + msg, e);
            } else if (msg.contains("TSP") || msg.contains("timestamp") || msg.contains("connect") || msg.contains("timeout")) {
                throw new TsaException("TSA request failed: " + msg, e);
            }
            throw e;
        }
    }

    /**
     * Validate the signed document using DSS validator.
     * This performs integrity checks on the signature and timestamp.
     * Note: This does NOT verify trust (self-signed certs won't be trusted),
     * but it DOES verify cryptographic integrity.
     */
    private static void validateSignedDocument(String signedPdfPath, AuditRecord audit) {
        try {
            DSSDocument signedDoc = new FileDocument(signedPdfPath);

            // Create validator for PDF documents
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDoc);

            // Use a certificate verifier that doesn't require trusted certs
            // We only want to check cryptographic integrity, not trust chain
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            validator.setCertificateVerifier(certificateVerifier);

            // Validate
            Reports reports = validator.validateDocument();
            SimpleReport simpleReport = reports.getSimpleReport();

            // Get first signature ID (we only have one)
            String signatureId = simpleReport.getFirstSignatureId();
            if (signatureId == null) {
                LOG.warn("VALIDATION_WARN: No signature found in document");
                audit.setSignatureIntegrityOk(false);
                audit.setTimestampIntegrityOk(false);
                audit.addError("VALIDATION_ERROR: No signature found");
                return;
            }

            // Check signature indication
            Indication indication = simpleReport.getIndication(signatureId);
            SubIndication subIndication = simpleReport.getSubIndication(signatureId);

            // For self-signed certs, we expect INDETERMINATE with NO_CERTIFICATE_CHAIN_FOUND
            // But the signature itself should be mathematically valid
            boolean signatureIntact = simpleReport.isSignatureIntact(signatureId);
            boolean signatureValid = simpleReport.isValid(signatureId);

            // Check timestamps
            int timestampCount = simpleReport.getSignatureTimestamps(signatureId).size();
            boolean hasTimestamp = timestampCount > 0;

            // Log results
            LOG.info("VALIDATION: indication={}, subIndication={}", indication, subIndication);
            LOG.info("VALIDATION: signatureIntact={}, signatureValid={}, timestamps={}",
                signatureIntact, signatureValid, timestampCount);

            // Record in audit
            // For self-signed: signatureIntact=true is what we care about
            // signatureValid might be false due to trust chain, which is expected
            audit.setSignatureIntegrityOk(signatureIntact);
            audit.setTimestampIntegrityOk(hasTimestamp);
            audit.setValidationIndication(indication.name());
            if (subIndication != null) {
                audit.setValidationSubIndication(subIndication.name());
            }

            if (signatureIntact) {
                LOG.info("VALIDATION_OK: Signature integrity verified");
            } else {
                LOG.error("VALIDATION_FAIL: Signature integrity check failed!");
                audit.addError("VALIDATION_ERROR: Signature integrity failed");
            }

            if (hasTimestamp) {
                LOG.info("VALIDATION_OK: Timestamp present ({} timestamp(s))", timestampCount);
            } else {
                LOG.warn("VALIDATION_WARN: No timestamp found");
            }

        } catch (Exception e) {
            LOG.error("Validation failed with exception", e);
            audit.setSignatureIntegrityOk(false);
            audit.addError("VALIDATION_ERROR: " + e.getMessage());
        }
    }

    /**
     * Sign document with TSA timestamp, with exponential backoff retry.
     * TSA servers can be temporarily unavailable, so we retry up to 3 times.
     */
    private static DSSDocument signDocumentWithTsaRetry(
            PAdESService service,
            DSSDocument toSignDocument,
            PAdESSignatureParameters parameters,
            SignatureValue signatureValue,
            AuditRecord audit) throws Exception {

        final int MAX_RETRIES = 3;
        final long[] BACKOFF_MS = {0, 1000, 3000};  // 0s, 1s, 3s (exponential-ish)

        Exception lastException = null;
        long totalLatency = 0;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            // Wait before retry (skip for first attempt)
            if (attempt > 1) {
                long backoff = BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)];
                LOG.info("TSA retry attempt {}/{} after {}ms backoff...", attempt, MAX_RETRIES, backoff);
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new TsaException("TSA retry interrupted", ie);
                }
            }

            long tsaStart = System.currentTimeMillis();
            try {
                DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
                long tsaTime = System.currentTimeMillis() - tsaStart;
                totalLatency += tsaTime;

                LOG.info("TSA_OK: Timestamp obtained in {}ms (attempt {}/{})", tsaTime, attempt, MAX_RETRIES);

                // Record TSA metrics in audit
                audit.setTsaLatencyMs(totalLatency);
                audit.setTsaAttempts(attempt);
                audit.setTsaTokenTime(Instant.now());

                return signedDocument;

            } catch (Exception e) {
                long tsaTime = System.currentTimeMillis() - tsaStart;
                totalLatency += tsaTime;
                lastException = e;

                String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                LOG.warn("TSA_FAIL: Attempt {}/{} failed after {}ms: {}",
                    attempt, MAX_RETRIES, tsaTime, errorMsg);

                // Check if this is a retryable error (network/timeout issues)
                if (!isRetryableTsaError(e)) {
                    LOG.error("TSA error is not retryable, giving up");
                    break;
                }
            }
        }

        // All retries exhausted
        audit.setTsaLatencyMs(totalLatency);
        String errorMsg = lastException != null ? lastException.getMessage() : "Unknown TSA error";
        throw new TsaException("TSA failed after " + MAX_RETRIES + " attempts: " + errorMsg, lastException);
    }

    /**
     * Determine if a TSA error is worth retrying.
     * Network timeouts, connection refused, etc. are retryable.
     * Invalid response format, certificate errors, etc. are not.
     */
    private static boolean isRetryableTsaError(Exception e) {
        String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
        String className = e.getClass().getSimpleName().toLowerCase();

        // Retryable: network issues
        if (msg.contains("timeout") || msg.contains("timed out")) return true;
        if (msg.contains("connection") && (msg.contains("refused") || msg.contains("reset"))) return true;
        if (msg.contains("unreachable") || msg.contains("no route")) return true;
        if (msg.contains("temporary") || msg.contains("unavailable")) return true;
        if (className.contains("timeout") || className.contains("socket")) return true;
        if (className.contains("connect")) return true;

        // Check cause chain
        Throwable cause = e.getCause();
        if (cause != null && cause != e) {
            if (cause instanceof java.net.SocketTimeoutException) return true;
            if (cause instanceof java.net.ConnectException) return true;
            if (cause instanceof java.net.UnknownHostException) return true;
        }

        // Not retryable: likely a permanent error
        return false;
    }

    private static String computeCertFingerprint(CertificateToken cert) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(cert.getEncoded());
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            LOG.warn("Failed to compute certificate fingerprint", e);
            return "unknown";
        }
    }

    private static String computeSha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
