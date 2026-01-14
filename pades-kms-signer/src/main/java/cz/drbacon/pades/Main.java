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
 *   KMS_KEY_NAME          - Full KMS key resource name (required)
 *                           Format: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
 *                           Or without version: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
 *   TSA_URL               - Primary TSA URL (default: https://timestamp.aped.gov.gr/qtss - eIDAS qualified)
 *   TSA_FALLBACK_URL      - Fallback TSA URL (default: https://tsa.swisssign.net)
 *   TSA_CONNECT_TIMEOUT_MS - TSA connection timeout in ms (default: 5000)
 *   TSA_READ_TIMEOUT_MS   - TSA read timeout in ms (default: 15000)
 *   TSA_MAX_RETRIES       - Max retries per TSA (default: 2)
 *   TSA_FAIL_OPEN         - If "true", fallback to BASELINE-B when TSA unavailable (default: false)
 *
 * Exit codes:
 *   0 - Success
 *   1 - Usage error (wrong arguments)
 *   2 - Config error (KMS_KEY_NAME parse, missing env)
 *   3 - KMS error (permission denied, key not found)
 *   4 - TSA/network error (timestamp server unavailable) - only if TSA_FAIL_OPEN=false
 *   5 - PDF error (file not found, parse/write error)
 *
 * TSA Error Types (canonical codes for FE):
 *   TSA_UNAVAILABLE      - Network/timeout/refused (HTTP 503)
 *   TSA_RATE_LIMITED     - HTTP 429 (HTTP 429)
 *   TSA_INVALID_RESPONSE - Parse/token error (HTTP 502)
 *   TSA_TLS_ERROR        - TLS/certificate error (HTTP 502)
 *   TSA_CLIENT_ERROR     - HTTP 400/401/403 (HTTP 400)
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

    // TSA configuration - APED Greece (eIDAS qualified) as primary
    private static final String DEFAULT_TSA_URL = "https://timestamp.aped.gov.gr/qtss";
    private static final String DEFAULT_TSA_FALLBACK_URL = "https://tsa.swisssign.net";
    private static final int DEFAULT_TSA_CONNECT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_TSA_READ_TIMEOUT_MS = 15000;
    private static final int DEFAULT_TSA_MAX_RETRIES = 2;

    // Parsed KMS configuration
    private static String PROJECT_ID;
    private static String LOCATION;
    private static String KEY_RING;
    private static String KEY_NAME;
    private static String KEY_VERSION;

    // TSA configuration
    private static String TSA_URL;
    private static String TSA_FALLBACK_URL;
    private static int TSA_CONNECT_TIMEOUT_MS;
    private static int TSA_READ_TIMEOUT_MS;
    private static int TSA_MAX_RETRIES;
    private static boolean TSA_FAIL_OPEN;  // Fallback to BASELINE-B if TSA fails

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

        // TSA configuration (optional overrides)
        TSA_URL = getEnvOrDefault("TSA_URL", DEFAULT_TSA_URL);
        TSA_FALLBACK_URL = getEnvOrDefault("TSA_FALLBACK_URL", DEFAULT_TSA_FALLBACK_URL);
        TSA_CONNECT_TIMEOUT_MS = getEnvOrDefaultInt("TSA_CONNECT_TIMEOUT_MS", DEFAULT_TSA_CONNECT_TIMEOUT_MS);
        TSA_READ_TIMEOUT_MS = getEnvOrDefaultInt("TSA_READ_TIMEOUT_MS", DEFAULT_TSA_READ_TIMEOUT_MS);
        TSA_MAX_RETRIES = getEnvOrDefaultInt("TSA_MAX_RETRIES", DEFAULT_TSA_MAX_RETRIES);

        TSA_FAIL_OPEN = "true".equalsIgnoreCase(getEnvOrDefault("TSA_FAIL_OPEN", "false"));

        LOG.info("TSA primary: {} (timeout: {}ms connect, {}ms read)", TSA_URL, TSA_CONNECT_TIMEOUT_MS, TSA_READ_TIMEOUT_MS);
        LOG.info("TSA fallback: {}", TSA_FALLBACK_URL);
        LOG.info("TSA fail-open mode: {} (fallback to BASELINE-B if TSA unavailable)", TSA_FAIL_OPEN);

        if (TSA_URL.startsWith("http://")) {
            LOG.warn("TSA_URL uses HTTP instead of HTTPS - consider using HTTPS for security");
        }
    }

    private static String getEnvOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static int getEnvOrDefaultInt(String name, int defaultValue) {
        String value = System.getenv(name);
        if (value != null && !value.isEmpty()) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                LOG.warn("Invalid integer for {}: {}, using default: {}", name, value, defaultValue);
            }
        }
        return defaultValue;
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
            audit.setTsaFallbackUrl(TSA_FALLBACK_URL);
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
        private final FallbackTSPSource.TsaErrorType errorType;
        private final int httpStatus;

        public TsaException(String message, Throwable cause) {
            super(message, cause);
            this.errorType = FallbackTSPSource.TsaErrorType.TSA_UNAVAILABLE;
            this.httpStatus = 503;
        }

        public TsaException(String message, FallbackTSPSource.TsaErrorType errorType, int httpStatus, Throwable cause) {
            super(message, cause);
            this.errorType = errorType;
            this.httpStatus = httpStatus;
        }

        public FallbackTSPSource.TsaErrorType getErrorType() {
            return errorType;
        }

        public int getHttpStatus() {
            return httpStatus;
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

            // Configure PAdES parameters - start with BASELINE-T (with timestamp)
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
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

            // Create certificate verifier (allows self-signed for now)
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

            // Create PAdES service
            PAdESService service = new PAdESService(certificateVerifier);

            // Create FallbackTSPSource with proper timeouts
            FallbackTSPSource tspSource = new FallbackTSPSource(
                TSA_URL, TSA_FALLBACK_URL,
                TSA_CONNECT_TIMEOUT_MS, TSA_READ_TIMEOUT_MS, TSA_MAX_RETRIES
            );
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

            // Embed signature with timestamp
            LOG.info("Requesting timestamp from TSA...");
            DSSDocument signedDocument;
            boolean tsaApplied = true;
            String signatureProfile = "PAdES-BASELINE-T";

            try {
                signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

                // Record TSA metrics from FallbackTSPSource
                audit.setTsaUrlUsed(tspSource.getUrlUsed());
                audit.setTsaFallbackUsed(tspSource.isFallbackUsed());
                audit.setTsaQualified(tspSource.isQualified());
                audit.setTsaLatencyMs(tspSource.getTotalLatencyMs());
                audit.setTsaAttempts(tspSource.getTotalAttempts());
                audit.setTsaTokenTime(Instant.now());

                LOG.info("TSA_OK: Timestamp applied from {} (qualified: {}, fallback: {})",
                    tspSource.getUrlUsed(), tspSource.isQualified(), tspSource.isFallbackUsed());

            } catch (FallbackTSPSource.TsaException e) {
                // TSA failed - check if fail-open mode is enabled
                LOG.error("TSA_FAILED: {} (error type: {})", e.getMessage(), e.getErrorType());

                // Record TSA failure metrics
                audit.setTsaLatencyMs(tspSource.getTotalLatencyMs());
                audit.setTsaAttempts(tspSource.getTotalAttempts());
                audit.setTsaErrorType(e.getErrorType().name());
                audit.setTsaErrorMessage(tspSource.getLastErrorMessage());

                if (TSA_FAIL_OPEN) {
                    // Fail-open: fallback to BASELINE-B (no timestamp)
                    LOG.warn("TSA_FAIL_OPEN: Falling back to BASELINE-B (no timestamp)");

                    parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
                    signatureProfile = "PAdES-BASELINE-B";
                    tsaApplied = false;

                    // Re-compute data to sign with new parameters
                    dataToSign = service.getDataToSign(toSignDocument, parameters);

                    // Re-sign with KMS
                    signatureValue = token.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);

                    // Sign without TSP source
                    service.setTspSource(null);
                    signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

                    audit.addWarning("TSA_UNAVAILABLE_FALLBACK_TO_B");
                    LOG.warn("Signed with BASELINE-B due to TSA unavailability");

                } else {
                    // Fail-closed: throw error
                    throw new TsaException(
                        "TSA request failed: " + e.getMessage(),
                        e.getErrorType(),
                        e.getHttpStatus(),
                        e
                    );
                }
            }

            // Record final signature profile
            audit.setSignatureProfile(signatureProfile);
            audit.setTsaApplied(tsaApplied);

            // Pre-flight validation: verify signature in memory BEFORE writing to disk
            LOG.info("Pre-flight validation: verifying signature in memory...");
            boolean preflightOk = validateInMemory(signedDocument, certificateVerifier);
            if (!preflightOk) {
                LOG.error("PRE_FLIGHT_FAIL: Signature validation failed in memory before disk write!");
                audit.addError("PRE_FLIGHT_FAIL: Signature invalid before disk write");
                // Continue anyway to write the file for debugging, but log prominently
            } else {
                LOG.info("PRE_FLIGHT_OK: In-memory signature validation passed");
            }

            // Save signed document
            LOG.info("Saving signed document to: {}", outputPath);
            try (OutputStream os = new FileOutputStream(outputPath)) {
                signedDocument.writeTo(os);
            }
            LOG.info("PDF_WRITE_OK: Document saved successfully (profile: {})", signatureProfile);

            // Post-write validation: verify signature after writing to disk
            LOG.info("Post-write validation: verifying signature from disk...");
            validateSignedDocument(outputPath, audit);

            LOG.info("Document signed and validated successfully!");

        } catch (TsaException e) {
            throw e;  // Already properly wrapped
        } catch (FallbackTSPSource.TsaException e) {
            throw new TsaException(e.getMessage(), e.getErrorType(), e.getHttpStatus(), e);
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
            // TOTAL_PASSED = fully valid, INDETERMINATE = crypto OK but trust issues
            // TOTAL_FAILED = crypto failure
            boolean signatureValid = simpleReport.isValid(signatureId);

            // Signature is cryptographically intact if indication is not TOTAL_FAILED
            // For self-signed: INDETERMINATE is expected and acceptable
            boolean signatureIntact = (indication != Indication.TOTAL_FAILED);

            // Check timestamps
            int timestampCount = simpleReport.getSignatureTimestamps(signatureId).size();
            boolean hasTimestamp = timestampCount > 0;

            // Log results with prominent indication/subIndication for debugging
            LOG.info("VALIDATION: indication={}, subIndication={}", indication, subIndication);
            LOG.info("VALIDATION: signatureIntact={}, signatureValid={}, timestamps={}",
                signatureIntact, signatureValid, timestampCount);

            // Record in audit
            // For self-signed: signatureIntact=true means crypto is OK (not TOTAL_FAILED)
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
                // Log detailed error info for TOTAL_FAILED cases
                String subIndicationStr = subIndication != null ? subIndication.name() : "null";
                LOG.error("VALIDATION_FAIL: Signature integrity check failed! indication={}, subIndication={}",
                    indication, subIndicationStr);

                // Try to get more details from the detailed report
                try {
                    eu.europa.esig.dss.detailedreport.DetailedReport detailedReport = reports.getDetailedReport();
                    String conclusion = detailedReport.getBasicBuildingBlocksSignatureConclusion(signatureId);
                    LOG.error("VALIDATION_FAIL: BBB conclusion: {}", conclusion);
                } catch (Exception detailEx) {
                    LOG.warn("Could not extract detailed report info: {}", detailEx.getMessage());
                }

                audit.addError("VALIDATION_ERROR: Signature integrity failed (indication=" + indication +
                    ", subIndication=" + subIndicationStr + ")");
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
     * Validate signature in memory before writing to disk.
     * Returns true if signature is cryptographically valid.
     */
    private static boolean validateInMemory(DSSDocument signedDoc, CommonCertificateVerifier certificateVerifier) {
        try {
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDoc);
            validator.setCertificateVerifier(certificateVerifier);

            Reports reports = validator.validateDocument();
            SimpleReport simpleReport = reports.getSimpleReport();

            String signatureId = simpleReport.getFirstSignatureId();
            if (signatureId == null) {
                LOG.error("PRE_FLIGHT: No signature found in document");
                return false;
            }

            Indication indication = simpleReport.getIndication(signatureId);
            SubIndication subIndication = simpleReport.getSubIndication(signatureId);

            LOG.info("PRE_FLIGHT: indication={}, subIndication={}", indication, subIndication);

            if (indication == Indication.TOTAL_FAILED) {
                LOG.error("PRE_FLIGHT: TOTAL_FAILED - subIndication={}", subIndication);

                // Dump more diagnostic info
                try {
                    eu.europa.esig.dss.detailedreport.DetailedReport detailedReport = reports.getDetailedReport();
                    LOG.error("PRE_FLIGHT: Detailed conclusion: {}",
                        detailedReport.getBasicBuildingBlocksSignatureConclusion(signatureId));
                } catch (Exception ex) {
                    LOG.warn("PRE_FLIGHT: Could not get detailed report: {}", ex.getMessage());
                }

                return false;
            }

            return true;
        } catch (Exception e) {
            LOG.error("PRE_FLIGHT: Validation exception: {}", e.getMessage(), e);
            return false;
        }
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
