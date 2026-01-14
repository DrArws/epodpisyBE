package cz.drbacon.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
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
 *   TSA_URL      - Timestamp authority URL (optional, default: http://timestamp.digicert.com)
 */
public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    // TSA configuration (can be overridden via env var)
    private static final String DEFAULT_TSA_URL = "http://timestamp.digicert.com";

    // Parsed KMS configuration
    private static String PROJECT_ID;
    private static String LOCATION;
    private static String KEY_RING;
    private static String KEY_NAME;
    private static String KEY_VERSION;
    private static String TSA_URL;

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
            // Parse: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
            try {
                String[] parts = kmsKeyName.split("/");
                if (parts.length >= 10) {
                    PROJECT_ID = parts[1];   // projects/{project}
                    LOCATION = parts[3];     // locations/{location}
                    KEY_RING = parts[5];     // keyRings/{keyring}
                    KEY_NAME = parts[7];     // cryptoKeys/{key}
                    KEY_VERSION = parts[9];  // cryptoKeyVersions/{version}
                    LOG.info("Parsed KMS key: project={}, location={}, keyring={}, key={}, version={}",
                        PROJECT_ID, LOCATION, KEY_RING, KEY_NAME, KEY_VERSION);
                } else {
                    throw new IllegalArgumentException("Invalid format, expected 10 path segments");
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse KMS_KEY_NAME: " + kmsKeyName + " - " + e.getMessage(), e);
            }
        }

        // TSA URL (optional override)
        TSA_URL = System.getenv("TSA_URL");
        if (TSA_URL == null || TSA_URL.isEmpty()) {
            TSA_URL = DEFAULT_TSA_URL;
        }
    }

    public static void main(String[] args) {
        AuditRecord audit = new AuditRecord();

        try {
            if (args.length < 2) {
                System.err.println("Usage: java -jar pades-kms-signer.jar <input.pdf> <output.pdf> [signer-name]");
                System.exit(1);
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

            // Validate input
            File inputFile = new File(inputPath);
            if (!inputFile.exists()) {
                throw new IllegalArgumentException("Input file does not exist: " + inputPath);
            }

            // Compute input hash
            String inputHash = computeSha256(inputFile);
            audit.setDocumentSha256Before(inputHash);
            LOG.info("Input SHA-256: {}", inputHash);

            // Sign the document
            signDocument(inputPath, outputPath, signerName, audit);

            // Compute output hash
            File outputFile = new File(outputPath);
            if (outputFile.exists()) {
                String outputHash = computeSha256(outputFile);
                audit.setDocumentSha256After(outputHash);
                LOG.info("Output SHA-256: {}", outputHash);
                audit.setSuccess(true);
            } else {
                throw new RuntimeException("Output file was not created");
            }

            LOG.info("=== Signing completed successfully ===");

        } catch (Exception e) {
            LOG.error("Signing failed", e);
            audit.setSuccess(false);
            audit.addError(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        } finally {
            // Write audit record
            try {
                String auditPath = "audit.json";
                audit.writeToFile(auditPath);
                LOG.info("Audit record written to: {}", auditPath);
            } catch (Exception e) {
                LOG.error("Failed to write audit record", e);
            }
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

            LOG.info("Signing certificate subject: {}", signingCert.getSubject().getRFC2253());

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

            // Configure TSA
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
            SignatureValue signatureValue = token.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);

            // Embed signature and timestamp
            LOG.info("Embedding signature and requesting timestamp from TSA...");
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // Record TSA timestamp (approximate - actual timestamp is embedded in PDF)
            audit.setTsaTokenTime(Instant.now());

            // Save signed document
            LOG.info("Saving signed document to: {}", outputPath);
            try (OutputStream os = new FileOutputStream(outputPath)) {
                signedDocument.writeTo(os);
            }

            LOG.info("Document signed successfully!");
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
