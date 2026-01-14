package cz.drbacon.pades;

import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * DSS Signature Token that uses Google Cloud KMS for signing.
 * The private key never leaves KMS - only the digest is sent for signing.
 */
public class KmsSignatureToken extends AbstractSignatureTokenConnection {

    private static final Logger LOG = LoggerFactory.getLogger(KmsSignatureToken.class);

    private final String keyVersionName;
    private final KeyManagementServiceClient kmsClient;
    private final CertificateToken certificateToken;
    private final KmsPrivateKeyEntry privateKeyEntry;

    public KmsSignatureToken(String projectId, String location, String keyRing,
                             String keyName, String keyVersion, String signerName) throws Exception {
        this.keyVersionName = CryptoKeyVersionName.format(projectId, location, keyRing, keyName, keyVersion);
        this.kmsClient = KeyManagementServiceClient.create();

        LOG.info("Initializing KMS signature token for key: {}", keyVersionName);

        // Get public key from KMS
        PublicKey publicKey = kmsClient.getPublicKey(keyVersionName);
        LOG.info("Retrieved public key from KMS, algorithm: {}", publicKey.getAlgorithm());

        // Parse PEM public key
        java.security.PublicKey javaPublicKey = parsePublicKey(publicKey.getPem());

        // Generate self-signed certificate for the KMS key
        X509Certificate cert = generateSelfSignedCertificate(javaPublicKey, signerName);
        this.certificateToken = new CertificateToken(cert);

        this.privateKeyEntry = new KmsPrivateKeyEntry(certificateToken);

        LOG.info("KMS signature token initialized successfully");
    }

    private java.security.PublicKey parsePublicKey(String pem) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            Object obj = pemParser.readObject();
            if (obj instanceof SubjectPublicKeyInfo) {
                SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo) obj;
                return java.security.KeyFactory.getInstance("RSA")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki.getEncoded()));
            }
            throw new IOException("Unexpected PEM content: " + obj.getClass());
        } catch (Exception e) {
            throw new IOException("Failed to parse public key PEM", e);
        }
    }

    private X509Certificate generateSelfSignedCertificate(java.security.PublicKey publicKey,
                                                          String signerName) throws Exception {
        LOG.info("Generating self-signed certificate for signer: {}", signerName);

        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000L); // yesterday
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); // 1 year

        X500Principal subject = new X500Principal("CN=" + signerName + ", O=DrBacon E-Signing, C=CZ");

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            new org.bouncycastle.asn1.x500.X500Name(subject.getName()),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            new org.bouncycastle.asn1.x500.X500Name(subject.getName()),
            subjectPublicKeyInfo
        );

        // Use KMS to sign the certificate
        ContentSigner signer = new KmsContentSigner();
        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
        return Collections.singletonList(privateKeyEntry);
    }

    @Override
    public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm,
                               DSSPrivateKeyEntry keyEntry) throws DSSException {
        int inputLength = toBeSigned.getBytes().length;
        LOG.info("Signing {} bytes with KMS, digest algorithm: {}", inputLength, digestAlgorithm);

        // Detect if DSS is sending raw data or already-hashed data
        // SHA256=32 bytes, SHA384=48 bytes, SHA512=64 bytes
        int expectedDigestSize = getExpectedDigestSize(digestAlgorithm);
        boolean isAlreadyDigest = (inputLength == expectedDigestSize);

        try {
            byte[] digest;
            if (isAlreadyDigest) {
                // DSS already computed the digest - use it directly, DO NOT re-hash!
                digest = toBeSigned.getBytes();
                LOG.info("KMS_SIGN: ToBeSigned IS digest ({} bytes) - using directly, digestHex={}...",
                    inputLength, bytesToHex(digest, 8));
            } else {
                // DSS sent raw data - compute the digest
                digest = computeDigest(toBeSigned.getBytes(), digestAlgorithm);
                LOG.info("KMS_SIGN: ToBeSigned={} bytes (raw), computed digest={} bytes, digestHex={}...",
                    inputLength, digest.length, bytesToHex(digest, 8));
            }

            // Build KMS request with appropriate digest field
            Digest.Builder digestBuilder = Digest.newBuilder();
            switch (digestAlgorithm) {
                case SHA256:
                    digestBuilder.setSha256(ByteString.copyFrom(digest));
                    break;
                case SHA384:
                    digestBuilder.setSha384(ByteString.copyFrom(digest));
                    break;
                case SHA512:
                    digestBuilder.setSha512(ByteString.copyFrom(digest));
                    break;
                default:
                    throw new DSSException("Unsupported digest algorithm for KMS: " + digestAlgorithm);
            }

            AsymmetricSignRequest request = AsymmetricSignRequest.newBuilder()
                .setName(keyVersionName)
                .setDigest(digestBuilder.build())
                .build();

            LOG.info("Calling KMS asymmetricSign for key: {}", keyVersionName);
            long kmsStart = System.currentTimeMillis();
            AsymmetricSignResponse response = kmsClient.asymmetricSign(request);
            long kmsLatency = System.currentTimeMillis() - kmsStart;

            byte[] signatureBytes = response.getSignature().toByteArray();
            LOG.info("KMS_SIGN: signature={} bytes in {}ms, sigHex={}...",
                signatureBytes.length, kmsLatency, bytesToHex(signatureBytes, 8));

            // Validate signature length for RSA4096: should be ~512 bytes
            if (signatureBytes.length < 256 || signatureBytes.length > 1024) {
                LOG.warn("KMS_SIGN: Unexpected signature length: {} bytes (expected ~512 for RSA4096)",
                    signatureBytes.length);
            }

            // IMPORTANT: Set correct SignatureAlgorithm based on digest algorithm used
            SignatureAlgorithm signatureAlgorithm = mapToSignatureAlgorithm(digestAlgorithm);
            LOG.info("KMS_SIGN: Using SignatureAlgorithm: {}", signatureAlgorithm);

            SignatureValue signatureValue = new SignatureValue();
            signatureValue.setAlgorithm(signatureAlgorithm);
            signatureValue.setValue(signatureBytes);

            return signatureValue;

        } catch (Exception e) {
            LOG.error("KMS signing failed", e);
            throw new DSSException("KMS signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Map DSS DigestAlgorithm to the correct SignatureAlgorithm for RSA.
     */
    private SignatureAlgorithm mapToSignatureAlgorithm(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA256:
                return SignatureAlgorithm.RSA_SHA256;
            case SHA384:
                return SignatureAlgorithm.RSA_SHA384;
            case SHA512:
                return SignatureAlgorithm.RSA_SHA512;
            default:
                LOG.warn("Unknown digest algorithm {}, defaulting to RSA_SHA256", digestAlgorithm);
                return SignatureAlgorithm.RSA_SHA256;
        }
    }

    /**
     * Get expected digest size in bytes for the given algorithm.
     */
    private int getExpectedDigestSize(DigestAlgorithm algorithm) {
        switch (algorithm) {
            case SHA256: return 32;
            case SHA384: return 48;
            case SHA512: return 64;
            default: return -1;
        }
    }

    private byte[] computeDigest(byte[] data, DigestAlgorithm algorithm) throws NoSuchAlgorithmException {
        String javaAlgorithm = algorithm.getJavaName();
        MessageDigest md = MessageDigest.getInstance(javaAlgorithm);
        return md.digest(data);
    }

    /**
     * Convert first N bytes to hex string for logging.
     */
    private String bytesToHex(byte[] bytes, int maxBytes) {
        int len = Math.min(bytes.length, maxBytes);
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }

    @Override
    public void close() {
        if (kmsClient != null) {
            kmsClient.close();
        }
    }

    public String getKeyVersionName() {
        return keyVersionName;
    }

    public CertificateToken getCertificateToken() {
        return certificateToken;
    }

    /**
     * Private key entry wrapping the KMS key.
     */
    private class KmsPrivateKeyEntry implements DSSPrivateKeyEntry {
        private final CertificateToken certificate;

        KmsPrivateKeyEntry(CertificateToken certificate) {
            this.certificate = certificate;
        }

        @Override
        public CertificateToken getCertificate() {
            return certificate;
        }

        @Override
        public CertificateToken[] getCertificateChain() {
            return new CertificateToken[] { certificate };
        }

        @Override
        public EncryptionAlgorithm getEncryptionAlgorithm() {
            return EncryptionAlgorithm.RSA;
        }
    }

    /**
     * Content signer using KMS for signing (used for self-signed certificate generation).
     */
    private class KmsContentSigner implements ContentSigner {
        private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        @Override
        public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
            return new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha256WithRSAEncryption
            );
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public byte[] getSignature() {
            try {
                byte[] data = outputStream.toByteArray();
                byte[] digest = computeDigest(data, DigestAlgorithm.SHA256);

                Digest kmsDigest = Digest.newBuilder()
                    .setSha256(ByteString.copyFrom(digest))
                    .build();

                AsymmetricSignRequest request = AsymmetricSignRequest.newBuilder()
                    .setName(keyVersionName)
                    .setDigest(kmsDigest)
                    .build();

                AsymmetricSignResponse response = kmsClient.asymmetricSign(request);
                return response.getSignature().toByteArray();

            } catch (Exception e) {
                throw new RuntimeException("KMS signing for certificate failed", e);
            }
        }
    }
}
