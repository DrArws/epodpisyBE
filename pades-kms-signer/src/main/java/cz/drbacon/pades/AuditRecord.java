package cz.drbacon.pades;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Audit record for PDF signing operation.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditRecord {

    @JsonProperty("session_id")
    private String sessionId;

    @JsonProperty("document_sha256_before")
    private String documentSha256Before;

    @JsonProperty("document_sha256_after")
    private String documentSha256After;

    @JsonProperty("kms_key_version")
    private String kmsKeyVersion;

    @JsonProperty("signing_time_utc")
    private Instant signingTimeUtc;

    @JsonProperty("tsa_url")
    private String tsaUrl;

    @JsonProperty("tsa_url_used")
    private String tsaUrlUsed;

    @JsonProperty("tsa_fallback_url")
    private String tsaFallbackUrl;

    @JsonProperty("tsa_fallback_used")
    private Boolean tsaFallbackUsed;

    @JsonProperty("tsa_qualified")
    private Boolean tsaQualified;

    @JsonProperty("tsa_applied")
    private Boolean tsaApplied;

    @JsonProperty("tsa_error_type")
    private String tsaErrorType;

    @JsonProperty("tsa_error_message")
    private String tsaErrorMessage;

    @JsonProperty("tsa_token_time")
    private Instant tsaTokenTime;

    @JsonProperty("signer_display_name")
    private String signerDisplayName;

    @JsonProperty("ip")
    private String ip;

    @JsonProperty("user_agent")
    private String userAgent;

    @JsonProperty("otp_method")
    private String otpMethod;

    @JsonProperty("otp_verified_at")
    private Instant otpVerifiedAt;

    @JsonProperty("signature_profile")
    private String signatureProfile;

    @JsonProperty("certificate_subject")
    private String certificateSubject;

    @JsonProperty("certificate_fingerprint")
    private String certificateFingerprint;

    @JsonProperty("trust_model")
    private String trustModel;

    @JsonProperty("kms_latency_ms")
    private Long kmsLatencyMs;

    @JsonProperty("tsa_latency_ms")
    private Long tsaLatencyMs;

    @JsonProperty("tsa_attempts")
    private Integer tsaAttempts;

    @JsonProperty("signature_bytes")
    private Integer signatureBytes;

    @JsonProperty("signature_integrity_ok")
    private Boolean signatureIntegrityOk;

    @JsonProperty("timestamp_integrity_ok")
    private Boolean timestampIntegrityOk;

    @JsonProperty("validation_indication")
    private String validationIndication;

    @JsonProperty("validation_sub_indication")
    private String validationSubIndication;

    @JsonProperty("input_file")
    private String inputFile;

    @JsonProperty("output_file")
    private String outputFile;

    @JsonProperty("success")
    private boolean success;

    @JsonProperty("errors")
    private List<String> errors = new ArrayList<>();

    @JsonProperty("warnings")
    private List<String> warnings = new ArrayList<>();

    public AuditRecord() {
        this.sessionId = UUID.randomUUID().toString();
        this.signingTimeUtc = Instant.now();
        this.ip = System.getenv("CLIENT_IP") != null ? System.getenv("CLIENT_IP") : "127.0.0.1";
        this.userAgent = "pades-kms-signer/1.0.0";
        this.otpMethod = "none";
    }

    // Getters and setters

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getDocumentSha256Before() {
        return documentSha256Before;
    }

    public void setDocumentSha256Before(String documentSha256Before) {
        this.documentSha256Before = documentSha256Before;
    }

    public String getDocumentSha256After() {
        return documentSha256After;
    }

    public void setDocumentSha256After(String documentSha256After) {
        this.documentSha256After = documentSha256After;
    }

    public String getKmsKeyVersion() {
        return kmsKeyVersion;
    }

    public void setKmsKeyVersion(String kmsKeyVersion) {
        this.kmsKeyVersion = kmsKeyVersion;
    }

    public Instant getSigningTimeUtc() {
        return signingTimeUtc;
    }

    public void setSigningTimeUtc(Instant signingTimeUtc) {
        this.signingTimeUtc = signingTimeUtc;
    }

    public String getTsaUrl() {
        return tsaUrl;
    }

    public void setTsaUrl(String tsaUrl) {
        this.tsaUrl = tsaUrl;
    }

    public String getTsaUrlUsed() {
        return tsaUrlUsed;
    }

    public void setTsaUrlUsed(String tsaUrlUsed) {
        this.tsaUrlUsed = tsaUrlUsed;
    }

    public String getTsaFallbackUrl() {
        return tsaFallbackUrl;
    }

    public void setTsaFallbackUrl(String tsaFallbackUrl) {
        this.tsaFallbackUrl = tsaFallbackUrl;
    }

    public Boolean getTsaFallbackUsed() {
        return tsaFallbackUsed;
    }

    public void setTsaFallbackUsed(Boolean tsaFallbackUsed) {
        this.tsaFallbackUsed = tsaFallbackUsed;
    }

    public Boolean getTsaQualified() {
        return tsaQualified;
    }

    public void setTsaQualified(Boolean tsaQualified) {
        this.tsaQualified = tsaQualified;
    }

    public Boolean getTsaApplied() {
        return tsaApplied;
    }

    public void setTsaApplied(Boolean tsaApplied) {
        this.tsaApplied = tsaApplied;
    }

    public String getTsaErrorType() {
        return tsaErrorType;
    }

    public void setTsaErrorType(String tsaErrorType) {
        this.tsaErrorType = tsaErrorType;
    }

    public String getTsaErrorMessage() {
        return tsaErrorMessage;
    }

    public void setTsaErrorMessage(String tsaErrorMessage) {
        this.tsaErrorMessage = tsaErrorMessage;
    }

    public Instant getTsaTokenTime() {
        return tsaTokenTime;
    }

    public void setTsaTokenTime(Instant tsaTokenTime) {
        this.tsaTokenTime = tsaTokenTime;
    }

    public String getSignerDisplayName() {
        return signerDisplayName;
    }

    public void setSignerDisplayName(String signerDisplayName) {
        this.signerDisplayName = signerDisplayName;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getOtpMethod() {
        return otpMethod;
    }

    public void setOtpMethod(String otpMethod) {
        this.otpMethod = otpMethod;
    }

    public Instant getOtpVerifiedAt() {
        return otpVerifiedAt;
    }

    public void setOtpVerifiedAt(Instant otpVerifiedAt) {
        this.otpVerifiedAt = otpVerifiedAt;
    }

    public String getSignatureProfile() {
        return signatureProfile;
    }

    public void setSignatureProfile(String signatureProfile) {
        this.signatureProfile = signatureProfile;
    }

    public String getCertificateSubject() {
        return certificateSubject;
    }

    public void setCertificateSubject(String certificateSubject) {
        this.certificateSubject = certificateSubject;
    }

    public String getCertificateFingerprint() {
        return certificateFingerprint;
    }

    public void setCertificateFingerprint(String certificateFingerprint) {
        this.certificateFingerprint = certificateFingerprint;
    }

    public String getTrustModel() {
        return trustModel;
    }

    public void setTrustModel(String trustModel) {
        this.trustModel = trustModel;
    }

    public Long getKmsLatencyMs() {
        return kmsLatencyMs;
    }

    public void setKmsLatencyMs(Long kmsLatencyMs) {
        this.kmsLatencyMs = kmsLatencyMs;
    }

    public Long getTsaLatencyMs() {
        return tsaLatencyMs;
    }

    public void setTsaLatencyMs(Long tsaLatencyMs) {
        this.tsaLatencyMs = tsaLatencyMs;
    }

    public Integer getTsaAttempts() {
        return tsaAttempts;
    }

    public void setTsaAttempts(Integer tsaAttempts) {
        this.tsaAttempts = tsaAttempts;
    }

    public Integer getSignatureBytes() {
        return signatureBytes;
    }

    public void setSignatureBytes(Integer signatureBytes) {
        this.signatureBytes = signatureBytes;
    }

    public Boolean getSignatureIntegrityOk() {
        return signatureIntegrityOk;
    }

    public void setSignatureIntegrityOk(Boolean signatureIntegrityOk) {
        this.signatureIntegrityOk = signatureIntegrityOk;
    }

    public Boolean getTimestampIntegrityOk() {
        return timestampIntegrityOk;
    }

    public void setTimestampIntegrityOk(Boolean timestampIntegrityOk) {
        this.timestampIntegrityOk = timestampIntegrityOk;
    }

    public String getValidationIndication() {
        return validationIndication;
    }

    public void setValidationIndication(String validationIndication) {
        this.validationIndication = validationIndication;
    }

    public String getValidationSubIndication() {
        return validationSubIndication;
    }

    public void setValidationSubIndication(String validationSubIndication) {
        this.validationSubIndication = validationSubIndication;
    }

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void addError(String error) {
        this.errors.add(error);
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void addWarning(String warning) {
        this.warnings.add(warning);
    }

    /**
     * Write audit record to JSON file.
     */
    public void writeToFile(String path) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.writeValue(new File(path), this);
    }
}
