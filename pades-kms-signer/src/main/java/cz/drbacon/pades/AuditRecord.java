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

    @JsonProperty("input_file")
    private String inputFile;

    @JsonProperty("output_file")
    private String outputFile;

    @JsonProperty("success")
    private boolean success;

    @JsonProperty("errors")
    private List<String> errors = new ArrayList<>();

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
