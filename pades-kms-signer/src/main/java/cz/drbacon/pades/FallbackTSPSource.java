package cz.drbacon.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * TSPSource wrapper with primary/fallback TSA support and proper error classification.
 *
 * Failover triggers (retry with fallback):
 * - ConnectException (connection refused)
 * - SocketTimeoutException
 * - UnknownHostException
 * - HTTP 5xx (server error)
 * - HTTP 429 (rate limited)
 *
 * Non-failover (client/config error - log but still try fallback):
 * - HTTP 400/401/403 (bad request, auth, forbidden)
 *
 * Reports detailed metrics for audit trail.
 */
public class FallbackTSPSource implements TSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(FallbackTSPSource.class);

    private final String primaryUrl;
    private final String fallbackUrl;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int maxRetries;

    // Metrics for audit
    private String urlUsed;
    private boolean fallbackUsed;
    private boolean qualified;
    private long totalLatencyMs;
    private int totalAttempts;
    private TsaErrorType lastErrorType;
    private String lastErrorMessage;
    private final List<String> attemptLog = new ArrayList<>();

    /**
     * TSA error classification for proper HTTP status mapping.
     */
    public enum TsaErrorType {
        NONE,
        TSA_UNAVAILABLE,      // Network/timeout/refused -> HTTP 503
        TSA_RATE_LIMITED,     // HTTP 429 -> HTTP 429
        TSA_INVALID_RESPONSE, // Parse error, bad token -> HTTP 502
        TSA_TLS_ERROR,        // TLS handshake, cert -> HTTP 502
        TSA_CLIENT_ERROR      // HTTP 400/401/403 -> HTTP 400
    }

    public FallbackTSPSource(String primaryUrl, String fallbackUrl,
                              int connectTimeoutMs, int readTimeoutMs, int maxRetries) {
        this.primaryUrl = primaryUrl;
        this.fallbackUrl = fallbackUrl;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.maxRetries = maxRetries;
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {
        // Reset metrics
        urlUsed = null;
        fallbackUsed = false;
        qualified = false;
        totalLatencyMs = 0;
        totalAttempts = 0;
        lastErrorType = TsaErrorType.NONE;
        lastErrorMessage = null;
        attemptLog.clear();

        // Try primary TSA
        Exception primaryException = null;
        TimestampBinary result = tryTsa(primaryUrl, false, digestAlgorithm, digest);
        if (result != null) {
            return result;
        }
        primaryException = new DSSException(lastErrorMessage);

        // Primary failed, try fallback
        if (fallbackUrl != null && !fallbackUrl.isEmpty()) {
            LOG.warn("Primary TSA {} failed, switching to fallback {}", primaryUrl, fallbackUrl);
            result = tryTsa(fallbackUrl, true, digestAlgorithm, digest);
            if (result != null) {
                return result;
            }
        }

        // Both failed
        throw new TsaException(
            "All TSA servers failed after " + totalAttempts + " attempts: " + lastErrorMessage,
            lastErrorType,
            primaryException
        );
    }

    private TimestampBinary tryTsa(String tsaUrl, boolean isFallback,
                                    DigestAlgorithm digestAlgorithm, byte[] digest) {
        OnlineTSPSource tspSource = createConfiguredTspSource(tsaUrl);

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            totalAttempts++;

            // Exponential backoff (skip for first attempt)
            if (attempt > 1) {
                long backoff = 1000L * (1 << (attempt - 2));  // 1s, 2s, 4s...
                LOG.info("TSA {} retry {}/{} after {}ms backoff",
                    isFallback ? "fallback" : "primary", attempt, maxRetries, backoff);
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    lastErrorType = TsaErrorType.TSA_UNAVAILABLE;
                    lastErrorMessage = "Interrupted";
                    return null;
                }
            }

            long start = System.currentTimeMillis();
            String attemptDesc = String.format("%s attempt %d/%d",
                isFallback ? "fallback" : "primary", attempt, maxRetries);

            try {
                LOG.info("TSA request to {} ({})", tsaUrl, attemptDesc);
                TimestampBinary result = tspSource.getTimeStampResponse(digestAlgorithm, digest);
                long elapsed = System.currentTimeMillis() - start;
                totalLatencyMs += elapsed;

                // Success!
                urlUsed = tsaUrl;
                fallbackUsed = isFallback;
                qualified = isQualifiedTsa(tsaUrl);
                lastErrorType = TsaErrorType.NONE;
                lastErrorMessage = null;

                LOG.info("TSA_OK: {} in {}ms ({})", tsaUrl, elapsed, attemptDesc);
                attemptLog.add(String.format("OK: %s %dms", tsaUrl, elapsed));

                return result;

            } catch (Exception e) {
                long elapsed = System.currentTimeMillis() - start;
                totalLatencyMs += elapsed;

                TsaErrorType errorType = classifyError(e);
                String errorMsg = extractErrorMessage(e);

                lastErrorType = errorType;
                lastErrorMessage = errorMsg;

                LOG.warn("TSA_FAIL: {} {} after {}ms: {} ({})",
                    tsaUrl, errorType, elapsed, errorMsg, attemptDesc);
                attemptLog.add(String.format("FAIL: %s %s %dms %s",
                    tsaUrl, errorType, elapsed, errorMsg));

                // Decide if we should retry or give up on this TSA
                if (!shouldRetry(errorType)) {
                    LOG.info("Error type {} is not retryable for this TSA", errorType);
                    break;
                }
            }
        }

        return null;  // All attempts failed
    }

    private OnlineTSPSource createConfiguredTspSource(String tsaUrl) {
        OnlineTSPSource tspSource = new OnlineTSPSource(tsaUrl);

        // Use TimestampDataLoader - it sets Content-Type: application/timestamp-query
        // which is REQUIRED by TSA servers (CommonsDataLoader doesn't set this!)
        TimestampDataLoader dataLoader = new TimestampDataLoader();
        dataLoader.setTimeoutConnection(connectTimeoutMs);
        dataLoader.setTimeoutSocket(readTimeoutMs);
        // Connection request timeout (time waiting for connection from pool)
        dataLoader.setTimeoutConnectionRequest(connectTimeoutMs);

        tspSource.setDataLoader(dataLoader);

        return tspSource;
    }

    /**
     * Classify exception into canonical error type.
     */
    private TsaErrorType classifyError(Exception e) {
        String message = getFullErrorMessage(e);
        String className = e.getClass().getSimpleName();

        // Check exception chain
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof SocketTimeoutException) {
                return TsaErrorType.TSA_UNAVAILABLE;
            }
            if (cause instanceof ConnectException) {
                return TsaErrorType.TSA_UNAVAILABLE;
            }
            if (cause instanceof UnknownHostException) {
                return TsaErrorType.TSA_UNAVAILABLE;
            }
            if (cause instanceof javax.net.ssl.SSLException) {
                return TsaErrorType.TSA_TLS_ERROR;
            }
            cause = cause.getCause();
        }

        // Check message patterns
        String lowerMessage = message.toLowerCase();

        // Network errors
        if (lowerMessage.contains("connection refused") ||
            lowerMessage.contains("connect timed out") ||
            lowerMessage.contains("read timed out") ||
            lowerMessage.contains("no route to host") ||
            lowerMessage.contains("network is unreachable") ||
            lowerMessage.contains("host is down")) {
            return TsaErrorType.TSA_UNAVAILABLE;
        }

        // TLS errors
        if (lowerMessage.contains("ssl") ||
            lowerMessage.contains("tls") ||
            lowerMessage.contains("certificate") ||
            lowerMessage.contains("handshake")) {
            return TsaErrorType.TSA_TLS_ERROR;
        }

        // HTTP status codes in message
        if (lowerMessage.contains("429") || lowerMessage.contains("rate limit")) {
            return TsaErrorType.TSA_RATE_LIMITED;
        }
        if (lowerMessage.contains("500") ||
            lowerMessage.contains("502") ||
            lowerMessage.contains("503") ||
            lowerMessage.contains("504")) {
            return TsaErrorType.TSA_UNAVAILABLE;
        }
        if (lowerMessage.contains("400") ||
            lowerMessage.contains("401") ||
            lowerMessage.contains("403")) {
            return TsaErrorType.TSA_CLIENT_ERROR;
        }

        // Invalid response / parse errors
        if (lowerMessage.contains("invalid") ||
            lowerMessage.contains("parse") ||
            lowerMessage.contains("unexpected") ||
            lowerMessage.contains("malformed")) {
            return TsaErrorType.TSA_INVALID_RESPONSE;
        }

        // Default to unavailable for unknown network issues
        if (className.contains("Connect") ||
            className.contains("Socket") ||
            className.contains("Timeout")) {
            return TsaErrorType.TSA_UNAVAILABLE;
        }

        return TsaErrorType.TSA_INVALID_RESPONSE;  // Default for unknown errors
    }

    /**
     * Determine if error type warrants retry.
     */
    private boolean shouldRetry(TsaErrorType errorType) {
        switch (errorType) {
            case TSA_UNAVAILABLE:
            case TSA_RATE_LIMITED:
                return true;  // Transient, retry makes sense
            case TSA_TLS_ERROR:
            case TSA_CLIENT_ERROR:
            case TSA_INVALID_RESPONSE:
                return false;  // Permanent-ish, retry won't help
            default:
                return false;
        }
    }

    private String getFullErrorMessage(Exception e) {
        StringBuilder sb = new StringBuilder();
        Throwable t = e;
        while (t != null) {
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(t.getClass().getSimpleName());
            if (t.getMessage() != null) {
                sb.append(": ").append(t.getMessage());
            }
            t = t.getCause();
        }
        return sb.toString();
    }

    private String extractErrorMessage(Exception e) {
        if (e.getMessage() != null) {
            return e.getMessage();
        }
        if (e.getCause() != null && e.getCause().getMessage() != null) {
            return e.getCause().getMessage();
        }
        return e.getClass().getSimpleName();
    }

    /**
     * Check if TSA URL is a known eIDAS qualified TSA.
     */
    private boolean isQualifiedTsa(String tsaUrl) {
        if (tsaUrl == null) return false;
        return tsaUrl.contains("timestamp.aped.gov.gr") ||  // APED Greece
               tsaUrl.contains("tsa.swisssign.net") ||      // SwissSign
               tsaUrl.contains("timestamp.sectigo.com");    // Sectigo
    }

    // Getters for audit metrics

    public String getUrlUsed() {
        return urlUsed;
    }

    public boolean isFallbackUsed() {
        return fallbackUsed;
    }

    public boolean isQualified() {
        return qualified;
    }

    public long getTotalLatencyMs() {
        return totalLatencyMs;
    }

    public int getTotalAttempts() {
        return totalAttempts;
    }

    public TsaErrorType getLastErrorType() {
        return lastErrorType;
    }

    public String getLastErrorMessage() {
        return lastErrorMessage;
    }

    public List<String> getAttemptLog() {
        return attemptLog;
    }

    /**
     * Custom exception with error type for proper HTTP status mapping.
     */
    public static class TsaException extends DSSException {
        private final TsaErrorType errorType;

        public TsaException(String message, TsaErrorType errorType, Throwable cause) {
            super(message, cause);
            this.errorType = errorType;
        }

        public TsaErrorType getErrorType() {
            return errorType;
        }

        /**
         * Get recommended HTTP status code for this error.
         */
        public int getHttpStatus() {
            switch (errorType) {
                case TSA_UNAVAILABLE:
                    return 503;  // Service Unavailable
                case TSA_RATE_LIMITED:
                    return 429;  // Too Many Requests
                case TSA_TLS_ERROR:
                case TSA_INVALID_RESPONSE:
                    return 502;  // Bad Gateway
                case TSA_CLIENT_ERROR:
                    return 400;  // Bad Request
                default:
                    return 500;  // Internal Server Error
            }
        }
    }
}
