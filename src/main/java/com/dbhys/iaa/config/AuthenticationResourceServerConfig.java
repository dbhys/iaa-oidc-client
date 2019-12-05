package com.dbhys.iaa.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Created by Milas on 2019/3/19.
 */
@Configuration
@ConfigurationProperties("dbhys.oidc")
public class AuthenticationResourceServerConfig {

    /**
     * The default lifespan for cached JWK sets (5 minutes).
     */
    public static final long DEFAULT_LIFESPAN_HOUR = 24;

    /**
     * The default HTTP connect timeout for JWK set retrieval, in
     * milliseconds. Set to 500 milliseconds.
     */
    private static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 500;


    /**
     * The default HTTP read timeout for JWK set retrieval, in
     * milliseconds. Set to 500 milliseconds.
     */
    private static final int DEFAULT_HTTP_READ_TIMEOUT = 500;

    private String issuer;

    private String clientId;

    private String scope;

    private Long lifeSpan = DEFAULT_LIFESPAN_HOUR;

    // The HTTP connect timeout, in milliseconds. Zero implies no timeout. Must not be negative.
    private Integer connectTimeout = DEFAULT_HTTP_CONNECT_TIMEOUT;

    // The HTTP response read timeout, in milliseconds. Zero implies no timeout. Must not be negative.
    private Integer readTimeout = DEFAULT_HTTP_READ_TIMEOUT;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Long getLifeSpan() {
        return lifeSpan;
    }

    public void setLifeSpan(Long lifeSpan) {
        this.lifeSpan = lifeSpan;
    }

    public Integer getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Integer connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Integer getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Integer readTimeout) {
        this.readTimeout = readTimeout;
    }
}
