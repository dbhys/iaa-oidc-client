package com.dbhys.iaa.validator;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

/**
 * Created by wangxd43 on 2019/12/5.
 */
public class IdTokenValidatorForRs {
    public static final int DEFAULT_MAX_CLOCK_SKEW = 60;
    private final Issuer expectedIssuer;
    private final JWSKeySelector jwsKeySelector;
    private final JWEKeySelector jweKeySelector;
    private int maxClockSkew = 60;

    public IdTokenValidatorForRs(Issuer expectedIssuer, JWSKeySelector jwsKeySelector, JWEKeySelector jweKeySelector) {
        if (expectedIssuer == null) {
            throw new IllegalArgumentException("The expected token issuer must not be null");
        } else {
            this.expectedIssuer = expectedIssuer;

            this.jwsKeySelector = jwsKeySelector;
            this.jweKeySelector = jweKeySelector;

        }
    }

    public IdTokenValidatorForRs(Issuer expectedIssuer, JWSAlgorithm expectedJWSAlg, JWKSet jwkSet) {
        this(expectedIssuer, (JWSKeySelector) (new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableJWKSet(jwkSet))), (JWEKeySelector) null);
    }

    public IdTokenValidatorForRs(Issuer expectedIssuer, JWSAlgorithm expectedJWSAlg, URL jwkSetURI) {
        this(expectedIssuer, expectedJWSAlg, jwkSetURI, (ResourceRetriever) null);
    }

    public IdTokenValidatorForRs(Issuer expectedIssuer, JWSAlgorithm expectedJWSAlg, URL jwkSetURI, ResourceRetriever resourceRetriever) {
        this(expectedIssuer, (JWSKeySelector) (new JWSVerificationKeySelector(expectedJWSAlg, new RemoteJWKSet(jwkSetURI, resourceRetriever))), (JWEKeySelector) null);
    }

    public IdTokenValidatorForRs(Issuer expectedIssuer, JWSAlgorithm expectedJWSAlg, Secret clientSecret) {
        this(expectedIssuer, (JWSKeySelector) (new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes()))), (JWEKeySelector) null);
    }


    public Issuer getExpectedIssuer() {
        return this.expectedIssuer;
    }

    public JWSKeySelector getJWSKeySelector() {
        return this.jwsKeySelector;
    }

    public JWEKeySelector getJWEKeySelector() {
        return this.jweKeySelector;
    }

    public int getMaxClockSkew() {
        return this.maxClockSkew;
    }

    public void setMaxClockSkew(int maxClockSkew) {
        this.maxClockSkew = maxClockSkew;
    }

    public IdTokenValidatorForRs(Issuer expectedIssuer) {
        this(expectedIssuer, (JWSKeySelector) ((JWSKeySelector) null), (JWEKeySelector) null);
    }

    public IDTokenClaimsSet validate(JWT idToken, Nonce expectedNonce) throws BadJOSEException, JOSEException {
        if (idToken instanceof PlainJWT) {
            return this.validate((PlainJWT) idToken, expectedNonce);
        } else if (idToken instanceof SignedJWT) {
            return this.validate((SignedJWT) idToken, expectedNonce);
        } else if (idToken instanceof EncryptedJWT) {
            return this.validate((EncryptedJWT) idToken, expectedNonce);
        } else {
            throw new JOSEException("Unexpected JWT type: " + idToken.getClass());
        }
    }

    private IDTokenClaimsSet validate(PlainJWT idToken, Nonce expectedNonce) throws BadJOSEException, JOSEException {
        if (this.getJWSKeySelector() != null) {
            throw new BadJWTException("Signed ID token expected");
        } else {
            JWTClaimsSet jwtClaimsSet;
            try {
                jwtClaimsSet = idToken.getJWTClaimsSet();
            } catch (ParseException var5) {
                throw new BadJWTException(var5.getMessage(), var5);
            }

            JWTClaimsSetVerifier<?> claimsVerifier = new IdTokenClaimsVerifierForRs(this.getExpectedIssuer(), expectedNonce, this.getMaxClockSkew());
            claimsVerifier.verify(jwtClaimsSet, null);
            return toIDTokenClaimsSet(jwtClaimsSet);
        }
    }

    private IDTokenClaimsSet validate(SignedJWT idToken, Nonce expectedNonce) throws BadJOSEException, JOSEException {
        if (this.getJWSKeySelector() == null) {
            throw new BadJWTException("Verification of signed JWTs not configured");
        } else {
            ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor();
            jwtProcessor.setJWSKeySelector(this.getJWSKeySelector());
            jwtProcessor.setJWTClaimsSetVerifier(new IdTokenClaimsVerifierForRs(this.getExpectedIssuer(), expectedNonce, this.getMaxClockSkew()));
            JWTClaimsSet jwtClaimsSet = jwtProcessor.process(idToken, null);
            return toIDTokenClaimsSet(jwtClaimsSet);
        }
    }

    private IDTokenClaimsSet validate(EncryptedJWT idToken, Nonce expectedNonce) throws BadJOSEException, JOSEException {
        if (this.getJWEKeySelector() == null) {
            throw new BadJWTException("Decryption of JWTs not configured");
        } else if (this.getJWSKeySelector() == null) {
            throw new BadJWTException("Verification of signed JWTs not configured");
        } else {
            ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor();
            jwtProcessor.setJWSKeySelector(this.getJWSKeySelector());
            jwtProcessor.setJWEKeySelector(this.getJWEKeySelector());
            jwtProcessor.setJWTClaimsSetVerifier(new IdTokenClaimsVerifierForRs(this.getExpectedIssuer(), expectedNonce, this.getMaxClockSkew()));
            JWTClaimsSet jwtClaimsSet = jwtProcessor.process(idToken, null);
            return toIDTokenClaimsSet(jwtClaimsSet);
        }
    }

    private static IDTokenClaimsSet toIDTokenClaimsSet(JWTClaimsSet jwtClaimsSet) throws JOSEException {
        try {
            return new IDTokenClaimsSet(jwtClaimsSet);
        } catch (com.nimbusds.oauth2.sdk.ParseException var2) {
            throw new JOSEException(var2.getMessage(), var2);
        }
    }

    protected static JWSKeySelector createJWSKeySelector(OIDCProviderMetadata opMetadata, OIDCClientInformation clientInfo) throws GeneralException {
        JWSAlgorithm expectedJWSAlg = clientInfo.getOIDCMetadata().getIDTokenJWSAlg();
        if (opMetadata.getIDTokenJWSAlgs() == null) {
            throw new GeneralException("Missing OpenID Provider id_token_signing_alg_values_supported parameter");
        } else if (!opMetadata.getIDTokenJWSAlgs().contains(expectedJWSAlg)) {
            throw new GeneralException("The OpenID Provider doesn't support " + expectedJWSAlg + " ID tokens");
        } else if (Algorithm.NONE.equals(expectedJWSAlg)) {
            return null;
        } else if (!JWSAlgorithm.Family.RSA.contains(expectedJWSAlg) && !JWSAlgorithm.Family.EC.contains(expectedJWSAlg)) {
            if (JWSAlgorithm.Family.HMAC_SHA.contains(expectedJWSAlg)) {
                Secret clientSecret = clientInfo.getSecret();
                if (clientSecret == null) {
                    throw new GeneralException("Missing client secret");
                } else {
                    return new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes()));
                }
            } else {
                throw new GeneralException("Unsupported JWS algorithm: " + expectedJWSAlg);
            }
        } else {
            URL jwkSetURL;
            try {
                jwkSetURL = opMetadata.getJWKSetURI().toURL();
            } catch (MalformedURLException var5) {
                throw new GeneralException("Invalid jwk set URI: " + var5.getMessage(), var5);
            }

            JWKSource jwkSource = new RemoteJWKSet(jwkSetURL);
            return new JWSVerificationKeySelector(expectedJWSAlg, jwkSource);
        }
    }

    protected static JWEKeySelector createJWEKeySelector(OIDCProviderMetadata opMetadata, OIDCClientInformation clientInfo, JWKSource clientJWKSource) throws GeneralException {
        JWEAlgorithm expectedJWEAlg = clientInfo.getOIDCMetadata().getIDTokenJWEAlg();
        EncryptionMethod expectedJWEEnc = clientInfo.getOIDCMetadata().getIDTokenJWEEnc();
        if (expectedJWEAlg == null) {
            return null;
        } else if (expectedJWEEnc == null) {
            throw new GeneralException("Missing required ID token JWE encryption method for " + expectedJWEAlg);
        } else if (opMetadata.getIDTokenJWEAlgs() != null && opMetadata.getIDTokenJWEAlgs().contains(expectedJWEAlg)) {
            if (opMetadata.getIDTokenJWEEncs() != null && opMetadata.getIDTokenJWEEncs().contains(expectedJWEEnc)) {
                return new JWEDecryptionKeySelector(expectedJWEAlg, expectedJWEEnc, clientJWKSource);
            } else {
                throw new GeneralException("The OpenID Provider doesn't support " + expectedJWEAlg + " / " + expectedJWEEnc + " ID tokens");
            }
        } else {
            throw new GeneralException("The OpenID Provider doesn't support " + expectedJWEAlg + " ID tokens");
        }
    }

    public static com.nimbusds.openid.connect.sdk.validators.IDTokenValidator create(OIDCProviderMetadata opMetadata, OIDCClientInformation clientInfo, JWKSource clientJWKSource) throws GeneralException {
        JWSKeySelector jwsKeySelector = createJWSKeySelector(opMetadata, clientInfo);
        JWEKeySelector jweKeySelector = createJWEKeySelector(opMetadata, clientInfo, clientJWKSource);
        return new com.nimbusds.openid.connect.sdk.validators.IDTokenValidator(opMetadata.getIssuer(), clientInfo.getID(), jwsKeySelector, jweKeySelector);
    }

    public static com.nimbusds.openid.connect.sdk.validators.IDTokenValidator create(OIDCProviderMetadata opMetadata, OIDCClientInformation clientInfo) throws GeneralException {
        return create(opMetadata, clientInfo, (JWKSource) null);
    }

    public static com.nimbusds.openid.connect.sdk.validators.IDTokenValidator create(Issuer opIssuer, OIDCClientInformation clientInfo) throws GeneralException, IOException {
        return create(opIssuer, clientInfo, (JWKSource) null, 0, 0);
    }

    public static com.nimbusds.openid.connect.sdk.validators.IDTokenValidator create(Issuer opIssuer, OIDCClientInformation clientInfo, JWKSource clientJWKSource, int connectTimeout, int readTimeout) throws GeneralException, IOException {
        OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(opIssuer, connectTimeout, readTimeout);
        return create(opMetadata, clientInfo, clientJWKSource);
    }
}
