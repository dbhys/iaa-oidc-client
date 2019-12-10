package com.dbhys.iaa.validator;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;

import java.text.ParseException;
import java.util.Date;

/**
 * Created by wangxd43 on 2019/12/5.
 *
 * ClaimsVerifier for resource server
 */
public class IdTokenClaimsVerifierForRs implements JWTClaimsSetVerifier, ClockSkewAware {
    private final Issuer expectedIssuer;
    private final Nonce expectedNonce;
    private int maxClockSkew;

    public IdTokenClaimsVerifierForRs(Issuer issuer, Nonce nonce, int maxClockSkew) {
        if(issuer == null) {
            throw new IllegalArgumentException("The expected ID token issuer must not be null");
        } else {
            this.expectedIssuer = issuer;

                this.expectedNonce = nonce;
                this.setMaxClockSkew(maxClockSkew);

        }
    }

    public Issuer getExpectedIssuer() {
        return this.expectedIssuer;
    }

    public Nonce getExpectedNonce() {
        return this.expectedNonce;
    }

    public int getMaxClockSkew() {
        return this.maxClockSkew;
    }

    public void setMaxClockSkew(int maxClockSkew) {
        if(maxClockSkew < 0) {
            throw new IllegalArgumentException("The max clock skew must be zero or positive");
        } else {
            this.maxClockSkew = maxClockSkew;
        }
    }

    public void verify(JWTClaimsSet claimsSet, SecurityContext ctx) throws BadJWTException {
        String tokenIssuer = claimsSet.getIssuer();
        if(tokenIssuer == null) {
            throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
        } else if(!this.expectedIssuer.getValue().equals(tokenIssuer)) {
            throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
        } else if(claimsSet.getSubject() == null) {
            throw BadJWTExceptions.MISSING_SUB_CLAIM_EXCEPTION;
        } else {
            Date exp = claimsSet.getExpirationTime();
            if(exp == null) {
                throw BadJWTExceptions.MISSING_EXP_CLAIM_EXCEPTION;
            } else {
                Date iat = claimsSet.getIssueTime();
                if(iat == null) {
                    throw BadJWTExceptions.MISSING_IAT_CLAIM_EXCEPTION;
                } else {
                    Date nowRef = new Date();
                    if(!DateUtils.isAfter(exp, nowRef, (long)this.maxClockSkew)) {
                        throw BadJWTExceptions.EXPIRED_EXCEPTION;
                    } else if(!DateUtils.isBefore(iat, nowRef, (long)this.maxClockSkew)) {
                        throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION;
                    } else {
                        if(this.expectedNonce != null) {
                            String tokenNonce;
                            try {
                                tokenNonce = claimsSet.getStringClaim("nonce");
                            } catch (ParseException var10) {
                                throw new BadJWTException("Invalid JWT nonce (nonce) claim: " + var10.getMessage());
                            }

                            if(tokenNonce == null) {
                                throw BadJWTExceptions.MISSING_NONCE_CLAIM_EXCEPTION;
                            }

                            if(!this.expectedNonce.getValue().equals(tokenNonce)) {
                                throw new BadJWTException("Unexpected JWT nonce (nonce) claim: " + tokenNonce);
                            }
                        }

                    }
                }
            }
        }
    }

}
