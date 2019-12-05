package com.dbhys.iaa.validator;

import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
/**
 * Authentication token validator.
 * Created by Milas on 2019/3/19.
 */
public class AuthenticationTokenValidator extends IDTokenValidator{

    /**
     * Creates a new abstract JWT validator.
     *
     * @param expectedIssuer The expected token issuer (OpenID Provider).
     *                       Must not be {@code null}.
     * @param clientID       The client ID. Must not be {@code null}.
     * @param jwsKeySelector The key selector for JWS verification,
     *                       {@code null} if unsecured (plain) tokens are
     *                       expected.
     * @param jweKeySelector The key selector for JWE decryption,
     *                       {@code null} if encrypted tokens are not
     */
    public AuthenticationTokenValidator(Issuer expectedIssuer, ClientID clientID, JWSKeySelector jwsKeySelector, JWEKeySelector jweKeySelector) {
        super(expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
    }

}
