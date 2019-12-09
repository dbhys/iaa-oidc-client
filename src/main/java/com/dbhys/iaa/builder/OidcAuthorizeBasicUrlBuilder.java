package com.dbhys.iaa.builder;

import com.dbhys.iaa.config.OidcConfig;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.util.StringUtils;

/**
 * Created by wangxd43 on 2019/12/5.
 */
public class OidcAuthorizeBasicUrlBuilder {

    private OidcConfig oidcConfig;

    private OIDCProviderMetadata oidcProviderMetadata;

    public OidcAuthorizeBasicUrlBuilder(OidcConfig oidcConfig, OIDCProviderMetadata oidcProviderMetadata) throws Exception {
        if(oidcConfig == null){
            throw new Exception("");
        }
        if(oidcProviderMetadata == null){
            throw new Exception("");
        }
        this.oidcConfig = oidcConfig;
        this.oidcProviderMetadata = oidcProviderMetadata;
    }

    public String build(String state, String[] scopes, String[] responseTypes){
        if(state == null || state.trim().length() == 0){
            state = new Identifier().getValue();
        }
        if(scopes == null || scopes.length == 0){
            scopes = this.oidcConfig.getScope();
        }
        if(responseTypes == null || responseTypes.length == 0){
            responseTypes = this.oidcConfig.getResponseType();
        }
        String authorizationEndpoint  = this.oidcProviderMetadata.getAuthorizationEndpointURI().toString();
        StringBuffer sb = new StringBuffer(authorizationEndpoint);
        String nonce = new Nonce().getValue();

        if(authorizationEndpoint.contains("?")){
            sb.append("&");
        } else {
            sb.append("?");
        }
        sb.append("&response_type=").append(StringUtils.arrayToDelimitedString(responseTypes, " "));
        sb.append("&scope=").append(StringUtils.arrayToDelimitedString(scopes, " "));
        sb.append("&client_id=").append(this.oidcConfig.getClientId());
        sb.append("&redirect_uri=").append(this.oidcConfig.getRedirectUri()[0]);
        sb.append("&state=").append(state);
        sb.append("&nonce=").append(nonce);
        return sb.toString();
    }
}
