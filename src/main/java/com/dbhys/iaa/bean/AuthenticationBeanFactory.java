package com.dbhys.iaa.bean;

import com.dbhys.iaa.config.AuthenticationResourceServerConfig;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.dbhys.iaa.validator.AuthenticationTokenValidator;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Created by Milas on 2019/3/18.
 */
@Component
public class AuthenticationBeanFactory implements ApplicationContextAware, InitializingBean {

    @Autowired
    private AuthenticationResourceServerConfig config;

    private ApplicationContext applicationContext;

    private OIDCProviderMetadata oidcProviderMetadata;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (config == null || config.getIssuer() == null) {
            throw new Error("Resource server config and property 'issuer' can't be null!");
        }
        try {
            //将applicationContext转换为ConfigurableApplicationContext
            ConfigurableApplicationContext configurableApplicationContext = (ConfigurableApplicationContext) this.applicationContext;

            // 获取bean工厂并转换为ConfigurableListableBeanFactory
            ConfigurableListableBeanFactory configurableListableBeanFactory = configurableApplicationContext.getBeanFactory();

            this.oidcProviderMetadata = OIDCProviderMetadata.resolve(new Issuer(config.getIssuer()), config.getConnectTimeout(), config.getReadTimeout());
            JWKSetCache jwkSetCache = new DefaultJWKSetCache(config.getLifeSpan(), TimeUnit.HOURS);
            ResourceRetriever resourceRetriever = new DefaultResourceRetriever(this.config.getConnectTimeout(), this.config.getReadTimeout());
            JWKSource jwkSource = new RemoteJWKSet(this.oidcProviderMetadata.getJWKSetURI().toURL(), resourceRetriever, jwkSetCache);
            JWSKeySelector jwsKeySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource);
            AuthenticationTokenValidator authenticationTokenValidator = new AuthenticationTokenValidator(new Issuer(this.config.getIssuer()), new ClientID(this.config.getClientId()), jwsKeySelector, null);

            configurableListableBeanFactory.registerSingleton("oidcProviderMetadata", oidcProviderMetadata);
            configurableListableBeanFactory.registerSingleton("jwkSetCache", jwkSetCache);
            configurableListableBeanFactory.registerSingleton("resourceRetriever", resourceRetriever);
            configurableListableBeanFactory.registerSingleton("jwkSource", jwkSource);
            configurableListableBeanFactory.registerSingleton("jwsKeySelector", jwsKeySelector);
            configurableListableBeanFactory.registerSingleton("authenticationTokenValidator", authenticationTokenValidator);
        } catch (GeneralException e) {
            e.printStackTrace();
            throw new Error("Init authentication config and resource error.");
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("Init authentication config and resource error.");
        }
    }


    public OIDCProviderMetadata getOidcProviderMetadata() {
        return this.oidcProviderMetadata;
    }


}
