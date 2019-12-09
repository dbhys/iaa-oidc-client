package com.dbhys.iaa.security;

import com.dbhys.iaa.builder.OidcAuthorizeBasicUrlBuilder;
import com.dbhys.iaa.http.HttpHeader;
import com.dbhys.iaa.http.HttpMethod;
import com.dbhys.iaa.http.MediaType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.dbhys.iaa.http.HttpStatus;
import com.dbhys.iaa.validator.AuthenticationTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Milas on 2019/3/14.
 */
@Component
public class ApiSecurityInterceptor implements ApplicationContextAware, HandlerInterceptor {
    private final static Logger logger = LoggerFactory.getLogger(ApiSecurityInterceptor.class.toString());

    private static String AUTHENTICATION_HEADER = "Authentication";
    private static String BEARER = "BEARER ";

    private ApplicationContext applicationContext;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (request.getMethod().toUpperCase().equals(HttpMethod.OPTIONS.name())) {
            return true;
        }

        final String authenticationHeader = request.getHeader(AUTHENTICATION_HEADER);
        Map<String, String> errorInfo = null;
        if (authenticationHeader != null && authenticationHeader.toUpperCase().startsWith(BEARER)) {
            final String token = authenticationHeader.substring(7);

            try {
                AuthenticationTokenValidator validator = applicationContext.getBean(AuthenticationTokenValidator.class);
                IDTokenClaimsSet idTokenClaimsSet = validator.validate(SignedJWT.parse(token), null);
                AuthenticationHelper.setAuthentication(new Authentication(idTokenClaimsSet.getSubject().getValue()));
                return true;
            } catch (Exception e) {
                logger.error("Invalid token: " + authenticationHeader, e);
                errorInfo = new HashMap();
                errorInfo.put("error", "invalid_token");
                errorInfo.put("error_description", "Invalid token!");
                response.setStatus(HttpStatus.FORBIDDEN.value());
            }
        } else {
            errorInfo = new HashMap();
            errorInfo.put("error", "login_required");
            errorInfo.put("error_description", "You should login at first!");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }
        String state = request.getParameter("state");
        if (state != null) {
            errorInfo.put("state", state);
        }
        OidcAuthorizeBasicUrlBuilder oidcAuthorizeBasicUrlBuilder = applicationContext.getBean(OidcAuthorizeBasicUrlBuilder.class);
        errorInfo.put("error_uri", oidcAuthorizeBasicUrlBuilder.build(state, null, null));
        responseError(request, response, errorInfo);
        return false;
    }

    private void responseError(HttpServletRequest request, HttpServletResponse response, Map<String, String> errorInfo) throws IOException {
        String acceptMediaType = request.getHeader(HttpHeader.ACCEPT);
        if (acceptMediaType == null || acceptMediaType.trim() == "" || acceptMediaType.contains(MediaType.ALL_VALUE)) {
            acceptMediaType = request.getHeader(HttpHeader.CONTENT_TYPE);
        }
        if (acceptMediaType == null || acceptMediaType.trim() == "") {
            acceptMediaType = MediaType.APPLICATION_JSON_UTF8_VALUE;
        }

        response.resetBuffer();
        if (acceptMediaType.contains(MediaType.APPLICATION_JSON_VALUE) || acceptMediaType.contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE)) {
            response.getWriter().write(toJson(errorInfo));
        } else if (acceptMediaType.contains(MediaType.APPLICATION_XML_VALUE)) {
            response.getWriter().write(toXml(errorInfo));
        } else if (acceptMediaType.contains("text/")) {
            response.getWriter().write(toText(errorInfo));
        } else {
            response.setHeader(HttpHeader.WWW_AUTHENTICATE, toText(errorInfo));
        }
        try {
            response.flushBuffer();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {

    }

    private String toJson(Map<String, String> errorInfo) {
        StringBuffer sb = new StringBuffer("{");
        int i = 0;
        for(String key : errorInfo.keySet()){
            if (i == 0) {
                i++;
            } else {
                sb.append(",");
            }
            sb.append("\"").append(key).append("\": \"").append(errorInfo.get(key)).append("\"");
        }
        return sb.append("}").toString();
    }

    /*private String toHtml(String error, String errorDescription) {
        return "{\"error\": \"" + error + "\",\"error_description\" : \"" + errorDescription + "\"}";
    }*/

    private String toXml(Map<String, String> errorInfo) {
        StringBuffer sb = new StringBuffer("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        for(String key : errorInfo.keySet()){
            sb.append("<").append(key).append(">").append(errorInfo.get(key)).append("<").append(key).append(">");
        }
        return sb.toString();
    }

    private String toText(Map<String, String> errorInfo) {
        StringBuffer sb = new StringBuffer();
        int i = 0;
        for(String key : errorInfo.keySet()){
            if (i == 0) {
                i++;
            } else {
                sb.append(",");
            }
            sb.append(key).append("=").append("\"").append(errorInfo.get(key)).append("\"");
        }
        return sb.toString();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
