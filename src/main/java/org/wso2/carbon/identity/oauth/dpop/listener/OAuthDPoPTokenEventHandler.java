package org.wso2.carbon.identity.oauth.dpop.listener;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth.dpop.util.TokenType;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;

/**
 * This class extends AbstractOAuthEventInterceptor and listen to oauth related events. In this class, dpop proof validation
 * will be handle for dpop type token requests
 */
public class OAuthDPoPTokenEventHandler extends AbstractOAuthEventInterceptor {
    private static final Log log = LogFactory.getLog(OAuthDPoPTokenEventHandler.class);

    /**
     * This method handles stores token to session mapping during post token issuance. This is used by authorization
     * grant flow.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the pre token issue event with the DPoP proof for the " +
                    "application: %s", tokenReqDTO.getClientId()));
        }
        String dPopProof=null;
        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
            if (TokenType.DPOP.name().equalsIgnoreCase(httpRequestHeader.getName())){
                dPopProof = httpRequestHeader.getValue()[0];
                break;
            }
        }
        if(!StringUtils.isBlank(dPopProof)){
            /*
             * if the DPoP proof is provided then it will be handle as DPoP token request
             */
            if(!dPoPValidation(dPopProof,tokReqMsgCtx)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP proof validation failed, Application ID: " + tokenReqDTO.getClientId());
                }
                throw new IdentityOAuth2Exception("DPoP validation failed");
            }
        }else{
            /*
             * As there is no DPoP Proof It will be handled as Bearer token request
             */
            if (log.isDebugEnabled()) {
                log.debug("Bearer access token request received from: " + tokenReqDTO.getClientId());
            }
        }
    }
    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the pre token renewal event with the DPoP proof for the " +
                    "application: %s", tokenReqDTO.getClientId()));
        }
        String dPopProof=null;
        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
            if (TokenType.DPOP.name().equalsIgnoreCase(httpRequestHeader.getName())){
                dPopProof = httpRequestHeader.getValue()[0];
                break;
            }
        }
        if(!StringUtils.isBlank(dPopProof)){
            /*
             * if the DPoP proof is provided then it will be handle as DPoP token request
             */
            if(!dPoPValidation(dPopProof,tokReqMsgCtx)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP proof validation failed, Application ID: " + tokenReqDTO.getClientId());
                }
                throw new IdentityOAuth2Exception("DPoP validation failed");
            }
        }else{
            /*
             * As there is no DPoP Proof It will be handled as Bearer token request
             */
            if (log.isDebugEnabled()) {
                log.debug("Bearer access token renewal request received from: " + tokenReqDTO.getClientId());
            }
        }
    }
    @Override
    public boolean isEnabled() {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ||
                Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }
    private boolean dPoPValidation(String dPopProof,OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        /**
         *  2.  Is DPoP header-formed JWT
         *  3. all required claims are contained in the JWT,
         *  4. signature validation using extracted public key (JWK)
         */
        try {
            SignedJWT signedJwt = SignedJWT.parse(dPopProof);
            JWSHeader header = signedJwt.getHeader();
            dPoPHeaderCheck(header);
            return isValidSignature(header.getJWK().toString(),signedJwt, tokReqMsgCtx);

        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Invalid DPoP Header");
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(e.getMessage());
        }
    }

    private boolean isValidSignature(String jwk,SignedJWT signedJwt,OAuthTokenReqMessageContext tokReqMsgCtx)
            throws ParseException, JOSEException {
        JWK parseJwk = JWK.parse(jwk);
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType("DPoP");
        boolean validSignature = false;
        if("EC".equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            ECKey ecKey = (ECKey) parseJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            validSignature =verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey),signedJwt);
            if(validSignature){
                tokenBinding.setBindingReference(computeThumbprintOfECKey(ecKey));
            }
        } else if("RSS".equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))){
            RSAKey rsaKey = (RSAKey) parseJwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            validSignature =verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey),signedJwt);
            if(validSignature){
                tokenBinding.setBindingReference(computeThumbprintOfRSAKey(rsaKey));
            }
        }
        tokReqMsgCtx.setTokenBinding(tokenBinding);
        return validSignature;
    }

    private void dPoPHeaderCheck(JWSHeader header)throws IdentityOAuth2Exception{
        if(header.getJWK()==null){
            throw new IdentityOAuth2Exception("DPoP proof header is not found");
        }
        JWSAlgorithm algorithm = header.getAlgorithm();
        if(algorithm==null){
            throw new IdentityOAuth2Exception("DPoP Proof validation failed, Encryption algorithm is not found");
        }
        if(!"dpop+jwt".equalsIgnoreCase(header.getType().toString())){
            throw new IdentityOAuth2Exception("Invalid DPoP type");
        }
    }
    private String computeThumbprintOfRSAKey(RSAKey rsaKey) throws JOSEException {
        RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
        return rsaKey.computeThumbprint().toString();
    }
    private String computeThumbprintOfECKey(ECKey ecKey) throws JOSEException {
        ECPublicKey ecPublicKey = ecKey.toECPublicKey();
        return ecKey.computeThumbprint().toString();

    }
    private boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt) throws JOSEException {
        return signedJwt.verify(jwsVerifier);
    }
    private void dPoPPayloadCheck(JWTClaimsSet jwtClaimsSet)throws IdentityOAuth2Exception{
        if(jwtClaimsSet==null){
            throw new IdentityOAuth2Exception("DPoP proof payload is invalid");
        }else{
            jwtClaimsSet.getClaim("htm");
            jwtClaimsSet.getClaim("htu");
            jwtClaimsSet.getClaim("iat");
            // payload.toJSONObject().ge
        }
    }
}
