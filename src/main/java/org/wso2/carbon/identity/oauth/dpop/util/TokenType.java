package org.wso2.carbon.identity.oauth.dpop.util;

public enum TokenType {

    BEARER("Bearer"),
    DPOP("DPoP");

    private String tokenTypeName;

    TokenType(String tokenTypeName) {
        this.tokenTypeName = tokenTypeName;
    }

    @Override
    public String toString() {
        return tokenTypeName;
    }
}
