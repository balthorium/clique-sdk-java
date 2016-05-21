package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;

public class PublicIdentity {

    protected static final ObjectMapper _mapper = SdkUtils.createMapper();
    protected URI _acct;

    PublicIdentity() {
    }

    public PublicIdentity(URI acct) {
        if (null == acct) {
            throw new IllegalArgumentException();
        }
        _acct = acct;
    }

    public URI getAcct() {
        return _acct;
    }

    public boolean hasPrivilege(URI resourceUri, String privilege) throws Exception {
        AuthChain authChain = (AuthChain) SdkUtils.getPublicRepo().getChain(resourceUri);
        return authChain.hasPrivilege(_acct, privilege);
    }
}