package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AuthChain;
import com.cisco.clique.sdk.chains.IdChain;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public class PublicIdentity {

    protected URI _acct;
    protected IdChain _idChain;

    PublicIdentity() {
    }

    public PublicIdentity(URI acct) throws Exception {
        if (null == acct) {
            throw new IllegalArgumentException("the acct URI must be non-null");
        }
        _acct = acct;
        _idChain = (IdChain) SdkUtils.getTransport().getChain(_acct);
        if (null != _idChain) {
            _idChain.validate();
        }
    }

    public URI getAcct() {
        return _acct;
    }

    public ECKey getPublicKey(String pkt) throws Exception {
        ECKey retval = null;
        if (_idChain.containsPkt(pkt)) {
            retval = SdkUtils.getTransport().getKey(pkt);
        }
        return retval;
    }

    public ECKey getActivePublicKey() throws Exception {
        return SdkUtils.getTransport().getKey(_idChain.getActivePkt());
    }

    public boolean hasPrivilege(URI resourceUri, String privilege) throws Exception {
        AuthChain authChain = (AuthChain) SdkUtils.getTransport().getChain(resourceUri);
        return authChain.hasPrivilege(_acct, privilege);
    }

    public String getHash() throws Exception {
        return _idChain.getHash();
    }
}