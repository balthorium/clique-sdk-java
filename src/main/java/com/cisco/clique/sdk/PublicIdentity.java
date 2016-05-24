package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdChain;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public class PublicIdentity {

    URI _acct;
    protected IdChain _idChain;

    protected PublicIdentity() {
    }

    private PublicIdentity(IdChain chain) throws Exception {
        _idChain = chain;
        _acct = _idChain.getSubject();
    }

    public static PublicIdentity get(URI acct) throws Exception {
        if (null == acct) {
            throw new IllegalArgumentException("the acct URI must be non-null");
        }
        IdChain chain = (IdChain) SdkCommon.getTransport().getChain(acct);
        if (null != chain) {
            chain.validate();
            return new PublicIdentity(chain);
        }
        return null;
    }

    public URI getAcct() throws Exception {
        return _acct;
    }

    public ECKey getPublicKey(String pkt) throws Exception {
        ECKey retval = null;
        if (_idChain.containsPkt(pkt)) {
            retval = SdkCommon.getTransport().getKey(pkt);
        }
        return retval;
    }

    public ECKey getActivePublicKey() throws Exception {
        return SdkCommon.getTransport().getKey(_idChain.getActivePkt());
    }

    void resetValidator() {
        _idChain.resetValidator();
    }

    @Override
    public String toString() {
        return _idChain.toString();
    }
}