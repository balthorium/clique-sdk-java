package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public class PublicIdentity {

    protected IdChain _idChain;
    protected Transport _transport;
    protected static final ObjectMapper _mapper = SdkCommon.createMapper();

    protected PublicIdentity() {
        _idChain = null;
        _transport = SdkCommon.getTransport();
    }

    public PublicIdentity(URI acct) throws Exception {
        this();
        if (null == acct) {
            throw new IllegalArgumentException("the acct URI must be non-null");
        }
        IdChain chain = (IdChain) _transport.getChain(acct);
        if (null == chain) {
            throw new IllegalArgumentException("the acct URI has no published identity chain");
        }
        chain.validate();
        _idChain = chain;
    }

    public PublicIdentity(String serialization) throws Exception {
        this();
        deserializeFromJson((ObjectNode) _mapper.readTree(serialization));
    }

    public URI getAcct() throws Exception {
        return _idChain.getSubject();
    }

    public ECKey getPublicKey(String pkt) throws Exception {
        ECKey retval = null;
        if (_idChain.containsPkt(pkt)) {
            retval = _transport.getKey(pkt);
        }
        return retval;
    }

    public ECKey getActivePublicKey() throws Exception {
        return _transport.getKey(_idChain.getActivePkt());
    }

    void resetValidator() {
        _idChain.resetValidator();
    }

    protected ObjectNode serializeAsJson() throws Exception {
        ObjectNode json = _mapper.createObjectNode();
        json.put("acct", _idChain.getSubject().toString());
        return json;
    }

    protected void deserializeFromJson(ObjectNode json) throws Exception {
        _idChain = (IdChain) _transport.getChain(URI.create(json.findPath("acct").asText()));
    }

    public String serialize() throws Exception {
        return _mapper.writeValueAsString(serializeAsJson());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PublicIdentity)) return false;
        PublicIdentity that = (PublicIdentity) o;
        return _idChain.equals(that._idChain);
    }

    @Override
    public int hashCode() {
        return _idChain.hashCode();
    }

    @Override
    public String toString() {
        return _idChain.toString();
    }
}