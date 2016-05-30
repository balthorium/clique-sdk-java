package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public class PublicIdentity {

    protected static final ObjectMapper _mapper = JsonMapperFactory.getInstance().createMapper();
    protected Transport _transport;
    protected IdChain _idChain;

    protected PublicIdentity(Transport transport) {
        _transport = transport;
        _idChain = null;
    }

    PublicIdentity(Transport transport, IdChain chain) throws Exception {
        _transport = transport;
        _idChain = chain;
    }

    public PublicIdentity(Transport transport, String serialization) throws Exception {
        _transport = transport;
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

    public String serialize() throws Exception {
        return _mapper.writeValueAsString(serializeAsJson());
    }

    protected ObjectNode serializeAsJson() throws Exception {
        ObjectNode json = _mapper.createObjectNode();
        json.put("acct", _idChain.getSubject().toString());
        return json;
    }

    protected void deserializeFromJson(ObjectNode json) throws Exception {
        _idChain = (IdChain) _transport.getChain(URI.create(json.findPath("acct").asText()));
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PublicIdentity)) {
            return false;
        }
        PublicIdentity that = (PublicIdentity) obj;
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