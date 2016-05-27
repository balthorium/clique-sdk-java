package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdChain;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.io.IOException;
import java.net.URI;

public class PublicIdentity {

    URI _acct;
    protected IdChain _idChain;
    protected static final ObjectMapper _mapper = SdkCommon.createMapper();

    protected PublicIdentity() {
    }

    protected PublicIdentity(String serialization) throws Exception {
        deserializeFromJson((ObjectNode) _mapper.readTree(serialization));
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

    protected ObjectNode serializeAsJson() throws Exception {
        ObjectNode json = _mapper.createObjectNode();
        json.put("acct", _acct.toString());
        return json;
    }

    protected void deserializeFromJson(ObjectNode json) throws Exception {
        _acct = URI.create(json.findPath("acct").asText());
    }

    /**
     * Generates a JSON serialization of this object which can be later used to recreate the object.
     * @return A JSON serialization which can be passed to the constructure to recreate the object.
     * @throws Exception On error.
     */
    public String serialize() throws Exception {
        return _mapper.writeValueAsString(serializeAsJson());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PublicIdentity)) return false;
        PublicIdentity that = (PublicIdentity) o;
        return _acct.equals(that._acct);
    }

    @Override
    public int hashCode() {
        return _acct.hashCode();
    }

    @Override
    public String toString() {
        return _idChain.toString();
    }
}