package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdBlock;
import com.cisco.clique.sdk.chains.IdChain;
import com.cisco.clique.sdk.validation.AbstractValidator;
import com.cisco.clique.sdk.validation.IdBlockValidator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public class PublicIdentity {

    protected static final ObjectMapper _mapper = JsonMapperFactory.getInstance().createMapper();
    protected IdChain _idChain;

    PublicIdentity() {
    }

    PublicIdentity(IdChain chain) throws Exception {
        _idChain = chain;
    }

    public PublicIdentity(AbstractValidator<IdBlock> validator, String serialization) throws Exception {
        deserializeFromJson(validator, (ObjectNode) _mapper.readTree(serialization));
    }

    public URI getAcct() throws Exception {
        return _idChain.getSubject();
    }

    public ECKey getPublicKey(String pkt) throws Exception {
        ECKey retval = null;
        if (_idChain.containsPkt(pkt)) {
            retval = _idChain.getValidator().getTransport().getKey(pkt);
        }
        return retval;
    }

    public ECKey getActivePublicKey() throws Exception {
        return _idChain.getValidator().getTransport().getKey(_idChain.getActivePkt());
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

    protected void deserializeFromJson(AbstractValidator<IdBlock> validator, ObjectNode json) throws Exception {
        _idChain = (IdChain) validator.getTransport().getIdChain(validator, URI.create(json.findPath("acct").asText()));
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