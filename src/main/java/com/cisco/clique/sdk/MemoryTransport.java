package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractBlock;
import com.cisco.clique.sdk.chains.AbstractChain;
import com.cisco.clique.sdk.validation.AbstractValidator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class MemoryTransport implements Transport {

    protected static final ObjectMapper _mapper = JsonMapperFactory.getInstance().createMapper();
    Map<String, ECKey> _keys;
    Map<URI, AbstractChain<? extends AbstractBlock>> _chains;

    public MemoryTransport() {
        _keys = new HashMap<>();
        _chains = new HashMap<>();
    }

    @Override
    public void putKey(ECKey key) throws Exception {
        _keys.put(key.toPublicJWK().computeThumbprint().toString(), key);
    }

    @Override
    public ECKey getKey(String pkt) {
        return _keys.get(pkt);
    }

    @Override
    public void putChain(AbstractChain<? extends AbstractBlock> chain) throws Exception {
        _chains.put(chain.getSubject(), chain);
    }

    @Override
    public AbstractChain<? extends AbstractBlock> getChain(AbstractValidator validator, URI subject) {
        return _chains.get(subject);
    }

    @Override
    public void clear() {
        _keys.clear();
        _chains.clear();
    }

    @Override
    public String toString() {
        try {
            ObjectNode objectNode = _mapper.createObjectNode();
            ArrayNode arrayNode = objectNode.putArray("keys");
            for (ECKey key : _keys.values()) {
                arrayNode.add(_mapper.readTree(key.toPublicJWK().toJSONString()));
            }
            arrayNode = objectNode.putArray("chains");
            for (AbstractChain chain : _chains.values()) {
                arrayNode.add(_mapper.readTree(chain.toString()));
            }
            return _mapper.writerWithDefaultPrettyPrinter().writeValueAsString(objectNode);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }
}
