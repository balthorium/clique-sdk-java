package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractBlock;
import com.cisco.clique.sdk.chains.AbstractChain;
import com.cisco.clique.sdk.chains.AuthBlock;
import com.cisco.clique.sdk.chains.IdBlock;
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
    Map<URI, AbstractChain<IdBlock>> _idChains;
    Map<URI, AbstractChain<AuthBlock>> _authChains;

    public MemoryTransport() {
        _keys = new HashMap<>();
        _idChains = new HashMap<>();
        _authChains = new HashMap<>();
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
    public void putIdChain(AbstractChain<IdBlock> chain) throws Exception {
        _idChains.put(chain.getSubject(), chain);
    }

    @Override
    public AbstractChain<IdBlock> getIdChain(AbstractValidator<IdBlock> validator, URI uri) throws Exception {
        return _idChains.get(uri);
    }

    @Override
    public void putAuthChain(AbstractChain<AuthBlock> chain) throws Exception {
        _authChains.put(chain.getSubject(), chain);
    }

    @Override
    public AbstractChain<AuthBlock> getAuthChain(AbstractValidator<AuthBlock> validator, URI uri) throws Exception {
        return _authChains.get(uri);
    }

    @Override
    public void clear() {
        _keys.clear();
        _idChains.clear();
        _authChains.clear();
    }

    @Override
    public String toString() {
        try {
            ObjectNode objectNode = _mapper.createObjectNode();
            ArrayNode arrayNode = objectNode.putArray("keys");
            for (ECKey key : _keys.values()) {
                arrayNode.add(_mapper.readTree(key.toPublicJWK().toJSONString()));
            }
            arrayNode = objectNode.putArray("idChains");
            for (AbstractChain chain : _idChains.values()) {
                arrayNode.add(_mapper.readTree(chain.toString()));
            }
            arrayNode = objectNode.putArray("authChains");
            for (AbstractChain chain : _authChains.values()) {
                arrayNode.add(_mapper.readTree(chain.toString()));
            }
            return _mapper.writerWithDefaultPrettyPrinter().writeValueAsString(objectNode);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }
}
