package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * This is a simple implementation of the Transport interface that does nothing more than maintain a local
 * cache of public keys and chains.  This is an in-memory transport and does not interact with any other services or
 * peers over the network.  This is mainly used for simple demonstrations and testing.
 */
public class TransportLocal implements Transport {

    Map<String, ECKey> _keys;
    Map<URI, AbstractChain> _chains;

    public TransportLocal() {
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
    public void putChain(AbstractChain chain) throws Exception {
        _chains.put(chain.getSubject(), chain);
    }

    @Override
    public AbstractChain getChain(URI subject) {
        return _chains.get(subject);
    }

    @Override
    public String toString() {
        try {
            ObjectMapper mapper = SdkCommon.createMapper();
            ArrayNode arrayNode = mapper.createArrayNode();
            for (ECKey key : _keys.values()) {
                arrayNode.add(mapper.readTree(key.toPublicJWK().toJSONString()));
            }
            for (AbstractChain chain : _chains.values()) {
                arrayNode.add(mapper.readTree(chain.toString()));
            }
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(arrayNode);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }
}
