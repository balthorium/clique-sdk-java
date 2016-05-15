package com.cisco.clique.cache;

import com.cisco.clique.sdk.SdkUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.nimbusds.jose.jwk.ECKey;

import java.util.HashMap;
import java.util.Map;

public class PublicKeyCache {
    Map<String, ECKey> _keys = new HashMap<>();
    private static final ObjectMapper _mapper = SdkUtils.createMapper();

    public PublicKeyCache() {
    }

    public void putKey(ECKey key) throws Exception {
        _keys.put(key.toPublicJWK().computeThumbprint().toString(), key);
    }

    public ECKey getKey(String pkt) {
        return _keys.get(pkt);
    }

    public String toString() {
        String retval = null;
        try {
            ArrayNode arrayNode = _mapper.createArrayNode();
            for (ECKey key : _keys.values()) {
                arrayNode.add(_mapper.readTree(key.toPublicJWK().toJSONString()));
            }
            retval = _mapper.writerWithDefaultPrettyPrinter().writeValueAsString(arrayNode);
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
        return retval;
    }
}

