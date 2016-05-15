package com.cisco.clique.cache;

import com.cisco.clique.sdk.AbstractChain;
import com.cisco.clique.sdk.IdChain;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class ChainCache {
    Map<URI, AbstractChain> _chains;

    public ChainCache() {
        _chains = new HashMap<>();
    }

    public void putChain(IdChain chain) throws Exception {
        _chains.put(chain.getSubject(), chain);
    }

    public AbstractChain getChain(URI subject) {
        return _chains.get(subject);
    }
}

