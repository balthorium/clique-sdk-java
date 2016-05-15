package com.cisco.clique.cache;

public class CliqueCache {
    private PublicKeyCache _publicKeyCache;
    private ChainCache _chainCache;

    public CliqueCache() {
        _publicKeyCache = new PublicKeyCache();
        _chainCache = new ChainCache();
    }

    public PublicKeyCache getPublicKeyCache() {
        return _publicKeyCache;
    }

    protected void setPublicKeyCache(PublicKeyCache publicKeyCache) {
        _publicKeyCache = publicKeyCache;
    }

    public ChainCache getChainCache() {
        return _chainCache;
    }

    protected void setChainCache(ChainCache idChainStore) {
        _chainCache = idChainStore;
    }
}
