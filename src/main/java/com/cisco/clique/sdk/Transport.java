package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractBlock;
import com.cisco.clique.sdk.chains.AbstractChain;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public interface Transport {

    void putKey(ECKey key) throws Exception;

    ECKey getKey(String pkt) throws Exception;

    void putChain(AbstractChain<? extends AbstractBlock> chain) throws Exception;

    AbstractChain<? extends AbstractBlock> getChain(URI subject) throws Exception;

    void clear();
}
