package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractChain;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public interface Transport {

    void putKey(ECKey key) throws Exception;

    ECKey getKey(String pkt) throws Exception;

    void putChain(AbstractChain chain) throws Exception;

    AbstractChain getChain(URI subject) throws Exception;
}
