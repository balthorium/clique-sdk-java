package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractChain;
import com.cisco.clique.sdk.chains.AuthBlock;
import com.cisco.clique.sdk.chains.IdBlock;
import com.cisco.clique.sdk.validation.AbstractValidator;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

public interface Transport {

    void putKey(ECKey key) throws Exception;

    ECKey getKey(String pkt) throws Exception;

    void putIdChain(AbstractChain<IdBlock> chain) throws Exception;

    AbstractChain<IdBlock> getIdChain(AbstractValidator<IdBlock> validator, URI uri) throws Exception;

    void putAuthChain(AbstractChain<AuthBlock> chain) throws Exception;

    AbstractChain<AuthBlock> getAuthChain(AbstractValidator<AuthBlock> validator, URI uri) throws Exception;

    void clear();
}
