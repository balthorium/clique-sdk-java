package com.cisco.clique.sdk;

import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

/**
 * This interface defines a southbound interface on which the Clique SDK depends for basic operation.  It includes
 * methods for getting and setting keys, as well as for getting and setting chains.  The implementing class is
 * responsible for managing local cache and for handling cache-misses.
 */
public interface Transport {

    /**
     * Put a given key to the Clique transport.
     *
     * @param key The key to be shared.
     * @throws Exception On failure.
     */
    void putKey(ECKey key) throws Exception;

    /**
     * Retrieve a key with the given public key thumbprint from the Clique transport.
     *
     * @param pkt The thumbprint of a public key to be retrieved.
     * @return The key, or null if not found.
     * @throws Exception On failure.
     */
    ECKey getKey(String pkt) throws Exception;

    /**
     * Put a given chain to the Clique transport.
     *
     * @param chain The chain to be shared.
     * @throws Exception On failure.
     */
    void putChain(AbstractChain chain) throws Exception;

    /**
     * Retrieve a chain with the given subject URI.
     *
     * @param subject The subject URI on which to match.
     * @return The matching chain, or null if not found.
     * @throws Exception On failure.
     */
    AbstractChain getChain(URI subject) throws Exception;
}
