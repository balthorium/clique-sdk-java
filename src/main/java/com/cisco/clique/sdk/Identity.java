package com.cisco.clique.sdk;

import com.cisco.clique.cache.CliqueCache;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents an identity, including the identity's unique URI, and a collection of it's key pairs.
 */
public class Identity {

    private URI _acct;
    private Map<String, ECKey> _keys;
    CliqueCache _cc;
    private static final ObjectMapper _mapper = SdkUtils.createMapper();

    /**
     * Creates a new identity and initializes it with a new key pair.
     *
     * @param cc   The local clique cache.
     * @param acct The unique URI to associate with the identity.
     * @throws Exception
     */
    public Identity(CliqueCache cc, URI acct) throws Exception {
        if (null == cc || null == acct) {
            throw new IllegalArgumentException();
        }
        _cc = cc;
        _acct = acct;
        _keys = new HashMap<>();
        newKey();
    }

    /**
     * Instantiates a new Identity object based on identity information provided in a parsed JSON document.
     *
     * @param cc   The local clique cache.
     * @param node The parsed JSON document from which to extract identity information.
     * @throws Exception
     */
    public Identity(CliqueCache cc, JsonNode node) throws Exception {
        if (null == cc || null == node) {
            throw new IllegalArgumentException();
        }
        _cc = cc;
        _acct = URI.create(node.findPath("acct").asText());
        _keys = new HashMap<>();
        JsonNode keys = node.findPath("keys");
        if (null != keys && keys instanceof ArrayNode) {
            for (JsonNode jwk : keys) {
                addKey((ECKey) JWK.parse(_mapper.writeValueAsString(jwk)));
            }
        }
    }

    /**
     * Returns a JSON object representing this identity (including private key material - so be careful).
     *
     * @return A JSON object representing this identity.
     * @throws Exception
     */
    public ObjectNode toJson() throws Exception {
        ObjectNode identity = _mapper.createObjectNode();
        identity.put("acct", _acct.toString());
        ArrayNode keys = identity.putArray("keys");
        for (ECKey key : _keys.values()) {
            keys.add(_mapper.readTree(key.toJSONString()));
        }
        return identity;
    }

    /**
     * Adds the given key to this identity's keychain.  Also interns the public key to the clique cache.
     *
     * @param key The key to be added to this identity's keychain.
     * @throws Exception
     */
    void addKey(ECKey key) throws Exception {
        if (null == key) {
            throw new IllegalArgumentException();
        }
        _keys.put(key.toPublicJWK().computeThumbprint().toString(), key);
        _cc.getPublicKeyCache().putKey(key.toPublicJWK());
    }

    /**
     * Creates a new asymmetric key pair and adds it to this identity's keychain.
     *
     * @return The newly created asymmetric key pair.
     * @throws Exception
     */
    public ECKey newKey() throws Exception {
        ECKey.Curve crv = ECKey.Curve.P_256;
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA");
        gen.initialize(crv.toECParameterSpec());
        KeyPair pair = gen.generateKeyPair();
        ECKey key = new ECKey.Builder(crv, (ECPublicKey) pair.getPublic())
                .privateKey((ECPrivateKey) pair.getPrivate())
                .build();
        addKey(key);
        return key;
    }

    /**
     * Returns the unqiue URI of this identity.
     *
     * @return The unique URI of this identity.
     */
    public URI getAcct() {
        return _acct;
    }

    /**
     * Given a public key thumbprint (pkt) returns the matching full key pair, if present in this identity's keychain.
     *
     * @param pkt The public key thumbprint being requested.
     * @return The full public/private key pair matching the given pkt.
     */
    public ECKey getKey(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException();
        }
        return _keys.get(pkt);
    }

    /**
     * Returns the currently active key pair for this identity, as determined by consulting the identity's id chain
     * as currently represented in the local clique cache.
     *
     * @return This identity's currently active key pair.
     * @throws Exception
     */
    public ECKey getActiveKey() throws Exception {
        return getKey(((IdChain) _cc.getChainCache().getChain(_acct)).getActivePkt());
    }

    @Override
    public String toString() {
        String retval = null;
        try {
            retval = _mapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(toJson());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return retval;
    }
}