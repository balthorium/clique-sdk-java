package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdChain;
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
public class Identity extends PublicIdentity {

    private Identity _issuer;
    private Map<String, ECKey> _keyPairs;
    protected static final ObjectMapper _mapper = SdkCommon.createMapper();


    /**
     * Creates a new self-asserted identity and initializes it with a new key pair.
     *
     * @param acct The unique URI to associate with the identity.
     * @throws Exception On failure.
     */
    public Identity(URI acct) throws Exception {
        this(null, acct);
    }

    /**
     * Creates a new mint-asserted identity and initializes it with a new key pair.
     *
     * @param mint The identity of the mint that is asserting this new identity.
     * @param acct The unique URI to associate with the identity.
     * @throws Exception On failure.
     */
    public Identity(Identity mint, URI acct) throws Exception {
        _idChain = (IdChain) SdkCommon.getTransport().getChain(acct);
        if (null != _idChain) {
            throw new IllegalArgumentException("an identity chain already exists for the given URI");
        }
        _acct = acct;
        _issuer = (null != mint) ? mint : this;
        _keyPairs = new HashMap<>();
        rotateKeyPair();
    }

    /**
     * Instantiates a new Identity object based on identity information provided in a parsed JSON document.
     *
     * @param node The parsed JSON document from which to extract identity information.
     * @throws Exception On failure.
     */
    public Identity(JsonNode node) throws Exception {
        if (null == node) {
            throw new IllegalArgumentException("node must be non-null");
        }
        _acct = URI.create(node.findPath("acct").asText());
        _keyPairs = new HashMap<>();
        JsonNode keys = node.findPath("keys");
        if (null != keys && keys instanceof ArrayNode) {
            for (JsonNode jwk : keys) {
                ECKey key = (ECKey) JWK.parse(_mapper.writeValueAsString(jwk));
                storeKeyPair(key);
                SdkCommon.getTransport().putKey(key.toPublicJWK());
            }
        }
    }

    /**
     * Adds the given key pair to this identity's keychain.  Also interns the public key to the transport.
     *
     * @param key The key to be added to this identity's keychain.
     * @throws Exception On failure.
     */
    void storeKeyPair(ECKey key) throws Exception {
        if (null == key) {
            throw new IllegalArgumentException("key must be non-null");
        }
        _keyPairs.put(key.toPublicJWK().computeThumbprint().toString(), key);
    }

    /**
     * Creates a new asymmetric key pair and adds it to this identity's keychain.
     *
     * @return The new active key resulting from rotation.
     * @throws Exception On failure.
     */
    public ECKey rotateKeyPair() throws Exception {
        Transport transport = SdkCommon.getTransport();

        // generate a new key pair
        ECKey.Curve crv = ECKey.Curve.P_256;
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA");
        gen.initialize(crv.toECParameterSpec());
        KeyPair pair = gen.generateKeyPair();
        ECKey key = new ECKey.Builder(crv, (ECPublicKey) pair.getPublic())
                .privateKey((ECPrivateKey) pair.getPrivate())
                .build();

        // store key pair to local key chain
        storeKeyPair(key);

        // publish public key to transport
        SdkCommon.getTransport().putKey(key.toPublicJWK());

        // append a new block to this identity's IdChain
        if (null != _idChain) {

            // append to exist IdChain (basic rotation)
            _idChain.newBuilder()
                    .setIssuer(_idChain.getSubject())
                    .setIssuerKey(getActiveKeyPair())
                    .setSubject(_idChain.getSubject())
                    .setSubjectPubKey(key.toPublicJWK())
                    .build();
        } else {

            // create genesis block (new chain)
            _idChain = new IdChain();
            _idChain.newBuilder()
                    .setIssuer(_issuer.getAcct())
                    .setIssuerKey(!_acct.equals(_issuer.getAcct()) ? _issuer.getActiveKeyPair() : key)
                    .setSubject(_acct)
                    .setSubjectPubKey(key.toPublicJWK())
                    .build();
        }

        // publish the new version of this identity's IdChain
        transport.putChain(_idChain);

        return key;
    }

    /**
     * Given a public key thumbprint (pkt) returns the matching full key pair, if present in this identity's keychain.
     *
     * @param pkt The public key thumbprint being requested.
     * @return The full public/private key pair matching the given pkt.
     */
    public ECKey getKeyPair(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException("pkt must be non-null");
        }
        return _keyPairs.get(pkt);
    }

    /**
     * Returns the currently active key pair for this identity, as determined by consulting the identity's id chain
     * as currently represented in the local clique net.
     *
     * @return This identity's currently active key pair.
     * @throws Exception On failure.
     */
    public ECKey getActiveKeyPair() throws Exception {
        ECKey retval = null;
        IdChain chain = (IdChain) SdkCommon.getTransport().getChain(_acct);
        if (null != chain) {
            retval = getKeyPair(chain.getActivePkt());
        }
        return retval;
    }

    @Override
    public String toString() {
        String retval = null;
        try {
            ObjectNode identity = _mapper.createObjectNode();
            identity.set("chain", _mapper.readTree(_idChain.toString()));
            ArrayNode keys = identity.putArray("keys");
            for (ECKey key : _keyPairs.values()) {
                ObjectNode keyNode = (ObjectNode) _mapper.readTree(key.toJSONString());
                keyNode.put("kid", key.computeThumbprint().toString());
                keys.add(keyNode);
            }
            retval = _mapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(identity);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return retval;
    }
}