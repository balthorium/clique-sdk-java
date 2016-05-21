package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.Set;

/**
 * Represents an identity, including the identity's unique URI, and a collection of it's key pairs.
 */
public class Identity extends PublicIdentity {

    private Map<String, ECKey> _keyPairs;

    /**
     * Creates a new identity and initializes it with a new key pair.
     *
     * @param acct The unique URI to associate with the identity.
     * @throws Exception On failure.
     */
    public Identity(URI acct) throws Exception {
        super(acct);
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
            throw new IllegalArgumentException();
        }
        _acct = URI.create(node.findPath("acct").asText());
        _keyPairs = new HashMap<>();
        JsonNode keys = node.findPath("keys");
        if (null != keys && keys instanceof ArrayNode) {
            for (JsonNode jwk : keys) {
                ECKey key = (ECKey) JWK.parse(_mapper.writeValueAsString(jwk));
                storeKeyPair(key);
                SdkUtils.getTransport().putKey(key.toPublicJWK());
            }
        }
    }

    public PolicyBuilder createPolicy(URI resourceUri) throws Exception {
        return new PolicyBuilder(new AuthChain(), resourceUri);
    }

    public PolicyBuilder updatePolicy(URI resourceUri) throws Exception {
        AuthChain authChain = (AuthChain) SdkUtils.getTransport().getChain(resourceUri);
        return new PolicyBuilder(authChain);
    }

    /**
     * Returns a JSON object representing this identity (including private key material - so be careful).
     *
     * @return A JSON object representing this identity.
     * @throws Exception On failure.
     */
    public ObjectNode toJson() throws Exception {
        ObjectNode identity = _mapper.createObjectNode();
        identity.put("acct", _acct.toString());
        ArrayNode keys = identity.putArray("keys");
        for (ECKey key : _keyPairs.values()) {
            keys.add(_mapper.readTree(key.toJSONString()));
        }
        return identity;
    }

    /**
     * Adds the given key pair to this identity's keychain.  Also interns the public key to the transport.
     *
     * @param key The key to be added to this identity's keychain.
     * @throws Exception On failure.
     */
    void storeKeyPair(ECKey key) throws Exception {
        if (null == key) {
            throw new IllegalArgumentException();
        }
        _keyPairs.put(key.toPublicJWK().computeThumbprint().toString(), key);
    }

    /**
     * Creates a new asymmetric key pair and adds it to this identity's keychain.
     *
     * @throws Exception On failure.
     */
    public void rotateKeyPair() throws Exception {
        Transport transport = SdkUtils.getTransport();
        Set<String> trustRoots = SdkUtils.getTrustRoots();

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
        SdkUtils.getTransport().putKey(key.toPublicJWK());

        // append a new block to this identity's IdChain
        IdChain idChain = (IdChain) transport.getChain(_acct);
        if (null != idChain) {

            // append to existing IdChain
            idChain.newBlockBuilder()
                    .setIssuer(_acct)
                    .setIssuerKey(getActiveKeyPair())
                    .setSubject(_acct)
                    .setSubjectPubKey(key.toPublicJWK())
                    .build();
        } else {

            // create a new self-asserted IdChain
            idChain = new IdChain();
            idChain.newBlockBuilder()
                    .setIssuer(_acct)
                    .setIssuerKey(key)
                    .setSubject(_acct)
                    .setSubjectPubKey(key.toPublicJWK())
                    .build();
        }

        // publish the new version of this identity's IdChain
        transport.putChain(idChain);
    }

    /**
     * Given a public key thumbprint (pkt) returns the matching full key pair, if present in this identity's keychain.
     *
     * @param pkt The public key thumbprint being requested.
     * @return The full public/private key pair matching the given pkt.
     */
    public ECKey getKeyPair(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException();
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
        IdChain chain = (IdChain) SdkUtils.getTransport().getChain(_acct);
        if (null != chain) {
            retval = getKeyPair(chain.getActivePkt());
        }
        return retval;
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

    public class PolicyBuilder {
        private AuthChain _authChain;
        private AuthBlock.Builder _blockBuilder;

        PolicyBuilder(AuthChain authChain, URI resourceUri) throws Exception {
            this(authChain);
            _blockBuilder.setSubject(resourceUri);
        }

        PolicyBuilder(AuthChain authChain) throws Exception {
            _authChain = authChain;
            _blockBuilder = authChain.newBlockBuilder()
                    .setIssuer(_acct)
                    .setIssuerKey(Identity.this.getActiveKeyPair());
        }

        public PolicyBuilder viralGrant(PublicIdentity grantee, String privilege) throws Exception {
            _blockBuilder.addGrant(new AuthBlockGrant(AuthBlockGrant.Type.VIRAL_GRANT, grantee.getAcct(), privilege));
            return this;
        }

        public PolicyBuilder grant(PublicIdentity grantee, String privilege) throws Exception {
            _blockBuilder.addGrant(new AuthBlockGrant(AuthBlockGrant.Type.GRANT, grantee.getAcct(), privilege));
            return this;
        }

        public PolicyBuilder revoke(PublicIdentity grantee, String privilege) throws Exception {
            _blockBuilder.addGrant(new AuthBlockGrant(AuthBlockGrant.Type.REVOKE, grantee.getAcct(), privilege));
            return this;
        }

        public void build() throws Exception {
            _blockBuilder.build();
            SdkUtils.getTransport().putChain(_authChain);
        }
    }
}