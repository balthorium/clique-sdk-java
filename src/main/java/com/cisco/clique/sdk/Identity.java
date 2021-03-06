package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.IdBlock;
import com.cisco.clique.sdk.chains.IdChain;
import com.cisco.clique.sdk.validation.AbstractValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

public class Identity extends PublicIdentity {

    private Map<String, ECKey> _keyPairs;

    Identity(AbstractValidator<IdBlock> validator, Identity mint, URI acct) throws Exception {
        _idChain = new IdChain(validator);
        ECKey key = createNewKeyPair();
        _idChain.newBlockBuilder()
                .setIssuer((null != mint) ? mint.getAcct() : acct)
                .setIssuerKey((null != mint) ? mint.getActiveKeyPair() : key)
                .setSubject(acct)
                .setSubjectPubKey(key.toPublicJWK())
                .build();
        validator.getTransport().putIdChain(_idChain);
    }

    public Identity(AbstractValidator<IdBlock> validator, String serialization) throws Exception {
        super(validator, serialization);
    }

    private void storeKeyPair(ECKey key) throws Exception {
        if (null == _keyPairs) {
            _keyPairs = new HashMap<>();
        }
        _keyPairs.put(key.toPublicJWK().computeThumbprint().toString(), key);
    }

    public ECKey rotateKeyPair() throws Exception {
        ECKey key = createNewKeyPair();
        _idChain.newBlockBuilder()
                .setIssuer(_idChain.getSubject())
                .setIssuerKey(getActiveKeyPair())
                .setSubject(_idChain.getSubject())
                .setSubjectPubKey(key.toPublicJWK())
                .build();
        _idChain.getValidator().getTransport().putIdChain(_idChain);
        return key;
    }

    private ECKey createNewKeyPair() throws Exception {
        ECKey.Curve crv = ECKey.Curve.P_256;
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA");
        gen.initialize(crv.toECParameterSpec());
        KeyPair pair = gen.generateKeyPair();
        ECKey key = new ECKey.Builder(crv, (ECPublicKey) pair.getPublic())
                .privateKey((ECPrivateKey) pair.getPrivate())
                .build();
        _idChain.getValidator().getTransport().putKey(key.toPublicJWK());
        storeKeyPair(key);
        return key;
    }

    public ECKey getKeyPair(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException("pkt must be non-null");
        }
        return _keyPairs.get(pkt);
    }

    public ECKey getActiveKeyPair() throws Exception {
        return getKeyPair(_idChain.getActivePkt());
    }

    @Override
    protected ObjectNode serializeToJson() throws Exception {
        ObjectNode json = super.serializeToJson();
        ArrayNode keys = json.putArray("keys");
        for (ECKey key : _keyPairs.values()) {
            ObjectNode keyNode = (ObjectNode) _mapper.readTree(key.toJSONString());
            keys.add(keyNode);
        }
        return json;
    }

    protected void deserializeFromJson(AbstractValidator<IdBlock> validator, ObjectNode json) throws Exception {
        super.deserializeFromJson(validator, json);
        ArrayNode array = (ArrayNode) json.findPath("keys");
        for (JsonNode node : array) {
            storeKeyPair(ECKey.parse(_mapper.writeValueAsString(node)));
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Identity)) {
            return false;
        }
        if (!super.equals(obj)) {
            return false;
        }
        Identity identity = (Identity) obj;
        return _keyPairs.keySet().equals(identity._keyPairs.keySet());
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + _keyPairs.hashCode();
        return result;
    }

    @Override
    public String toString() {
        try {
            ObjectNode identity = _mapper.createObjectNode();
            identity.set("chain", _mapper.readTree(_idChain.toString()));
            ArrayNode keys = identity.putArray("keys");
            for (ECKey key : _keyPairs.values()) {
                ObjectNode keyNode = (ObjectNode) _mapper.readTree(key.toJSONString());
                keyNode.put("kid", key.computeThumbprint().toString());
                keys.add(keyNode);
            }
            return _mapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(identity);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
}