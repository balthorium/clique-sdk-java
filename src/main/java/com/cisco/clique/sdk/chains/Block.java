package com.cisco.clique.sdk.chains;

import com.cisco.clique.sdk.SdkUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Hex;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public abstract class Block {

    protected ECKey _key;
    protected SignedJWT _jwt;
    protected String _serialization;
    protected static final ObjectMapper _mapper = SdkUtils.createMapper();

    protected Block(ECKey key, JWTClaimsSet.Builder claimsBuilder) throws Exception {
        if (null == key || null == claimsBuilder) {
            throw new IllegalArgumentException();
        }
        _key = key;
        _serialization = null;
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(_key.computeThumbprint().toString())
                .build();
        _jwt = new SignedJWT(header, claimsBuilder.build());
    }

    protected Block(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        _key = null;
        _serialization = serialization;
        _jwt = SignedJWT.parse(_serialization);
    }

    public String getKid() {
        return _jwt.getHeader().getKeyID();
    }

    public String getAntecedent() {
        Object ant = _jwt.getHeader().getCustomParam("ant");
        if (null != ant) {
            return ant.toString();
        }
        return null;
    }

    public URI getIssuer() {
        URI retval = null;
        try {
            retval = URI.create(_jwt.getJWTClaimsSet().getIssuer());
        }
        catch (Exception e) {
            // ignore
        }
        return retval;
    }

    public URI getSubject() {
        URI retval = null;
        try {
            retval = URI.create(_jwt.getJWTClaimsSet().getSubject());
        }
        catch (Exception e) {
            // ignore
        }
        return retval;
    }

    public String getHash() throws Exception {
        return Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(serialize().getBytes(StandardCharsets.UTF_8)));
    }

    public String serialize() throws Exception {
        if (null == _serialization) {
            if (null == _key) {
                throw new IllegalStateException();
            }
            _jwt.sign(new ECDSASigner(_key));
            _serialization = _jwt.serialize();
        }
        return _serialization;
    }

    public boolean verify(ECKey key) throws Exception {
        return _jwt.verify(new ECDSAVerifier(key.toECPublicKey()));
    }

    public ObjectNode getPayload() throws Exception {
        return (ObjectNode) _mapper.readTree(_jwt.getPayload().toString());
    }

    @Override
    public String toString() {
        return _jwt.getPayload().toString();
    }
}