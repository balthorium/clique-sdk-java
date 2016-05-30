package com.cisco.clique.sdk.chains;

import com.cisco.clique.sdk.JsonMapperFactory;
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
import java.text.ParseException;

public abstract class AbstractBlock {

    protected static final ObjectMapper _mapper = JsonMapperFactory.getInstance().createMapper();
    protected ECKey _key;
    protected SignedJWT _jwt;
    protected String _serialization;

    protected AbstractBlock(ECKey key, JWTClaimsSet.Builder claimsBuilder) throws Exception {
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

    protected AbstractBlock(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        _key = null;
        _serialization = serialization;
        _jwt = SignedJWT.parse(_serialization);
    }

    public SignedJWT getJwt() {
        return _jwt;
    }

    public String getKid() {
        return _jwt.getHeader().getKeyID();
    }

    public String getAntecedent() throws ParseException {
        Object ant = _jwt.getJWTClaimsSet().getClaim("ant");
        if (null != ant) {
            return ant.toString();
        }
        return null;
    }

    public URI getIssuer() {
        URI retval = null;
        try {
            retval = URI.create(_jwt.getJWTClaimsSet().getIssuer());
        } catch (Exception e) {
            // ignore
        }
        return retval;
    }

    public URI getSubject() {
        URI retval = null;
        try {
            retval = URI.create(_jwt.getJWTClaimsSet().getSubject());
        } catch (Exception e) {
            // ignore
        }
        return retval;
    }

    public String getHash() throws Exception {
        byte[] bytes = serialize().getBytes(StandardCharsets.UTF_8);
        return Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(bytes));
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
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AbstractBlock)) {
            return false;
        }
        AbstractBlock that = (AbstractBlock) obj;
        try {
            return serialize().equals(that.serialize());
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return _serialization.hashCode();
    }

    @Override
    public String toString() {
        return _jwt.getPayload().toString();
    }
}