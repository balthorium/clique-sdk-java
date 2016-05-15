package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Hex;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Represents the fundamental aspects of both ID and Auth chain blocks.  In both cases, a block represents a RFC7519
 * JWT with a key id header whose value is the RFC7638 thumbprint of a JWK containing the public key necessary to
 * validate the JWT.
 */
abstract class AbstractBlock {

    protected ECKey _key;
    protected SignedJWT _jwt;
    protected String _serialization;
    protected static final ObjectMapper _mapper = SdkUtils.createMapper();

    /**
     * Creates a new AbstractBlock, can only be called by derived class.
     *
     * @param key           The key to sign this block - must include the private key material.
     * @param claimsBuilder Represents the claims to be embedded within this AbstractBlock.
     * @throws Exception On failure.
     */
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

    /**
     * Creates an AbstractBlock based on a given serialization of a signed JWT.
     *
     * @param serialization The serialization of a signed JWT.
     * @throws Exception On failure.
     */
    AbstractBlock(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        _key = null;
        _serialization = serialization;
        _jwt = SignedJWT.parse(_serialization);
    }

    /**
     * Emits a representation of this block's payload as a parsed JSON object.
     *
     * @return Parsed JSON object representing block's payload.
     * @throws Exception On failure.
     */
    ObjectNode toJson() throws Exception {
        return (ObjectNode) _mapper.readTree(_jwt.getPayload().toString());
    }

    /**
     * Generates a SHA-256 hash of this block's JWT serialization and encodes as a UTF8 hex string.
     *
     * @return SHA-256 hash of this block.
     * @throws Exception On failure.
     */
    String getHash() throws Exception {
        return Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(serialize().getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Returns the issuer of the block as a URI.
     *
     * @return The issuer of the block as a URI.
     * @throws Exception On failure.
     */
    URI getIssuer() throws Exception {
        return URI.create(_jwt.getJWTClaimsSet().getIssuer());
    }

    /**
     * Returns the subject of the block as a URI.
     *
     * @return The subject of the block as a URI.
     * @throws Exception On failure.
     */
    URI getSubject() throws Exception {
        return URI.create(_jwt.getJWTClaimsSet().getSubject());
    }

    /**
     * Emits the signed JWT serialization of this block.
     *
     * @return Signed JWT serialization of this block.
     * @throws Exception On failure.
     */
    String serialize() throws Exception {
        if (null == _serialization) {
            if (null == _key) {
                throw new IllegalStateException();
            }
            _jwt.sign(new ECDSASigner(_key));
            _serialization = _jwt.serialize();
        }
        return _serialization;
    }
}