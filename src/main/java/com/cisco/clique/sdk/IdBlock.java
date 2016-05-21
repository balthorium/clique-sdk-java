package com.cisco.clique.sdk;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;

import java.net.URI;

/**
 * Represents an identity block.  An identity block is a specialization of an abstract block where the specific claims
 * included in the JWT payload are: ant, iss, and pkt.  These represent the SHA-256 antecedent hash, the issuer,
 * and a public key thumbprint, respectively.
 */
class IdBlock extends AbstractBlock {

    /**
     * Creates a new IdBlock.
     *
     * @param issuer        The issuer of the block.
     * @param issuerKey     The full key of the issuer.
     * @param subject       The subjecvt of the block.
     * @param subjectPubKey The public key of the subject.
     * @param ant           The antecedent block hash.
     * @throws Exception On failure.
     */
    IdBlock(URI issuer, ECKey issuerKey, URI subject, ECKey subjectPubKey, String ant) throws Exception {
        super(issuerKey, new JWTClaimsSet.Builder()
                .claim("iss", issuer.toString())
                .claim("sub", subject.toString())
                .claim("pkt", subjectPubKey.computeThumbprint().toString())
                .claim("ant", ant));
    }

    /**
     * Creates an IdBlock from an existing signed JWT serialization.
     *
     * @param serialization A signed JWT serialization.
     * @throws Exception On failure.
     */
    IdBlock(String serialization) throws Exception {
        super(serialization);
    }

    /**
     * Returns the public key thumbprint (pkt) claim contained in the ID block payload.
     *
     * @return The public key thumbprint.
     * @throws Exception On failure.
     */
    String getPkt() throws Exception {
        return _jwt.getJWTClaimsSet().getClaim("pkt").toString();
    }

    /**
     * Given a chain validation state, validates the antecedent (ant) claim contained in the ID block payload.
     *
     * @param cvs The chain validation state providing context for validation.
     * @return True if the block's antecedent is valid, false otherwise.
     * @throws Exception On failure.
     */
    boolean validateAntecedent(IdChain.ChainValidationState cvs) throws Exception {
        Object ant = _jwt.getJWTClaimsSet().getClaim("ant");

        // if this is the antecedent block then no validation required, just set the chain issuer on cvs
        if (null == ant && null == cvs._antecedentBlock) {
            cvs._issuer = URI.create(_jwt.getJWTClaimsSet().getClaim("iss").toString());
            return true;
        }

        return null != ant && null != cvs._antecedentBlock && ant.toString().equals(cvs._antecedentBlock.getHash());
    }

    /**
     * Given a chain validation state, validates this block's JWT signature.
     *
     * @param cvs The chain validation state providing context for validation.
     * @return True if the block's signature is valid, false otherwise.
     * @throws Exception On failure.
     */
    boolean validateSignature(IdChain.ChainValidationState cvs) throws Exception {
        Transport transport = SdkUtils.getTransport();

        // if this blocks hash matches a trust root hash then no need to validate signature
        if (cvs._trustRoots.contains(getHash())) {
            return true;
        }

        // pull the verification public key signature out of the block's kid header attribute
        String pkt = _jwt.getHeader().getKeyID();

        // if this is the genesis block, or the block is not signed by antecedent public key...
        if ((null == cvs._antecedentBlock) || !pkt.equals(cvs._antecedentBlock.getPkt())) {

            // fetch the IdChain of the genesis-block issuer and see if pkt is their key
            IdChain issuerChain = (IdChain) transport.getChain(cvs._issuer);
            if (!issuerChain.validate(cvs._trustRoots) || !issuerChain.containsPkt(pkt)) {
                pkt = null;
            }
        }
        return (null != pkt) && _jwt.verify(new ECDSAVerifier(transport.getKey(pkt).toECPublicKey()));
    }

    /**
     * Builder class for creating new IdBlocks.
     */
    static class Builder {
        protected IdChain _chain;
        protected URI _issuer;
        protected URI _subject;
        protected ECKey _issuerKey;
        protected ECKey _subjectPubKey;

        /**
         * Constructor for IdBlock builder.
         *
         * @param chain The IdChain to which this block is being added.
         */
        Builder(IdChain chain) {
            _chain = chain;
        }

        /**
         * Set the issuer URI to be asserted by the IdBlock being created.
         *
         * @param issuer The identity to act as issuer (iss) of this block.
         * @return This builder.
         */
        Builder setIssuer(URI issuer) {
            _issuer = issuer;
            return this;
        }

        /**
         * Provide the full asymmetric key to be used for signing and verifying the IdBlock being created.
         *
         * @param issuerKey The URI of the identity that signs this block.
         * @return This builder.
         */
        Builder setIssuerKey(ECKey issuerKey) {
            _issuerKey = issuerKey;
            return this;
        }

        /**
         * Set the subject (sub) URI to be asserted by the IdBlock being created.
         *
         * @param subject The URI of the identity represented by this block.
         * @return This builder.
         */
        Builder setSubject(URI subject) {
            _subject = subject;
            return this;
        }

        /**
         * Set the public key for which the thumbprint (pkt) is to be asserted by the IdBlock being created.
         *
         * @param subjectPubKey The public key whose thumbprint to assign as pkt claim on this block.
         * @return This builder.
         */
        Builder setSubjectPubKey(ECKey subjectPubKey) {
            _subjectPubKey = subjectPubKey;
            return this;
        }

        /**
         * Builds an ID block based on current builder.
         *
         * @return A new ID block which has already been added to the IdChain provided in the builder constructor.
         * @throws Exception On failure.
         */
        IdBlock build() throws Exception {
            String ant = (_chain._blocks.size() > 0) ? _chain._blocks.get(_chain._blocks.size() - 1).getHash() : null;

            if (null == _subject) {
                _subject = _issuer;
                _subjectPubKey = _issuerKey.toPublicJWK();
            }

            IdBlock block = new IdBlock(_issuer, _issuerKey, _subject, _subjectPubKey, ant);
            if (null != block.serialize()) {
                _chain.addBlock(block);
            } else {
                // TODO: throw an exception
                block = null;
            }
            return block;
        }
    }
}