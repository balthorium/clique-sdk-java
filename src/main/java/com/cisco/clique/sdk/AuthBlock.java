package com.cisco.clique.sdk;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Represents an auth chain block.  An auth block is a specialization of an abstract block where the specific claims
 * included in the JWT payload are: ant, iss, sub, and an array of grants.  These represent the SHA-256 antecedent hash,
 * the issuer, the subject (only in the first block of a chain), and a collection of privilege grants asserted by this
 * block, respectively.
 */
class AuthBlock extends AbstractBlock {

    /**
     * Create new block in an AuthChain.
     *
     * @param issuer    The URI of the block issuer identity.
     * @param issuerKey The full key to use for signing and verifying this block.
     * @param subject   The URI of the block subject (should be set only for genesis block).
     * @param grants    A collection of grants to be asserted in this block.
     * @param ant       The SHA-256 hash of the preceding block's signed JWT serialized form.
     * @throws Exception On failure.
     */
    AuthBlock(URI issuer, ECKey issuerKey, URI subject, JSONArray grants, String ant) throws Exception {
        super(issuerKey, new JWTClaimsSet.Builder()
                .claim("iss", issuer.toString())
                .claim("sub", (null != subject) ? subject.toString() : null)
                .claim("grants", grants)
                .claim("ant", ant));
    }

    /**
     * Create a block from a received JWT serialization.
     *
     * @param serialization A block in signed JWT serialized form.
     * @throws Exception On failure.
     */
    AuthBlock(String serialization) throws Exception {
        super(serialization);
    }

    /**
     * Returns list containing grants asserted within this block as AuthBlockGrant objects.
     *
     * @return A list containing all grants asserted within this block.
     * @throws Exception On failure.
     */
    List<AuthBlockGrant> getAuthBlockGrants() throws Exception {
        List<AuthBlockGrant> grantList = new ArrayList<>();
        JSONArray grantArray = (JSONArray) _jwt.getJWTClaimsSet().getClaim("grants");
        for (Object grant : grantArray) {
            grantList.add(new AuthBlockGrant(_mapper.readTree(((JSONObject) grant).toJSONString())));
        }
        return grantList;
    }

    /**
     * Validate the antecedent attribute of this block, if any.
     *
     * @param cvs The validation state following validation of preceding blocks of the chain.
     * @return True if the antecedent attribute state is valid, false otherwise.
     * @throws Exception On failure.
     */
    boolean validateAntecedent(AuthChain.ChainValidationState cvs) throws Exception {
        Object ant = _jwt.getJWTClaimsSet().getClaim("ant");
        if (null == ant || null == cvs._antecedentBlock) {
            return null == ant && null == cvs._antecedentBlock;
        }
        return ant.toString().equals(cvs._antecedentBlock.getHash());
    }

    /**
     * Validate the signature of this block.
     *
     * @param cvs The validation state following validation of preceding blocks of the chain.
     * @return True if the block signature is successfully verified, false otherwise.
     * @throws Exception On failure.
     */
    boolean validateSignature(AuthChain.ChainValidationState cvs) throws Exception {
        boolean retval = false;
        Transport transport = SdkUtils.getTransport();
        String pkt = _jwt.getHeader().getKeyID();
        ECKey key = transport.getKey(pkt);
        if (_jwt.verify(new ECDSAVerifier(key.toECPublicKey()))) {
            URI issuer = URI.create(_jwt.getJWTClaimsSet().getIssuer());
            IdChain idChain = (IdChain) transport.getChain(issuer);
            retval = idChain.containsPkt(pkt);
        }
        return retval;
    }

    /**
     * Validate the grants asserted by this block.  Successful validation requires that the issuer of this block
     * possess a virally grant for every privilege being extended or revoked by this block.  If this is the first
     * block of the AuthChain, then the grants are implicitly valid.
     *
     * @param cvs The validation state following validation of preceding blocks of the chain.
     * @return True if the grants asserted by this block are valid.
     * @throws Exception On failure.
     */
    boolean validateGrants(AuthChain.ChainValidationState cvs) throws Exception {
        Object ant = _jwt.getJWTClaimsSet().getClaim("ant");
        if (null == ant || null == cvs._antecedentBlock) {
            return null == ant && null == cvs._antecedentBlock;
        }
        URI issuer = URI.create(_jwt.getJWTClaimsSet().getIssuer());
        Map<String, AuthBlockGrant> creatorGrants = cvs._currentGrants.get(issuer);
        for (AuthBlockGrant authBlockGrant : getAuthBlockGrants()) {
            if (!creatorGrants.get(authBlockGrant.getPrivilege()).getType().equals(AuthBlockGrant.Type.VIRAL_GRANT)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Builder for generating new AuthBlocks.
     */
    public static class Builder {
        protected AuthChain _chain;
        protected URI _issuer;
        protected ECKey _issuerKey;
        protected URI _subject;
        protected List<AuthBlockGrant> _grants;

        /**
         * Create new AuthBlock builder.
         *
         * @param chain The AuthChain to which the block created by this builder will be added.
         */
        Builder(AuthChain chain) {
            _chain = chain;
            _grants = new ArrayList<>();
        }

        /**
         * Set the issuer URI to be asserted by the AuthBlock being created.
         *
         * @param issuer The identity to act as issuer (iss) of this block.
         * @return This builder.
         */
        Builder setIssuer(URI issuer) {
            _issuer = issuer;
            return this;
        }

        /**
         * Provide the full asymmetric key to be used for signing and verifying the AuthBlock being created.
         *
         * @param issuerKey The URI of the identity that signs this block.
         * @return This builder.
         */
        Builder setIssuerKey(ECKey issuerKey) {
            _issuerKey = issuerKey;
            return this;
        }

        /**
         * Provide the URI of a subject resource for which the chain's privilege policy applies.  This should be
         * set only for the first block in an AuthChain - it will be ignored otherwise.
         *
         * @param subject The URL of a subject resource for which this chain's privilege policy applies.
         * @return An AuthChain builder.
         */
        Builder setSubject(URI subject) {
            _subject = subject;
            return this;
        }

        /**
         * Add a grant to be asserted by this block.  May be invoked any number of times on the same builder.
         *
         * @param grant Add a grant to be asserted by this block.
         * @return This builder.
         */
        Builder addGrant(AuthBlockGrant grant) {
            _grants.add(grant);
            return this;
        }

        /**
         * Builds an AuthBlock based on state of this builder.
         *
         * @return A new AuthBlock which has already been added to the chain provided in the builder constructor.
         * @throws Exception On failure.
         */
        AuthBlock build() throws Exception {
            String ant = null;
            URI subject = null;

            if (_chain.size() == 0) {
                subject = _subject;
            } else {
                ant = _chain.getBlock(_chain.size() - 1).getHash();
            }

            JSONArray grantArray = new JSONArray();
            for (AuthBlockGrant grant : _grants) {
                grantArray.add(JSONObjectUtils.parseJSONObject(grant.toString()));
            }

            AuthBlock block = new AuthBlock(_issuer, _issuerKey, subject, grantArray, ant);
            _chain.addBlock(block);

            return block;
        }
    }
}
