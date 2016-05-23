package com.cisco.clique.sdk.chains;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class AuthBlock extends AbstractBlock {

    private AuthBlock(URI issuer, ECKey issuerKey, URI subject, JSONArray grants, String ant) throws Exception {
        super(issuerKey, new JWTClaimsSet.Builder()
                .claim("iss", issuer.toString())
                .claim("sub", (null != subject) ? subject.toString() : null)
                .claim("grants", grants)
                .claim("ant", ant));
    }

    AuthBlock(String serialization) throws Exception {
        super(serialization);
    }

    public List<AuthBlock.Grant> getGrants() throws Exception {
        List<AuthBlock.Grant> grantList = new ArrayList<>();
        JSONArray grantArray = (JSONArray) _jwt.getJWTClaimsSet().getClaim("grants");
        for (Object grant : grantArray) {
            grantList.add(new AuthBlock.Grant(_mapper.readTree(((JSONObject) grant).toJSONString())));
        }
        return grantList;
    }

    public static class Builder {
        private AuthChain _chain;
        private URI _issuer;
        private URI _subject;
        private ECKey _issuerKey;
        private List<AuthBlock.Grant> _grants;

        public Builder(AuthChain chain) {
            _chain = chain;
            _grants = new ArrayList<>();
        }

        public Builder setIssuer(URI issuer) {
            _issuer = issuer;
            return this;
        }

        public Builder setIssuerKey(ECKey issuerKey) {
            _issuerKey = issuerKey;
            return this;
        }

        public Builder setSubject(URI subject) {
            _subject = subject;
            return this;
        }

        public Builder addGrant(AuthBlock.Grant grant) {
            _grants.add(grant);
            return this;
        }

        public AuthBlock build() throws Exception {
            AbstractBlock lastBlock = _chain.lastBlock();
            String ant = (null != lastBlock) ? lastBlock.getHash() : null;

            JSONArray grantArray = new JSONArray();
            for (AuthBlock.Grant grant : _grants) {
                grantArray.add(JSONObjectUtils.parseJSONObject(grant.toString()));
            }

            AuthBlock block = new AuthBlock(_issuer, _issuerKey, _subject, grantArray, ant);
            block.serialize();

            _chain.addBlock(block);
            return block;
        }
    }

    /**
     * Represents grant assertions as contained within authorization chain blocks.
     */
    public static class Grant {

        private Type _type;
        private String _privilege;
        private URI _grantee;

        /**
         * Creates a new grant.
         *
         * @param type      The type of grant being asserted.
         * @param grantee   The identity to which the grant is extended.
         * @param privilege The privilege to which the grant applies.
         * @throws Exception On failure.
         */
        public Grant(Type type, URI grantee, String privilege) throws Exception {
            if (null == type || null == privilege || null == grantee) {
                throw new IllegalArgumentException();
            }
            _type = type;
            _grantee = grantee;
            _privilege = privilege;
        }

        /**
         * Creates a grant from a given parsed JSON document.
         *
         * @param node The root of the JSON document representing a grant.
         */
        public Grant(JsonNode node) {
            _type = Type.valueOf(node.findPath("type").asText());
            _privilege = node.findPath("privilege").asText();
            _grantee = URI.create(node.findPath("grantee").asText());
        }

        /**
         * Return the type of this grant.
         *
         * @return The type of this grant.
         */
        public Type getType() {
            return _type;
        }

        /**
         * Return the privilege to which this grant applies.
         *
         * @return The privilege to which this grant applies.
         */
        public String getPrivilege() {
            return _privilege;
        }

        /**
         * Return the identity to which this grant is extended.
         *
         * @return The identity to which this grant is extended.
         */
        public URI getGrantee() {
            return _grantee;
        }

        /**
         * A human readable representation of the grant, useful for logging.
         *
         * @return A string representation of the AuthBlock.Grant object's state.
         */
        @Override
        public String toString() {
            String retval = null;
            try {
                ObjectNode grant = _mapper.createObjectNode();
                grant.put("type", _type.toString());
                grant.put("privilege", _privilege);
                grant.put("grantee", _grantee.toString());

                retval = _mapper
                        .writerWithDefaultPrettyPrinter()
                        .writeValueAsString(grant);
            } catch (IOException e) {
                e.printStackTrace();
            }
            return retval;
        }

        public enum Type {

            /**
             * A privilege grant that also carries the right to extend the same privilege to other identities.
             */
            VIRAL_GRANT,

            /**
             * A privilege grant.
             */
            GRANT,

            /**
             * A revocation of privilege.
             */
            REVOKE
        }
    }
}
