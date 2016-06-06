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
                grantArray.add(JSONObjectUtils.parse(grant.toString()));
            }

            AuthBlock block = new AuthBlock(_issuer, _issuerKey, _subject, grantArray, ant);

            _chain.addBlock(block);
            return block;
        }
    }

    public static class Grant {

        private Type _type;
        private String _privilege;
        private URI _grantee;

        public Grant(Type type, URI grantee, String privilege) throws Exception {
            if (null == type || null == privilege || null == grantee) {
                throw new IllegalArgumentException();
            }
            _type = type;
            _grantee = grantee;
            _privilege = privilege;
        }

        public Grant(JsonNode node) {
            deserializeFromJson(node);
        }

        public Type getType() {
            return _type;
        }

        public String getPrivilege() {
            return _privilege;
        }

        public URI getGrantee() {
            return _grantee;
        }

        private ObjectNode serializeToJson() {
            ObjectNode node = _mapper.createObjectNode();
            node.put("type", _type.toString());
            node.put("privilege", _privilege);
            node.put("grantee", _grantee.toString());
            return node;
        }

        private void deserializeFromJson(JsonNode node) {
            _type = Type.valueOf(node.findPath("type").asText());
            _privilege = node.findPath("privilege").asText();
            _grantee = URI.create(node.findPath("grantee").asText());
        }

        @Override
        public String toString() {
            try {
                return _mapper
                        .writerWithDefaultPrettyPrinter()
                        .writeValueAsString(serializeToJson());
            } catch (IOException e) {
                e.printStackTrace();
            }
            return "";
        }

        public enum Type {
            VIRAL_GRANT,
            GRANT,
            REVOKE
        }
    }
}
