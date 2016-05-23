package com.cisco.clique.sdk.chains;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

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

    public List<AuthBlockGrant> getGrants() throws Exception {
        List<AuthBlockGrant> grantList = new ArrayList<>();
        JSONArray grantArray = (JSONArray) _jwt.getJWTClaimsSet().getClaim("grants");
        for (Object grant : grantArray) {
            grantList.add(new AuthBlockGrant(_mapper.readTree(((JSONObject) grant).toJSONString())));
        }
        return grantList;
    }

    static public class Builder {
        private AuthChain _chain;
        private URI _issuer;
        private URI _subject;
        private ECKey _issuerKey;
        private List<AuthBlockGrant> _grants;

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

        public Builder addGrant(AuthBlockGrant grant) {
            _grants.add(grant);
            return this;
        }

        public AuthBlock build() throws Exception {
            AbstractBlock lastBlock = _chain.lastBlock();
            String ant = (null != lastBlock) ? lastBlock.getHash() : null;

            JSONArray grantArray = new JSONArray();
            for (AuthBlockGrant grant : _grants) {
                grantArray.add(JSONObjectUtils.parseJSONObject(grant.toString()));
            }

            AuthBlock block = new AuthBlock(_issuer, _issuerKey, _subject, grantArray, ant);
            block.serialize();

            _chain.addBlock(block);
            return block;
        }
    }
}
