package com.cisco.clique.sdk;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

class AuthBlock extends Block {

    AuthBlock(URI issuer, ECKey issuerKey, URI subject, JSONArray grants, String ant) throws Exception {
        super(issuerKey, new JWTClaimsSet.Builder()
                .claim("iss", issuer.toString())
                .claim("sub", (null != subject) ? subject.toString() : null)
                .claim("grants", grants)
                .claim("ant", ant));
    }

    AuthBlock(String serialization) throws Exception {
        super(serialization);
    }

    List<AuthBlockGrant> getGrants() throws Exception {
        List<AuthBlockGrant> grantList = new ArrayList<>();
        JSONArray grantArray = (JSONArray) _jwt.getJWTClaimsSet().getClaim("grants");
        for (Object grant : grantArray) {
            grantList.add(new AuthBlockGrant(_mapper.readTree(((JSONObject) grant).toJSONString())));
        }
        return grantList;
    }

    static public class Builder {
        protected AuthChain _chain;
        protected URI _issuer;
        protected URI _subject;
        protected ECKey _issuerKey;
        protected List<AuthBlockGrant> _grants;

        Builder(AuthChain chain) {
            _chain = chain;
            _grants = new ArrayList<>();
        }

        Builder setIssuer(URI issuer) {
            _issuer = issuer;
            return this;
        }

        Builder setIssuerKey(ECKey issuerKey) {
            _issuerKey = issuerKey;
            return this;
        }

        Builder setSubject(URI subject) {
            _subject = subject;
            return this;
        }
        Builder addGrant(AuthBlockGrant grant) {
            _grants.add(grant);
            return this;
        }

        AuthBlock build() throws Exception {
            Block lastBlock = _chain.lastBlock();
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
