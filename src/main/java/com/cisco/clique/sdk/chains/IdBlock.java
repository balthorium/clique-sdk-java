package com.cisco.clique.sdk.chains;

import com.cisco.clique.sdk.Clique;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;

import java.net.URI;

public class IdBlock extends AbstractBlock {

    private IdBlock(URI issuer, ECKey issuerKey, URI subject, ECKey subjectPubKey, String ant) throws Exception {
        super(issuerKey, new JWTClaimsSet.Builder()
                .claim("iss", issuer.toString())
                .claim("sub", subject.toString())
                .claim("pkt", subjectPubKey.computeThumbprint().toString())
                .claim("ant", ant));
    }

    IdBlock(String serialization) throws Exception {
        super(serialization);
    }

    public String getPkt() throws Exception {
        return _jwt.getJWTClaimsSet().getClaim("pkt").toString();
    }

    public static class Builder {
        private IdChain _chain;
        private URI _issuer;
        private URI _subject;
        private ECKey _issuerKey;
        private ECKey _subjectPubKey;


        public Builder(IdChain chain) {
            _chain = chain;
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

        public Builder setSubjectPubKey(ECKey subjectPubKey) {
            _subjectPubKey = subjectPubKey;
            return this;
        }

        public IdBlock build() throws Exception {
            AbstractBlock lastBlock = _chain.lastBlock();
            String ant = (null != lastBlock) ? lastBlock.getHash() : null;
            IdBlock block = new IdBlock(_issuer, _issuerKey, _subject, _subjectPubKey, ant);
            block.serialize();

            // automatically add locally created self-issued blocks to the trust roots
            if (_issuer.equals(_subject)) {
                Clique.getInstance().getTrustRoots().add(block.getHash());
            }

            _chain.addBlock(block);
            return block;
        }
    }
}