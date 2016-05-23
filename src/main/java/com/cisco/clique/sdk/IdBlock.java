package com.cisco.clique.sdk;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;

import java.net.URI;

class IdBlock extends Block {

    IdBlock(URI issuer, ECKey issuerKey, URI subject, ECKey subjectPubKey, String ant) throws Exception {
        super(issuerKey, new JWTClaimsSet.Builder()
                .claim("iss", issuer.toString())
                .claim("sub", subject.toString())
                .claim("pkt", subjectPubKey.computeThumbprint().toString())
                .claim("ant", ant));
    }

    IdBlock(String serialization) throws Exception {
        super(serialization);
    }

    String getPkt() throws Exception {
        return _jwt.getJWTClaimsSet().getClaim("pkt").toString();
    }

    static public class Builder {
        protected IdChain _chain;
        protected URI _issuer;
        protected URI _subject;
        protected ECKey _issuerKey;
        protected ECKey _subjectPubKey;


        Builder(IdChain chain) {
            _chain = chain;
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

        Builder setSubjectPubKey(ECKey subjectPubKey) {
            _subjectPubKey = subjectPubKey;
            return this;
        }

        IdBlock build() throws Exception {
            Block lastBlock = _chain.lastBlock();
            String ant = (null != lastBlock) ? lastBlock.getHash() : null;
            IdBlock block = new IdBlock(_issuer, _issuerKey, _subject, _subjectPubKey, ant);
            block.serialize();

            // automatically add locally created self-issued blocks to the trust roots
            if (_issuer.equals(_subject)) {
                SdkUtils.getTrustRoots().add(block.getHash());
            }

            _chain.addBlock(block);
            return block;
        }
    }
}