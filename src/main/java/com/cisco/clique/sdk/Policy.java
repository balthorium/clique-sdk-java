package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AuthBlock;
import com.cisco.clique.sdk.chains.AuthChain;
import com.cisco.clique.sdk.validation.AbstractValidator;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;

public class Policy {

    private AuthChain _authChain;

    Policy(AuthChain chain) throws Exception {
        _authChain = chain;
    }

    public Policy(AbstractValidator<AuthBlock> validator, ArrayNode array) throws Exception {
        _authChain = new AuthChain(validator, array);
    }

    public Policy(AbstractValidator<AuthBlock> validator, String serialization) throws Exception {
        _authChain = new AuthChain(validator, serialization);
    }

    public PolicyBuilder update(Identity issuer) throws Exception {
        if (null == issuer) {
            throw new IllegalArgumentException("the issuer must both be non-null");
        }
        return new PolicyBuilder(issuer);
    }

    public boolean hasPrivilege(PublicIdentity grantee, String privilege) throws Exception {
        return _authChain.hasPrivilege(grantee.getAcct(), privilege);
    }

    void resetValidator() {
        _authChain.resetValidator();
    }

    public String serialize() throws Exception {
        return _authChain.serialize();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Policy)) {
            return false;
        }
        Policy policy = (Policy) obj;
        return _authChain.equals(policy._authChain);

    }

    @Override
    public int hashCode() {
        return _authChain.hashCode();
    }

    @Override
    public String toString() {
        return _authChain.toString();
    }

    public class PolicyBuilder {
        private AuthBlock.Builder _blockBuilder;

        PolicyBuilder(Identity issuer, URI resource) throws Exception {
            this(issuer);
            _blockBuilder.setSubject(resource);
        }

        PolicyBuilder(Identity issuer) throws Exception {
            _blockBuilder = _authChain.newBlockBuilder()
                    .setIssuer(issuer.getAcct())
                    .setIssuerKey(issuer.getActiveKeyPair());
        }

        public PolicyBuilder viralGrant(PublicIdentity grantee, String privilege) throws Exception {
            _blockBuilder.addGrant(new AuthBlock.Grant(AuthBlock.Grant.Type.VIRAL_GRANT, grantee.getAcct(), privilege));
            return this;
        }

        public PolicyBuilder grant(PublicIdentity grantee, String privilege) throws Exception {
            _blockBuilder.addGrant(new AuthBlock.Grant(AuthBlock.Grant.Type.GRANT, grantee.getAcct(), privilege));
            return this;
        }

        public PolicyBuilder revoke(PublicIdentity grantee, String privilege) throws Exception {
            _blockBuilder.addGrant(new AuthBlock.Grant(AuthBlock.Grant.Type.REVOKE, grantee.getAcct(), privilege));
            return this;
        }

        public Policy build() throws Exception {
            _blockBuilder.build();
            _authChain.getValidator().getTransport().putAuthChain(_authChain);
            return Policy.this;
        }
    }
}
