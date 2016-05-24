package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AuthBlock;
import com.cisco.clique.sdk.chains.AuthChain;

import java.net.URI;

public class Policy {

    protected AuthChain _authChain;

    private Policy(AuthChain chain) throws Exception {
        _authChain = chain;
    }

    public static PolicyBuilder create(Identity issuer, URI resource) throws Exception {
        if (null == issuer || null == resource) {
            throw new IllegalArgumentException("the issuer and resource URI must both be non-null");
        }
        return new Policy(new AuthChain()).new PolicyBuilder(issuer, resource);
    }

    public static Policy get(URI resource) throws Exception {
        if (null == resource) {
            throw new IllegalArgumentException("the resource URI must be non-null");
        }
        AuthChain chain = (AuthChain) SdkCommon.getTransport().getChain(resource);
        if (null != chain) {
            chain.validate();
            return new Policy(chain);
        }
        return null;
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

    public class PolicyBuilder {
        private AuthBlock.Builder _blockBuilder;

        PolicyBuilder(Identity issuer, URI resource) throws Exception {
            this(issuer);
            _blockBuilder.setSubject(resource);
        }

        PolicyBuilder(Identity issuer) throws Exception {
            _blockBuilder = _authChain.newBuilder()
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

        public Policy commit() throws Exception {
            _blockBuilder.build();
            SdkCommon.getTransport().putChain(_authChain);
            return Policy.this;
        }
    }

    @Override
    public String toString() {
        return _authChain.toString();
    }
}
