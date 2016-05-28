package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AuthChain;
import com.cisco.clique.sdk.chains.IdChain;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

public class Clique {

    public Transport _transport;
    private Set<String> _trustRoots;

    private static class CliqueFactorySingleton {
        private static final Clique INSTANCE = new Clique(new TransportLocal(), new HashSet<String>());
    }

    public static Clique getInstance() {
        return CliqueFactorySingleton.INSTANCE;
    }

    private Clique(Transport transport, Set<String> trustRoots) {
        _transport = transport;
        _trustRoots = trustRoots;
    }

    public Transport setTransport(Transport transport) {
        Transport old = _transport;
        _transport = transport;
        return old;
    }

    public Transport getTransport() {
        return _transport;
    }

    public Set<String> setTrustRoots(Set<String> trustRoots) {
        Set<String> old = _trustRoots;
        _trustRoots = trustRoots;
        return old;
    }

    public Set<String> getTrustRoots() {
        return _trustRoots;
    }


    public Identity createIdentity(URI acct) throws Exception {
        if (null != _transport.getChain(acct)) {
            throw new IllegalArgumentException("an identity chain already exists for the given acct URI");
        }
        return new Identity(null, acct);
    }

    public Identity createIdentity(Identity mint, URI acct) throws Exception {
        if (null == mint || null == _transport.getChain(mint.getAcct())) {
            throw new IllegalArgumentException("an identity chain could not be found for the given mint URI");
        }
        if (null != _transport.getChain(acct)) {
            throw new IllegalArgumentException("an identity chain already exists for the given acct URI");
        }
        return new Identity(mint, acct);
    }

    public PublicIdentity getPublicIdentity(URI acct) throws Exception {
        if (null == acct) {
            throw new IllegalArgumentException("the acct URI must be non-null");
        }
        IdChain chain = (IdChain) _transport.getChain(acct);
        if (null == chain) {
            throw new IllegalArgumentException("the acct URI has no published identity chain");
        }
        return new PublicIdentity(chain);
    }

    public Policy.PolicyBuilder createPolicy(Identity issuer, URI resource) throws Exception {
        if (null == issuer || null == resource) {
            throw new IllegalArgumentException("the issuer and resource URI must both be non-null");
        }
        return new Policy(new AuthChain()).new PolicyBuilder(issuer, resource);
    }

    public Policy getPolicy(URI resource) throws Exception {
        if (null == resource) {
            throw new IllegalArgumentException("the resource URI must be non-null");
        }
        AuthChain chain = (AuthChain) _transport.getChain(resource);
        if (null == chain) {
            throw new IllegalArgumentException("the resource URI has no corresponding auth chain");
        }
        chain.validate();
        return new Policy(chain);
    }
}
