package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractChain;
import com.cisco.clique.sdk.chains.AuthChain;
import com.cisco.clique.sdk.chains.IdChain;
import com.cisco.clique.sdk.validation.AuthBlockValidator;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

public class Clique {

    public Transport _transport;
    private Set<String> _trustRoots;

    private Clique(Transport transport, Set<String> trustRoots) {
        _transport = transport;
        _trustRoots = trustRoots;
    }

    public static Clique getInstance() {
        return CliqueFactorySingleton.INSTANCE;
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
        if (null == acct) {
            throw new IllegalArgumentException("acct URI cannot be null");
        }
        if (null != _transport.getChain(acct)) {
            throw new IllegalArgumentException("an identity chain already exists for " + acct.toString());
        }
        return new Identity(null, acct);
    }

    public Identity createIdentity(Identity mint, URI acct) throws Exception {
        if (null == mint || null == acct) {
            throw new IllegalArgumentException("mint and acct URIs must both be non-null");
        }
        if (null == _transport.getChain(mint.getAcct())) {
            throw new IllegalArgumentException("an identity chain could not be found for " + acct.toString());
        }
        if (null != _transport.getChain(acct)) {
            throw new IllegalArgumentException("an identity chain already exists for " + acct.toString());
        }
        return new Identity(mint, acct);
    }

    public PublicIdentity getPublicIdentity(URI acct) throws Exception {
        if (null == acct) {
            throw new IllegalArgumentException("the acct URI must be non-null");
        }
        AbstractChain chain = _transport.getChain(acct);
        if (null == chain) {
            throw new IllegalArgumentException("no published identity chain found for " + acct.toString());
        }
        if (!(chain instanceof IdChain)) {
            throw new IllegalArgumentException(acct.toString() + " is published but not as an identity chain");
        }
        chain.validate();
        return new PublicIdentity((IdChain) chain);
    }

    public Policy.PolicyBuilder createPolicy(Identity issuer, URI resource) throws Exception {
        if (null == issuer || null == resource) {
            throw new IllegalArgumentException("the issuer and resource URI must both be non-null");
        }
        return new Policy(new AuthChain(new AuthBlockValidator())).new PolicyBuilder(issuer, resource);
    }

    public Policy getPolicy(URI resource) throws Exception {
        if (null == resource) {
            throw new IllegalArgumentException("the resource URI must be non-null");
        }
        AbstractChain chain = _transport.getChain(resource);
        if (null == chain) {
            throw new IllegalArgumentException("no published auth chain found for " + resource.toString());
        }
        if (!(chain instanceof AuthChain)) {
            throw new IllegalArgumentException(resource.toString() + "is published but not as an auth chain");
        }
        chain.validate();
        return new Policy((AuthChain) chain);
    }

    private static class CliqueFactorySingleton {
        private static final Clique INSTANCE = new Clique(new MemoryTransport(), new HashSet<String>());
    }
}
