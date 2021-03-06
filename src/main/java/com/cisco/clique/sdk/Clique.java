package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.AbstractChain;
import com.cisco.clique.sdk.chains.AuthChain;
import com.cisco.clique.sdk.chains.IdChain;
import com.cisco.clique.sdk.validation.AuthBlockValidator;
import com.cisco.clique.sdk.validation.IdBlockValidator;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

public class Clique {

    public Transport _transport;
    private Set<String> _trustRoots;

    public Clique() {
        _transport = new MemoryTransport();
        _trustRoots = new HashSet<>();
    }

    public Clique(Transport transport, Set<String> trustRoots) {
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
        if (null == acct) {
            throw new IllegalArgumentException("acct URI cannot be null");
        }
        if (null != _transport.getIdChain(new IdBlockValidator(_transport, _trustRoots), acct)) {
            throw new IllegalArgumentException("an identity chain already exists for " + acct.toString());
        }
        return new Identity(new IdBlockValidator(_transport, _trustRoots), null, acct);
    }

    public Identity createIdentity(Identity mint, URI acct) throws Exception {
        if (null == mint || null == acct) {
            throw new IllegalArgumentException("mint and acct URIs must both be non-null");
        }
        if (null == _transport.getIdChain(new IdBlockValidator(_transport, _trustRoots), mint.getAcct())) {
            throw new IllegalArgumentException("an identity chain could not be found for " + acct.toString());
        }
        if (null != _transport.getIdChain(new IdBlockValidator(_transport, _trustRoots), acct)) {
            throw new IllegalArgumentException("an identity chain already exists for " + acct.toString());
        }
        return new Identity(new IdBlockValidator(_transport, _trustRoots), mint, acct);
    }

    public Identity deserializeIdentity(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException("serialization must be non-null");
        }
        return new Identity(new IdBlockValidator(_transport, _trustRoots), serialization);
    }

    public PublicIdentity getPublicIdentity(URI acct) throws Exception {
        if (null == acct) {
            throw new IllegalArgumentException("the acct URI must be non-null");
        }
        AbstractChain chain = _transport.getIdChain(new IdBlockValidator(_transport, _trustRoots), acct);
        if (null == chain) {
            throw new IllegalArgumentException("no published identity chain found for " + acct.toString());
        }
        if (!(chain instanceof IdChain)) {
            throw new IllegalArgumentException(acct.toString() + " is published but not as an identity chain");
        }
        chain.validate();
        return new PublicIdentity((IdChain) chain);
    }

    public PublicIdentity deserializePublicIdentity(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException("serialization must be non-null");
        }
        return new PublicIdentity(new IdBlockValidator(_transport, _trustRoots), serialization);
    }

    public Policy.PolicyBuilder createPolicy(Identity issuer, URI resource) throws Exception {
        if (null == issuer || null == resource) {
            throw new IllegalArgumentException("the issuer and resource URI must both be non-null");
        }
        return new Policy(
                new AuthChain(new AuthBlockValidator(_transport, _trustRoots))).new PolicyBuilder(issuer, resource);
    }

    public Policy deserializePolicy(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException("serialization must be non-null");
        }
        return new Policy(new AuthBlockValidator(_transport, _trustRoots), serialization);
    }

    public Policy deserializePolicy(ArrayNode array) throws Exception {
        if (null == array) {
            throw new IllegalArgumentException("json array must be non-null");
        }
        return new Policy(new AuthBlockValidator(_transport, _trustRoots), array);
    }

    public Policy getPolicy(URI resource) throws Exception {
        if (null == resource) {
            throw new IllegalArgumentException("the resource URI must be non-null");
        }
        AbstractChain chain = _transport.getAuthChain(new AuthBlockValidator(_transport, _trustRoots), resource);
        if (null == chain) {
            throw new IllegalArgumentException("no published auth chain found for " + resource.toString());
        }
        if (!(chain instanceof AuthChain)) {
            throw new IllegalArgumentException(resource.toString() + "is published but not as an auth chain");
        }
        chain.validate();
        return new Policy((AuthChain) chain);
    }
}
