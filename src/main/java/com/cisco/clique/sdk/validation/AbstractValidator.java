package com.cisco.clique.sdk.validation;

import com.cisco.clique.sdk.Transport;
import com.cisco.clique.sdk.chains.AbstractBlock;
import com.cisco.clique.sdk.chains.IdChain;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;
import java.util.Set;

public abstract class AbstractValidator<T extends AbstractBlock> {

    protected T _lastValidated;
    protected URI _chainIssuer;
    protected URI _chainSubject;
    protected Transport _transport;
    Set<String> _trustRoots;

    public AbstractValidator(Transport transport, Set<String> trustRoots) {
        _transport = transport;
        _trustRoots = trustRoots;
    }

    public void addTrustRoot(String trustRoot) {
        _trustRoots.add(trustRoot);
    }

    public Set<String> getTrustRoots() {
        return _trustRoots;
    }

    public void reset() {
        _lastValidated = null;
        _chainIssuer = null;
        _chainSubject = null;
    }

    public Transport getTransport() {
        return _transport;
    }

    public T lastValidatedBlock() {
        return _lastValidated;
    }

    public final void validate(T block) throws Exception {
        doValidation(block);
        doPostValidation(block);
    }

    protected void doValidation(T block) throws Exception {

        if (_trustRoots.contains(block.getHash())) {
            return;
        }

        validateSignature(block);

        if (null == _lastValidated) {
            _chainIssuer = block.getIssuer();
            _chainSubject = block.getSubject();
        }

        validateAntecedent(block);
        validateIssuer(block);
    }

    protected void doPostValidation(T block) throws Exception {

        // set the validated block as the new current block
        _lastValidated = block;
    }

    protected void validateAntecedent(T block) throws Exception {
        Object ant = block.getJwt().getJWTClaimsSet().getClaim("ant");

        // succeed if this is the genesis block (and set the validator's chain-issuer and chain-subject)
        if (null == ant && null == _lastValidated) {
            return;
        }

        // fail if ant is null but not _lastValidated
        if (null == ant) {
            throw new InvalidBlockException("block antecedent claim is null but should not be");
        }

        // fail if _lastValidated is null but not ant
        if (null == _lastValidated) {
            throw new InvalidBlockException("block antecedent claim is not null but should be");
        }

        // fail if ant and _lastValidated hash don't match
        if (!ant.toString().equals(_lastValidated.getHash())) {
            throw new InvalidBlockException("block antecedent claim does not match hash of preceding block");
        }
    }

    protected void validateSignature(T block) throws Exception {

        // get the thumbprint of the block's signature verification key from the JWT "kid" header
        String pkt = block.getKid();
        if (null == pkt) {
            throw new InvalidBlockException("block JWT header does not contain a key id (kid)");
        }

        // fetch the public key corresponding to the thumbprint
        ECKey key = _transport.getKey(pkt);
        if (null == key) {
            throw new InvalidBlockException("block signature verification key could not be found");
        }

        // verify the block signature
        if (!block.verify(key)) {
            throw new InvalidBlockException("block signature verification failed");
        }
    }

    protected void validateIssuer(T block) throws Exception {

        // get the thumbprint of the block's signature verification key from the JWT "kid" header
        String pkt = block.getKid();
        if (null == pkt) {
            throw new InvalidBlockException("block JWT header does not contain a key id (kid)");
        }

        // get the block's issuer claim
        URI issuerUri = block.getIssuer();
        if (null == issuerUri) {
            throw new InvalidBlockException("block is missing an issuer claim or is not a valid URI");
        }

        // get the issuer's identity chain from transport/cache
        IdChain issuerChain = (IdChain) _transport.getChain(new IdBlockValidator(_transport, _trustRoots), issuerUri);
        if (null == issuerChain) {
            throw new InvalidBlockException("block issuer's identity chain could not be found");
        }

        // validate the issuer's identity chain
        issuerChain.validate();

        // verify the block's signature verification key thumbprint is somewhere in the issuer's identity chain
        if (!issuerChain.containsPkt(pkt)) {
            throw new InvalidBlockException("block signature verification key does not belong to named issuer");
        }
    }
}
