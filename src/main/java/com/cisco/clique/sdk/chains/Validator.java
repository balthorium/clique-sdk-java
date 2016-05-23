package com.cisco.clique.sdk.chains;

import com.cisco.clique.sdk.InvalidBlockException;
import com.cisco.clique.sdk.SdkUtils;
import com.cisco.clique.sdk.Transport;
import com.nimbusds.jose.jwk.ECKey;

import java.net.URI;

abstract public class Validator<T extends Block> {

    protected T _currentBlock;
    protected URI _chainIssuer;
    protected URI _chainSubject;
    protected Transport _transport;

    public Validator() {
        _transport = SdkUtils.getTransport();
    }

    public void reset() {
        _currentBlock = null;
        _chainIssuer = null;
        _chainSubject = null;
    }

    public final void validate(T block) throws Exception {
        doValidation(block);
        doPostValidation(block);
    }

    protected void doValidation(T block) throws Exception {
        validateSignature(block);

        if (null == _currentBlock) {
            _chainIssuer = block.getIssuer();
            _chainSubject = block.getSubject();
        }

        validateAntecedent(block);
        validateIssuer(block);
    }

    protected void doPostValidation(T block) throws Exception {

        // set the validated block as the new current block
        _currentBlock = block;
    }

    protected void validateAntecedent(T block) throws Exception {
        Object ant = block._jwt.getJWTClaimsSet().getClaim("ant");

        // succeed if this is the genesis block (and set the validator's chain-issuer and chain-subject)
        if (null == ant && null == _currentBlock) {
            return;
        }

        // fail if ant is null but not _currentBlock
        if (null == ant) {
            throw new InvalidBlockException("block's antecedent claim is null but should not be");
        }

        // fail if _currentBlock is null but not ant
        if (null == _currentBlock) {
            throw new InvalidBlockException("block's antecedent claim is not null but should be");
        }

        // fail if ant and _currentBlock hash don't match
        if (!ant.toString().equals(_currentBlock.getHash())) {
            throw new InvalidBlockException("block's antecedent claim does not match hash of preceding block");
        }
    }

    protected void validateSignature(T block) throws Exception {

        // get the thumbprint of the block's signature verification key from the JWT "kid" header
        String pkt = block.getKid();
        if (null == pkt) {
            throw new InvalidBlockException("block's JWT header does not contain a key id (kid)");
        }

        // fetch the public key corresponding to the thumbprint
        ECKey key = _transport.getKey(pkt);
        if (null == key) {
            throw new InvalidBlockException("block's signature verification key could not be found");
        }

        // verify the block signature
        if (!block.verify(key)) {
            throw new InvalidBlockException("block's signature verification failed");
        }
    }

    protected void validateIssuer(T block) throws Exception {

        // get the thumbprint of the block's signature verification key from the JWT "kid" header
        String pkt = block.getKid();
        if (null == pkt) {
            throw new InvalidBlockException("block's JWT header does not contain a key id (kid)");
        }

        // get the block's issuer claim
        URI issuerUri = block.getIssuer();
        if (null == issuerUri) {
            throw new InvalidBlockException("block is missing an issuer claim or is not a valid URI");
        }

        // get the issuer's identity chain from transport/cache
        IdChain issuerChain = (IdChain) _transport.getChain(issuerUri);
        if (null == issuerChain) {
            throw new InvalidBlockException("block issuer's identity chain could not be found");
        }

        // validate the issuer's identity chain
        issuerChain.validate();

        // verify the block's signature verification key thumbprint is somewhere in the issuer's identity chain
        if (!issuerChain.containsPkt(pkt)) {
            throw new InvalidBlockException("block's signature verification key does not belong to named issuer");
        }
    }
}
