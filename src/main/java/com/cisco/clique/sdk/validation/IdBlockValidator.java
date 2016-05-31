package com.cisco.clique.sdk.validation;

import com.cisco.clique.sdk.Transport;
import com.cisco.clique.sdk.chains.IdBlock;

import java.net.URI;
import java.util.Set;

public class IdBlockValidator extends AbstractValidator<IdBlock> {

    public IdBlockValidator(Transport transport) {
        super(transport);
    }

    public IdBlockValidator(Transport transport, Set<String> trustRoots) {
        super(transport, trustRoots);
    }

    @Override
    protected void validateIssuer(IdBlock block) throws Exception {

        // succeed if block's signature verification key thumbprint matches thumbprint published in the previous block
        if ((null != _lastValidated) && block.getKid().equals(_lastValidated.getPkt())) {
            return;
        }

        // do default issuer validation if block issuer matches issuer of chain's genesis block (but not self-issued)
        URI issuerUri = block.getIssuer();
        if (((null == _lastValidated) || issuerUri.equals(_chainIssuer)) && !issuerUri.equals(block.getSubject())) {
            super.validateIssuer(block);
            return;
        }

        throw new InvalidBlockException("identity block is not a trust root and issuer is not trusted");
    }
}
