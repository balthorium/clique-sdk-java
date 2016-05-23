package com.cisco.clique.sdk;

import java.net.URI;
import java.util.Set;

public class IdBlockValidator extends Validator<IdBlock> {
    Set<String> _trustRoots;

    IdBlockValidator() {
        _trustRoots = SdkUtils.getTrustRoots();
    }

    @Override
    protected void validateIssuer(IdBlock block) throws Exception {

        // succeed if block's hash matches a trust root
        if (_trustRoots.contains(block.getHash())) {
            return;
        }

        // succeed if block's sig. verification key thumbprint matches the thumbprint published in the previous block
        if ((null != _currentBlock) && block.getKid().equals(_currentBlock.getPkt())) {
            return;
        }

        // do default issuer validation if block issuer matches issuer of chain's genesis block (but not self-issued)
        URI issuerUri = block.getIssuer();
        if (((null == _currentBlock) || issuerUri.equals(_chainIssuer)) && !issuerUri.equals(block.getSubject())) {
            super.validateIssuer(block);
            return;
        }

        throw new InvalidBlockException("block is not a trust root, not signed with previous block's key, and not signed by the genesis block's issuer");
    }
}
