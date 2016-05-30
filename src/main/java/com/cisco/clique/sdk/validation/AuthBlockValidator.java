package com.cisco.clique.sdk.validation;

import com.cisco.clique.sdk.chains.AuthBlock;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class AuthBlockValidator extends AbstractValidator<AuthBlock> {

    private Map<URI, Map<String, AuthBlock.Grant.Type>> _currentGrants;

    public AuthBlockValidator() {
        _currentGrants = new HashMap<>();
    }

    @Override
    public void reset() {
        super.reset();
        _currentGrants.clear();
    }

    @Override
    protected void doValidation(AuthBlock block) throws Exception {
        super.doValidation(block);
        validateGrants(block);
    }

    @Override
    protected void doPostValidation(AuthBlock block) throws Exception {
        super.doPostValidation(block);

        // update the _currentGrants and set new block as _lastValidated
        for (AuthBlock.Grant grant : block.getGrants()) {
            URI grantee = grant.getGrantee();
            _currentGrants.putIfAbsent(grantee, new HashMap<String, AuthBlock.Grant.Type>());
            _currentGrants.get(grantee).put(grant.getPrivilege(), grant.getType());
        }
    }

    protected void validateGrants(AuthBlock block) throws Exception {

        // automatic success if this is the antecedent block
        if (null == block.getAntecedent()) {
            return;
        }

        // validate that the issuer has authority to assert the grants contained within the block
        URI issuer = block.getIssuer();
        Map<String, AuthBlock.Grant.Type> creatorGrants = _currentGrants.get(issuer);
        for (AuthBlock.Grant grant : block.getGrants()) {
            if (!creatorGrants.get(grant.getPrivilege()).equals(AuthBlock.Grant.Type.VIRAL_GRANT)) {
                throw new InvalidBlockException("block issuer has insufficient privileges to assert contained grants");
            }
        }
    }
}