package com.cisco.clique.sdk.chains;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class AuthBlockValidator extends Validator<AuthBlock> {

    private Map<URI, Map<String, AuthBlockGrant.Type>> _currentGrants;

    public AuthBlockValidator() {
        _currentGrants = new HashMap<>();
    }

    @Override
    public void reset() {
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

        // update the _currentGrants and set new block as _currentBlock
        for (AuthBlockGrant grant : block.getGrants()) {
            URI grantee = grant.getGrantee();
            _currentGrants.putIfAbsent(grantee, new HashMap<>());
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
        Map<String, AuthBlockGrant.Type> creatorGrants = _currentGrants.get(issuer);
        for (AuthBlockGrant grant : block.getGrants()) {
            if (!creatorGrants.get(grant.getPrivilege()).equals(AuthBlockGrant.Type.VIRAL_GRANT)) {
                throw new InvalidBlockException("block's issuer has insufficient privileges to assert these grants");
            }
        }
    }
}
