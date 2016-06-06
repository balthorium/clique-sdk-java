package com.cisco.clique.sdk.validation;

import com.cisco.clique.sdk.Transport;
import com.cisco.clique.sdk.chains.AuthBlock;

import java.net.URI;
import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AuthBlockValidator extends AbstractValidator<AuthBlock> {

    private Map<URI, Map<String, AuthBlock.Grant.Type>> _currentGrants;

    public AuthBlockValidator(Transport transport, Set<String> trustRoots) {
        super(transport, trustRoots);
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
        if (null == creatorGrants) {
            throw new InvalidParameterException("block issuer has no privileges on this chain");
        }
        for (AuthBlock.Grant grant : block.getGrants()) {
            AuthBlock.Grant.Type grantType = creatorGrants.get(grant.getPrivilege());
            if (null == grantType) {
                throw new InvalidParameterException("block issuer has no grant for the privilege it is granting");
            }
            if (!grantType.equals(AuthBlock.Grant.Type.VIRAL_GRANT)) {
                throw new InvalidBlockException("block issuer has insufficient privileges to assert contained grants");
            }
        }
    }
}
