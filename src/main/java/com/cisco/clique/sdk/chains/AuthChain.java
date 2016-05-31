package com.cisco.clique.sdk.chains;

import com.cisco.clique.sdk.validation.AbstractValidator;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonArrayFormatVisitor;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.ListIterator;

public class AuthChain extends AbstractChain<AuthBlock> {

    public AuthChain(AbstractValidator<AuthBlock> validator) {
        super(validator);
    }

    public AuthChain(AbstractValidator<AuthBlock> validator, ArrayNode array) throws Exception {
        super(validator, array);
    }

    public AuthChain(AbstractValidator<AuthBlock> validator, String serialization) throws Exception {
        super(validator, serialization);
    }

    public void addBlock(String serialization) throws Exception {
        addBlock(new AuthBlock(serialization));
    }

    public boolean hasPrivilege(URI acct, String privilege) throws Exception {
        if (null == acct || null == privilege) {
            throw new IllegalArgumentException();
        }
        ListIterator<AuthBlock> iterator = _blocks.listIterator(_blocks.size());
        while (iterator.hasPrevious()) {
            for (AuthBlock.Grant authBlockGrant : iterator.previous().getGrants()) {
                if (authBlockGrant.getGrantee().equals(acct) && authBlockGrant.getPrivilege().equals(privilege)) {
                    return !authBlockGrant.getType().equals(AuthBlock.Grant.Type.REVOKE);
                }
            }
        }
        return false;
    }

    public AuthBlock.Builder newBlockBuilder() {
        return new AuthBlock.Builder(this);
    }
}
