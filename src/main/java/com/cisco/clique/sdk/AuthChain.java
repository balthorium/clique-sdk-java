package com.cisco.clique.sdk;

import java.net.URI;
import java.util.ListIterator;

public class AuthChain extends Chain<AuthBlock> {

    public AuthChain() {
        this(new AuthBlockValidator());
    }

    public AuthChain(AuthBlockValidator validator) {
        super(validator);
    }

    public AuthChain(String serialization) throws Exception {
        this(new AuthBlockValidator(), serialization);
    }

    public AuthChain(AuthBlockValidator validator, String serialization) throws Exception {
        super(validator, serialization);
    }

    void addBlock(String serialization) throws Exception {
        addBlock(new AuthBlock(serialization));
    }

    boolean hasPrivilege(URI acct, String privilege) throws Exception {
        if (null == acct || null == privilege) {
            throw new IllegalArgumentException();
        }
        ListIterator<AuthBlock> iterator = _blocks.listIterator(_blocks.size());
        while (iterator.hasPrevious()) {
            for (AuthBlockGrant authBlockGrant : iterator.previous().getGrants()) {
                if (authBlockGrant.getGrantee().equals(acct) && authBlockGrant.getPrivilege().equals(privilege)) {
                    return !authBlockGrant.getType().equals(AuthBlockGrant.Type.REVOKE);
                }
            }
        }
        return false;
    }

    AuthBlock.Builder newBlockBuilder() {
        return new AuthBlock.Builder(this);
    }
}
