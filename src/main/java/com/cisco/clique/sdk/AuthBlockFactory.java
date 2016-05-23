package com.cisco.clique.sdk;

class AuthBlockFactory implements BlockFactory<AuthBlock> {

    @Override
    public AuthBlock newBlock(String serialization) throws Exception {
        return new AuthBlock(serialization);
    }
}
