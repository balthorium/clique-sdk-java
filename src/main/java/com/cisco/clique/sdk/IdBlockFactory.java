package com.cisco.clique.sdk;

class IdBlockFactory implements BlockFactory<IdBlock> {

    @Override
    public IdBlock newBlock(String serialization) throws Exception {
        return new IdBlock(serialization);
    }
}
