package com.cisco.clique.sdk;

public interface BlockFactory<T extends Block> {
    T newBlock(String serialization) throws Exception;
}
