package com.cisco.clique.sdk;

import java.util.HashSet;
import java.util.Set;

public class IdChain extends Chain<IdBlock> {

    Set<String> _pkts;

    public IdChain() {
        this(new IdBlockFactory(), new IdBlockValidator());
    }

    public IdChain(IdBlockFactory factory, IdBlockValidator validator) {
        super(factory, validator);
        _pkts = new HashSet<>();
    }

    public IdChain(String serialization) throws Exception {
        this(new IdBlockFactory(), new IdBlockValidator(), serialization);
    }

    public IdChain(IdBlockFactory factory, IdBlockValidator validator, String serialization) throws Exception {
        super(factory, validator, serialization);
        _pkts = new HashSet<>();
    }

    void addBlock(IdBlock block) throws Exception {
        super.addBlock(block);
        _pkts.add(block.getPkt());
    }

    boolean containsPkt(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException();
        }
        return _pkts.contains(pkt);
    }

    String getActivePkt() throws Exception {
        return _blocks.get(_blocks.size() - 1).getPkt();
    }

    IdBlock.Builder newBlockBuilder() {
        return new IdBlock.Builder(this);
    }
}
