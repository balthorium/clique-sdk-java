package com.cisco.clique.sdk;

import java.util.HashSet;
import java.util.Set;

public class IdChain extends Chain<IdBlock> {

    Set<String> _pkts;

    public IdChain() {
        this(new IdBlockValidator());
    }

    public IdChain(IdBlockValidator validator) {
        super(validator);
        _pkts = new HashSet<>();
    }

    public IdChain(String serialization) throws Exception {
        this(new IdBlockValidator(), serialization);
    }

    public IdChain(IdBlockValidator validator, String serialization) throws Exception {
        super(validator, serialization);
        _pkts = new HashSet<>();
    }

    void addBlock(IdBlock block) throws Exception {
        super.addBlock(block);
        _pkts.add(block.getPkt());
    }

    void addBlock(String serialization) throws Exception {
        addBlock(new IdBlock(serialization));
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
