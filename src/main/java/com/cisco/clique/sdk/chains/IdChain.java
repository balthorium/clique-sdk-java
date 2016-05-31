package com.cisco.clique.sdk.chains;

import com.cisco.clique.sdk.validation.AbstractValidator;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.util.HashSet;
import java.util.Set;

public class IdChain extends AbstractChain<IdBlock> {

    private Set<String> _pkts;

    public IdChain(AbstractValidator<IdBlock> validator) {
        super(validator);
        _pkts = new HashSet<>();
    }

    public IdChain(AbstractValidator<IdBlock> validator, ArrayNode array) throws Exception {
        super(validator, array);
        _pkts = new HashSet<>();
    }

    public IdChain(AbstractValidator<IdBlock> validator, String serialization) throws Exception {
        super(validator, serialization);
        _pkts = new HashSet<>();
    }

    void addBlock(IdBlock block) throws Exception {
        super.addBlock(block);
        _pkts.add(block.getPkt());
    }

    public void addBlock(String serialization) throws Exception {
        addBlock(new IdBlock(serialization));
    }

    public boolean containsPkt(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException();
        }
        return _pkts.contains(pkt);
    }

    public String getActivePkt() throws Exception {
        return _blocks.get(_blocks.size() - 1).getPkt();
    }

    public IdBlock.Builder newBlockBuilder() {
        return new IdBlock.Builder(this);
    }
}
