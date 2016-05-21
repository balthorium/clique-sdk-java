package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Represents an identity chain.  An identity chain is an ordered collection of identity blocks,
 * where the ordering is explicitly asserted through the inclusion within each block of the preceding block's
 * hash.  An identity chain is verifiable through the application of rules described in the Clique specification.
 */
class IdChain extends AbstractChain {

    ArrayList<IdBlock> _blocks;
    Set<String> _pkts;

    /**
     * Creates a new AuthChain.
     */
    IdChain() {
        _blocks = new ArrayList<>();
        _pkts = new HashSet<>();
    }

    /**
     * Parses an existing identity chain to an IdChain object.  The existing chain is provided in it's
     * serialized form.  Note this operation will not automatically perform validation of the provided chain.
     *
     * @param serialization A serialization of the existing full identity chain.
     * @throws Exception On failure.
     */
    IdChain(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        _blocks = new ArrayList<>();
        _pkts = new HashSet<>();
        ArrayNode chain = (ArrayNode) _mapper.readTree(serialization);
        for (JsonNode block : chain) {
            addBlock(new IdBlock(block.asText()));
        }
    }

    @Override
    AbstractBlock getBlock(int index) {
        return _blocks.get(index);
    }

    @Override
    List<? extends AbstractBlock> getBlocks() {
        return _blocks;
    }

    @Override
    int size() {
        return _blocks.size();
    }

    /**
     * Adds a block to the chain, performs no validation.
     *
     * @param block Block to be added to the chain.
     * @throws Exception On failure.
     */
    void addBlock(IdBlock block) throws Exception {
        if (null == block) {
            throw new IllegalArgumentException();
        }
        _blocks.add(block);
        _pkts.add(block.getPkt());
    }

    /**
     * Checks to see if the given public key thumbprint (pkt) is represented in this id chain.
     *
     * @param pkt The evaluated thumbprint.
     * @return True if pkt is found in the id chain, false otherwise.
     */
    boolean containsPkt(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException();
        }
        return _pkts.contains(pkt);
    }

    /**
     * Returns the public key thumbprint (pkt) of the most recently added block of the chain.
     *
     * @return The most recently appended key.
     * @throws Exception On failure.
     */
    String getActivePkt() throws Exception {
        return _blocks.get(_blocks.size() - 1).getPkt();
    }

    /**
     * Creates a builder that appends a new block to this chain.  The block is not actually appended until the
     * Builder.build() command is invoked, and then only if the builder has been provided with valid and sufficient
     * attributes for the new block.
     *
     * @return A builder for creating IdBlock objects.
     */
    IdBlock.Builder newBlockBuilder() {
        return new IdBlock.Builder(this);
    }

    /**
     * Performs a validation operation on the chain.  This Begins by checking whether the chain's genesis block
     * is either self signed by an identity in the trust root, or is signed by an identity that can be traced
     * back recursively to an identity in the trust root.
     *
     * @param trustRoots The set of trust roots to use for validation of this chain.
     * @return True if the chain is valid, false otherwise.
     * @throws Exception On failure.
     */
    boolean validate(Set<String> trustRoots) throws Exception {
        ChainValidationState cvs = new ChainValidationState(trustRoots);
        for (IdBlock block : _blocks) {
            if (!cvs.ratchet(block)) {
                return false;
            }
        }
        return true;
    }

    /**
     * A package scope class to represent the processing state used by the validate operation as it progresses
     * through the chain.
     */
    class ChainValidationState {
        Set<String> _trustRoots;
        IdBlock _antecedentBlock;
        URI _issuer;
        URI _subject;

        ChainValidationState(Set<String> trustRoots) {
            _trustRoots = trustRoots;
            _antecedentBlock = null;
            _issuer = null;
        }

        boolean ratchet(IdBlock block) throws Exception {
            if (!block.validateAntecedent(this) ||
                    !block.validateSignature(this)) {
                return false;
            }
            _antecedentBlock = block;
            return true;
        }
    }
}
