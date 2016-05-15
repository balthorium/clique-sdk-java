package com.cisco.clique.sdk;

import com.cisco.clique.cache.CliqueCache;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an identity chain.  An identity chain is an ordered collection of identity blocks,
 * where the ordering is explicitly asserted through the inclusion within each block of the preceding block's
 * hash.  An identity chain is verifiable through the application of rules described in the Clique specification.
 */
public class IdChain extends AbstractChain {

    ArrayList<IdBlock> _blocks;
    Map<String, Integer> _pktOrder;
    CliqueCache _cc;

    /**
     * Creates a new AuthChain.
     *
     * @param cc The local application's clique cache.
     */
    public IdChain(CliqueCache cc) {
        if (null == cc) {
            throw new IllegalArgumentException();
        }
        _cc = cc;
        _blocks = new ArrayList<>();
        _pktOrder = new HashMap<>();
    }

    /**
     * Parses an existing identity chain to an IdChain object.  The existing chain is provided in it's
     * serialized form.  Note this operation will not automatically perform validation of the provided chain.
     *
     * @param cc            The local application's clique cache.
     * @param serialization A serialization of the existing full identity chain.
     * @throws Exception
     */
    public IdChain(CliqueCache cc, String serialization) throws Exception {
        if (null == cc || null == serialization) {
            throw new IllegalArgumentException();
        }
        _cc = cc;
        _blocks = new ArrayList<>();
        _pktOrder = new HashMap<>();
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
    public int size() {
        return _blocks.size();
    }

    /**
     * Adds a block to the chain, performs no validation.
     *
     * @param block Block to be added to the chain.
     * @throws Exception
     */
    void addBlock(IdBlock block) throws Exception {
        if (null == block) {
            throw new IllegalArgumentException();
        }
        _blocks.add(block);
        _pktOrder.put(block.getPkt(), _pktOrder.size());
    }

    /**
     * Checks to see if the public key thumbprints pkt1 and pkt2 are both within this chain, and if so, whether
     * pkt1 is equal to or subsequent to pkt2.  If either thumbprint is not present in the chain, or pkt1 precedes
     * pkt2, this test will fail.
     *
     * @param pkt1 The subject thumbprint.
     * @param pkt2 The object thumbprint.
     * @return True of pkt2 is equal to or later than pkt1 in the chain, false otherwise.
     */
    boolean followsPkt(String pkt1, String pkt2) throws Exception {
        return containsPkt(pkt1) && containsPkt(pkt2) && _pktOrder.get(pkt2) <= _pktOrder.get(pkt1);
    }

    /**
     * Checks to see if the given public key thumbprint (pkt) is represented in this id chain.
     *
     * @param pkt The evaluated thumbprint.
     * @return True if pkt is found in the id chain, false otherwise.
     */
    public boolean containsPkt(String pkt) {
        if (null == pkt) {
            throw new IllegalArgumentException();
        }
        return _pktOrder.containsKey(pkt);
    }

    /**
     * Returns the public key thumbprint (pkt) of the most recently added block of the chain.
     *
     * @return The most recently appended key.
     * @throws Exception
     */
    public String getActivePkt() throws Exception {
        return _blocks.get(_blocks.size() - 1).getPkt();
    }

    /**
     * Creates a builder that appends a new block to this chain.  The block is not actually appended until the
     * Builder.build() command is invoked, and then only if the builder has been provided with valid and sufficient
     * attributes for the new block.
     *
     * @return A builder for creating IdBlock objects.
     */
    public IdBlock.Builder newBlockBuilder() {
        return new IdBlock.Builder(this);
    }

    /**
     * Performs a validation operation on the chain.  This Begins by checking whether the chain's genesis block
     * is either self signed by an identity in the trust root, or is signed by an identity that can be traced
     * back recursively to an identity in the trust root.
     *
     * @return True if the chain is valid, false otherwise.
     * @throws Exception
     */
    public boolean validate() throws Exception {
        ChainValidationState cvs = new ChainValidationState(_cc);
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
        CliqueCache _cc;
        IdBlock _antecedentBlock;
        URI _issuer;

        ChainValidationState(CliqueCache cc) {
            _cc = cc;
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
