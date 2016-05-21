package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.*;

/**
 * Represents an authorization chain.  An authorization chain is an ordered collection of authorization blocks,
 * where the ordering is explicitly asserted through the inclusion within each block of the preceding block's
 * hash.  An authorization chain is verifiable through the application of rules described in the Clique specification.
 */
class AuthChain extends AbstractChain {

    private ArrayList<AuthBlock> _blocks;

    /**
     * Creates a new AuthChain.
     */
    AuthChain() {
        _blocks = new ArrayList<>();
    }

    /**
     * Parses an existing authorization chain to an AuthChain object.  The existing chain is provided in it's
     * serialized form.  Note this operation will not automatically perform validation of the provided chain.
     *
     * @param serialization A serialization of the existing full authorization chain.
     * @throws Exception On failure.
     */
    AuthChain(String serialization) throws Exception {
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        _blocks = new ArrayList<>();
        ArrayNode chain = (ArrayNode) _mapper.readTree(serialization);
        for (JsonNode block : chain) {
            addBlock(new AuthBlock(block.asText()));
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
    void addBlock(AuthBlock block) throws Exception {
        _blocks.add(block);
    }

    /**
     * Evaluates whether the identity represented by the given URI possesses the given privilege, according to the
     * trust policy asserted by this chain.  This method does not perform validation of the chain before processing.
     *
     * @param acct      The URL of the identity whose privileges are being queried.
     * @param privilege The privilege to be checked.
     * @return True if the given identity has the given privilege, false otherwise.
     * @throws Exception On failure.
     */
    boolean hasPrivilege(URI acct, String privilege) throws Exception {
        if (null == acct || null == privilege) {
            throw new IllegalArgumentException();
        }
        ListIterator<AuthBlock> iterator = _blocks.listIterator(_blocks.size());
        while (iterator.hasPrevious()) {
            for (AuthBlockGrant authBlockGrant : iterator.previous().getAuthBlockGrants()) {
                if (authBlockGrant.getGrantee().equals(acct) && authBlockGrant.getPrivilege().equals(privilege)) {
                    return !authBlockGrant.getType().equals(AuthBlockGrant.Type.REVOKE);
                }
            }
        }
        return false;
    }

    /**
     * Creates a builder that appends a new block to this chain.  The block is not actually appended until the
     * Builder.build() command is invoked, and then only if the builder has been provided with valid and sufficient
     * attributes for the new block.
     *
     * @return A builder for creating AuthBlock objects.
     */
    AuthBlock.Builder newBlockBuilder() {
        return new AuthBlock.Builder(this);
    }

    /**
     * Performs a validation operation on the chain.  This Begins by checking whether the chain's genesis block
     * hash matches the given hash value, then progressively checks each subsequent block to ensure that the
     * antecedent hashes match, that the signatures can be validated with the issuers' public keys, and that the
     * issuers have authority to assert the privilege grants contained within the blocks they issue.
     *
     * @param genesisBlockHash The expected hash of the chain's genesis block.
     * @return True if the chain is valid, false otherwise.
     * @throws Exception On failure.
     */
    boolean validate(String genesisBlockHash) throws Exception {
        if (null == genesisBlockHash) {
            throw new IllegalArgumentException();
        }
        if (getHash().equals(genesisBlockHash)) {
            ChainValidationState cvs = new ChainValidationState();
            for (AuthBlock block : _blocks) {
                if (!cvs.ratchet(block)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * A package scope class to represent the processing state used by the validate operation as it progresses
     * through the chain.
     */
    class ChainValidationState {

        AuthBlock _antecedentBlock;
        Map<URI, Map<String, AuthBlockGrant>> _currentGrants;

        ChainValidationState() {
            _antecedentBlock = null;
            _currentGrants = new HashMap<>();
        }

        boolean ratchet(AuthBlock block) throws Exception {

            if (!block.validateAntecedent(this) ||
                    !block.validateSignature(this) ||
                    !block.validateGrants(this)) {
                return false;
            }

            for (AuthBlockGrant authBlockGrant : block.getAuthBlockGrants()) {
                URI grantee = authBlockGrant.getGrantee();
                _currentGrants.putIfAbsent(grantee, new HashMap<>());
                _currentGrants.get(grantee).put(authBlockGrant.getPrivilege(), authBlockGrant);
            }

            _antecedentBlock = block;
            return true;
        }
    }
}