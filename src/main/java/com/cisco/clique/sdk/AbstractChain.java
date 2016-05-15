package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.List;

/**
 * Base class for both identity and authorization chain classes.
 */
abstract public class AbstractChain {

    protected static final ObjectMapper _mapper = SdkUtils.createMapper();

    /**
     * Returns the block within this chain at the given index.
     *
     * @param index The index of the requested block.
     * @return The block at the requested index, or null in the case of overflow.
     */
    abstract AbstractBlock getBlock(int index);

    /**
     * Returns an ordered list of all blocks in the chain.
     *
     * @return The full chain as an ordered list of blocks.
     */
    abstract List<? extends AbstractBlock> getBlocks();

    /**
     * Returns the size of the chain.
     *
     * @return The number of blocks in the chain.
     */
    public abstract int size();

    /**
     * Returns a human-readable string representing the contents of this chain.  Note, this represents only the payload
     * of the chain, and does not represent the signed JWT serializations of each block.
     *
     * @return A human-readable representation of this chain - not for use as protocol.
     */
    public String toString() {
        String retval = null;
        try {
            retval = _mapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(toJsonPayloadOnly());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return retval;
    }

    /**
     * Returns a JSON array with text elements representing the payload of each block.  This should be used only
     * for producing human-readable representations of the chain (e.g. toString).
     *
     * @return A JSON array representing the chain blocks' payloads.
     * @throws Exception
     */
    private ArrayNode toJsonPayloadOnly() throws Exception {
        ArrayNode chain = _mapper.createArrayNode();
        for (AbstractBlock block : getBlocks()) {
            chain.add(block.toJson());
        }
        return chain;
    }

    /**
     * Returns a JSON array with text elements representing the JWT serialization of each block.
     *
     * @return A JSON array representing the full chain.
     * @throws Exception
     */
    ArrayNode toJson() throws Exception {
        ArrayNode chain = _mapper.createArrayNode();
        for (AbstractBlock block : getBlocks()) {
            chain.add(block.serialize());
        }
        return chain;
    }

    /**
     * Returns a JSON document representing a serialization of the entire chain.
     *
     * @return Text representing the full serialization of this chain.
     * @throws Exception
     */
    public String serialize() throws Exception {
        return _mapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(toJson());
    }

    /**
     * Returns the subject of this chain, as defined in the initial block.
     *
     * @return The subject of this chain.
     * @throws Exception
     */
    public URI getSubject() throws Exception {
        AbstractBlock block = getBlock(0);
        if (null != block) {
            return block.getSubject();
        }
        return null;
    }

    /**
     * Returns the SHA-256 hash of the signed JWT serialization of this chain's initial block.
     *
     * @return The hash of this chains initial block.
     * @throws Exception
     */
    public String getGenesisHash() throws Exception {
        return getBlock(0).getHash();
    }
}
