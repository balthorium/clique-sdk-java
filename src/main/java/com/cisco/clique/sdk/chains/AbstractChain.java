package com.cisco.clique.sdk.chains;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Consumer;

public abstract class AbstractChain<T extends AbstractBlock> {

    protected static final ObjectMapper _mapper = JsonMapperFactory.getInstance().createMapper();
    protected Validator<T> _validator;
    protected ArrayList<T> _blocks;

    protected AbstractChain(Validator<T> validator) {
        _validator = validator;
        _blocks = new ArrayList<>();
    }

    protected AbstractChain(Validator<T> validator, String serialization) throws Exception {
        this(validator);
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        ArrayNode array = (ArrayNode) _mapper.readTree(serialization);
        for (JsonNode object : array) {
            addBlock(object.asText());
        }
    }

    public List<? extends AbstractBlock> getBlocks() {
        return _blocks;
    }

    public void addBlock(T block) throws Exception {
        _validator.validate(block);
        _blocks.add(block);
    }

    abstract void addBlock(String serialization) throws Exception;

    public AbstractBlock lastBlock() {
        return (!_blocks.isEmpty()) ? _blocks.get(_blocks.size() - 1) : null;
    }

    public int size() {
        return _blocks.size();
    }

    public URI getIssuer() throws Exception {
        return (!_blocks.isEmpty()) ? _blocks.get(0).getIssuer() : null;
    }

    public URI getSubject() throws Exception {
        return (!_blocks.isEmpty()) ? _blocks.get(0).getSubject() : null;
    }

    public String getHash() throws Exception {
        return (!_blocks.isEmpty()) ? _blocks.get(0).getHash() : null;
    }

    public String serialize() throws Exception {
        ArrayNode array = _mapper.createArrayNode();
        for (T block : _blocks) {
            array.add(block.serialize());
        }
        return _mapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(array);
    }

    public void validate() throws Exception {
        if (lastBlock() != _validator.lastValidatedBlock()) {
            _validator.reset();
            for (T block : _blocks) {
                _validator.validate(block);
            }
        }
    }

    public void resetValidator() {
        _validator.reset();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AbstractChain)) {
            return false;
        }
        AbstractChain<?> that = (AbstractChain<?>) obj;
        return _blocks.equals(that._blocks);
    }

    @Override
    public int hashCode() {
        return _blocks.hashCode();
    }

    @Override
    public String toString() {
        try {
            ArrayNode array = _mapper.createArrayNode();
            for (T block : _blocks) {
                array.add(block.getPayload());
            }
            return _mapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(array);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
}
