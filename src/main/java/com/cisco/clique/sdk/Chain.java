package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.ArrayList;

abstract class Chain<T extends Block> {

    protected Validator<T> _validator;
    protected ArrayList<T> _blocks;
    protected static final ObjectMapper _mapper = SdkUtils.createMapper();

    Chain(Validator<T> validator) {
        _validator = validator;
        _blocks = new ArrayList<>();
    }

    Chain(Validator<T> validator, String serialization) throws Exception {
        this(validator);
        if (null == serialization) {
            throw new IllegalArgumentException();
        }
        ArrayNode array = (ArrayNode) _mapper.readTree(serialization);
        for (JsonNode object : array) {
            addBlock(object.asText());
        }
    }

    void addBlock(T block) throws Exception {
        _validator.validate(block);
        _blocks.add(block);
    }

    abstract void addBlock(String serialization) throws Exception;

    Block lastBlock() {
        if (!_blocks.isEmpty()) {
            return _blocks.get(_blocks.size() - 1);
        }
        return null;
    }

    int size() {
        return _blocks.size();
    }

    URI getIssuer() throws Exception {
        return (!_blocks.isEmpty()) ? _blocks.get(0).getIssuer() : null;
    }

    URI getSubject() throws Exception {
        return (!_blocks.isEmpty()) ? _blocks.get(0).getSubject() : null;
    }

    String getHash() throws Exception {
        return (!_blocks.isEmpty()) ? _blocks.get(0).getHash() : null;
    }

    String serialize() throws Exception {
        ArrayNode array = _mapper.createArrayNode();
        for (T block : _blocks) {
            array.add(block.serialize());
        }
        return _mapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(array);
    }

    void validate() throws Exception {
        _validator.reset();
        for (T block : _blocks) {
            _validator.validate(block);
        }
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
        return null;
    }
}
