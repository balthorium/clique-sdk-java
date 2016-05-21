package com.cisco.clique.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;

/**
 * Represents grant assertions as contained within authorization chain blocks.
 */
class AuthBlockGrant {

    private static final ObjectMapper _mapper = SdkUtils.createMapper();
    private Type _type;
    private String _privilege;
    private URI _grantee;
    private String _pkt;

    /**
     * Creates a new grant.
     *
     * @param type      The type of grant being asserted.
     * @param grantee   The identity to which the grant is extended.
     * @param privilege The privilege to which the grant applies.
     * @throws Exception On failure.
     */
    AuthBlockGrant(Type type, URI grantee, String privilege) throws Exception {
        if (null == type || null == privilege || null == grantee) {
            throw new IllegalArgumentException();
        }
        _type = type;
        _grantee = grantee;
        _privilege = privilege;
        _pkt = ((IdChain) SdkUtils.getPublicRepo().getChain(grantee)).getActivePkt();
    }

    /**
     * Creates a grant from a given parsed JSON document.
     *
     * @param node The root of the JSON document representing a grant.
     */
    AuthBlockGrant(JsonNode node) {
        _type = Type.valueOf(node.findPath("type").asText());
        _privilege = node.findPath("privilege").asText();
        _grantee = URI.create(node.findPath("grantee").asText());
        _pkt = node.findPath("pkt").asText();
    }

    /**
     * Produces parsed JSON document from the current state of this grant object.
     *
     * @return A parsed JSON document representing this grant.
     * @throws IOException
     */
    ObjectNode toJson() throws IOException {
        ObjectNode grant = _mapper.createObjectNode();
        grant.put("type", _type.toString());
        grant.put("privilege", _privilege);
        grant.put("grantee", _grantee.toString());
        return grant;
    }

    /**
     * Return the type of this grant.
     *
     * @return The type of this grant.
     */
    Type getType() {
        return _type;
    }

    /**
     * Return the privilege to which this grant applies.
     *
     * @return The privilege to which this grant applies.
     */
    String getPrivilege() {
        return _privilege;
    }

    /**
     * Return the identity to which this grant is extended.
     *
     * @return The identity to which this grant is extended.
     */
    URI getGrantee() {
        return _grantee;
    }

    /**
     * A human readable representation of the grant, useful for logging.
     *
     * @return A string representation of the AuthBlockGrant object's state.
     */
    @Override
    public String toString() {
        String retval = null;
        try {
            retval = _mapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(toJson());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return retval;
    }

    enum Type {

        /**
         * A privilege grant that also carries the right to extend the same privilege to other identities.
         */
        VIRAL_GRANT,

        /**
         * A privilege grant.
         */
        GRANT,

        /**
         * A revocation of privilege.
         */
        REVOKE
    }
}


