package com.cisco.clique.sdk.chains;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.DateSerializer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

/**
 * Package utility functions for simple stuff (like creating properly configured ObjectMapper instances).
 */
public class SdkCommon {

    private static final SimpleModule _dateModule;

    static {
        Security.addProvider(new BouncyCastleProvider());

        /**
         * We want all object mappers to serialize date fields as UTC and in RFC-3339 iso-date-time format.
         */
        SimpleDateFormat rfc3339DateTimeFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        rfc3339DateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        _dateModule = new SimpleModule("rfc3339-date-time");
        _dateModule.addSerializer(new DateSerializer(false, rfc3339DateTimeFormat));
    }

    /**
     * Create a new JSON object mapper.
     *
     * @return A newly created JSON object mapper.
     */
    public static ObjectMapper createMapper() {
        ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.registerModule(_dateModule);
        return mapper;
    }

}

