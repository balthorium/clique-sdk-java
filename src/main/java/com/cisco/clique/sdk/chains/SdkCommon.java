package com.cisco.clique.sdk.chains;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.DateSerializer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class SdkCommon {

    private static final SimpleModule _dateModule;

    static {
        Security.addProvider(new BouncyCastleProvider());
        SimpleDateFormat rfc3339DateTimeFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        rfc3339DateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        _dateModule = new SimpleModule("rfc3339-date-time");
        _dateModule.addSerializer(new DateSerializer(false, rfc3339DateTimeFormat));
    }

    public static ObjectMapper createMapper() {
        ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.registerModule(_dateModule);
        return mapper;
    }

}

