package com.cisco.clique.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.*;

import java.net.URI;
import java.security.Security;

public class IdentityTest {

    private static final URI aliceUri = URI.create("acct:alice@example.com");
    private CliqueTransport _ct;

    @BeforeClass
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        _ct = new CliqueTransportLocal();
    }

    @Test
    public void createSimpleIdentityTest() throws Exception {
        Identity alice = new Identity(_ct, aliceUri);
        Assert.assertEquals(alice.getAcct(), aliceUri);
        Assert.assertNull(alice.getActiveKey());
    }
}