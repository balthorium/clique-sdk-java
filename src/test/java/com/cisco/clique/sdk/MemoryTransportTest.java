package com.cisco.clique.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.net.URI;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class MemoryTransportTest {
    Clique _clique;
    URI _mintUri;
    URI _aliceUri;
    URI _bobUri;
    URI _resourceUri;

    @BeforeTest
    public void suiteSetUp() {
        Security.addProvider(new BouncyCastleProvider());
        _clique = new Clique();
        _mintUri = URI.create("uri:clique:mint");
        _aliceUri = URI.create("uri:clique:alice");
        _bobUri = URI.create("uri:clique:bob");
        _resourceUri = URI.create("uri:clique:some:resource");
    }

    @BeforeMethod
    public void testSetUp() {
        _clique.getTransport().clear();
        _clique.getTrustRoots().clear();
    }

    @Test
    public void nonDefaultTransportAndTrustRootsTest() throws Exception {
        Transport transport = new MemoryTransport();
        Set<String> trustRoots = new HashSet<>();
        Clique clique = new Clique(transport, trustRoots);
        assertEquals(transport, clique.getTransport());
        assertEquals(trustRoots, clique.getTrustRoots());
    }

    @Test
    public void toStringTest() throws Exception {

        Identity mint = _clique.createIdentity(_mintUri);
        assertNotNull(mint);

        Identity alice = _clique.createIdentity(mint, _aliceUri);
        assertNotNull(alice);

        Identity bob = _clique.createIdentity(mint, _bobUri);
        assertNotNull(bob);

        Policy policy = _clique.createPolicy(alice, _resourceUri)
                .viralGrant(alice, "read")
                .grant(bob, "write")
                .grant(bob, "read")
                .build();
        assertNotNull(policy);

        String transportString = _clique.getTransport().toString();
        assertNotNull(transportString);
        assertTrue(transportString.length() > 0);
    }
}
