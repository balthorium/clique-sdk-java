package com.cisco.clique.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.net.URI;
import java.security.Security;

public class PolicyTest {
    URI _mintUri;
    URI _aliceUri;
    URI _bobUri;

    Identity _alice;
    Identity _bob;

    @BeforeTest
    public void suiteSetUp() {
        Security.addProvider(new BouncyCastleProvider());
        _mintUri = URI.create("uri:clique:mint");
        _aliceUri = URI.create("uri:clique:alice");
        _bobUri = URI.create("uri:clique:bob");
    }

    @BeforeMethod
    public void testSetUp() throws Exception {
        SdkUtils.setTransport(new CacheTransport());
        SdkUtils.getTrustRoots().clear();
        Identity mint = new Identity(_mintUri);
        _alice = new Identity(mint, _aliceUri);
        _bob = new Identity(mint, _bobUri);
    }


    @Test
    public void newPolicyTest() throws Exception {
        URI resourceUri = URI.create("uri:some:protected:resource");
        String readPrivilege = "read";
        String writePrivilege = "write";

        PublicIdentity bobPublic = new PublicIdentity(_bobUri);

        _alice.createPolicy(resourceUri)
                .viralGrant(_alice, readPrivilege)
                .viralGrant(bobPublic, writePrivilege)
                .build();

        _alice.updatePolicy(resourceUri)
                .grant(bobPublic, readPrivilege)
                .build();

        Assert.assertTrue(_alice.hasPrivilege(resourceUri, readPrivilege));
        Assert.assertFalse(_alice.hasPrivilege(resourceUri, writePrivilege));
        Assert.assertTrue(bobPublic.hasPrivilege(resourceUri, readPrivilege));
        Assert.assertTrue(bobPublic.hasPrivilege(resourceUri, writePrivilege));
    }
}