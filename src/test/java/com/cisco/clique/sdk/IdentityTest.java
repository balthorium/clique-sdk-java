package com.cisco.clique.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.*;

import java.net.URI;
import java.security.Security;
import java.util.HashSet;

public class IdentityTest {

    @BeforeClass
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        SdkUtils.setTransport(new LocalTransport());
        SdkUtils.setTrustRoots(new HashSet<String>() {{ add("hashyMcHashface"); }});
    }

    @Test
    public void selfAssertedIdentityTest() throws Exception {

        // create and test self-asserted identity
//        Identity alice = new Identity(_ct, aliceUri);
//        Assert.assertEquals(alice.getAcct(), aliceUri);
//        ECKey activeKey = alice.getActiveKeyPair();
//        Assert.assertNotNull(activeKey);
//        String activePkt = activeKey.computeThumbprint().toString();
//        alice.getKeyPair(activePkt);
//
//        // check the automatically generated idchain
//        IdChain aliceChain = (IdChain) _ct.getChain(aliceUri);
//        Assert.assertNotNull(aliceChain);
//        Assert.assertEquals(aliceChain.getIssuer(), aliceUri);
//        Assert.assertEquals(aliceChain.getSubject(), aliceUri);
//        Assert.assertEquals(aliceChain.size(), 1);
//        Assert.assertEquals(aliceChain.getActivePkt(), activePkt);
//        Assert.assertEquals(aliceChain.getGenesisHash(), aliceChain.getBlock(0).getHash());
//        Assert.assertNotNull(aliceChain.toString());
//        Assert.assertTrue(aliceChain.validate(alice.getTrustRoots()));
    }


    @Test
    public void newIdentityText() throws Exception {

        URI meUri = URI.create("uri:clique:alice");
        URI youUri = URI.create("uri:clique:bob");
        URI resourceUri = URI.create("uri:some:protected:resource");
        String readPrivilege = "read";
        String writePrivilege = "write";

        Identity me = new Identity(meUri);
        new Identity(youUri);
        PublicIdentity you = new PublicIdentity(youUri);

        me.createPolicy(resourceUri)
                .viralGrant(me, readPrivilege)
                .viralGrant(you, writePrivilege)
                .build();

        me.updatePolicy(resourceUri)
                .grant(you, readPrivilege)
                .build();

        Assert.assertTrue(me.hasPrivilege(resourceUri, readPrivilege));
        Assert.assertFalse(me.hasPrivilege(resourceUri, writePrivilege));
        Assert.assertTrue(you.hasPrivilege(resourceUri, readPrivilege));
        Assert.assertTrue(you.hasPrivilege(resourceUri, writePrivilege));
    }
}