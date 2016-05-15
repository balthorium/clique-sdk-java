package com.cisco.clique.sdk;

import com.nimbusds.jose.jwk.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.*;

import java.net.URI;
import java.security.Security;

public class IdentityTest {

    private static final URI aliceUri = URI.create("acct:alice@example.com");
    private Transport _ct;

    @BeforeClass
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        _ct = new TransportLocal();
    }

    @Test
    public void selfAssertedIdentityTest() throws Exception {

        // create and test self-asserted identity
        Identity alice = new Identity(_ct, aliceUri);
        Assert.assertEquals(alice.getAcct(), aliceUri);
        ECKey activeKey = alice.getActiveKey();
        Assert.assertNotNull(activeKey);
        String activePkt = activeKey.computeThumbprint().toString();
        alice.getKey(activePkt);

        // check the automatically generated idchain
        IdChain aliceChain = (IdChain) _ct.getChain(aliceUri);
        Assert.assertNotNull(aliceChain);
        Assert.assertEquals(aliceChain.getIssuer(), aliceUri);
        Assert.assertEquals(aliceChain.getSubject(), aliceUri);
        Assert.assertEquals(aliceChain.size(), 1);
        Assert.assertEquals(aliceChain.getActivePkt(), activePkt);
        Assert.assertEquals(aliceChain.getGenesisHash(), aliceChain.getBlock(0).getHash());
        Assert.assertNotNull(aliceChain.toString());
        Assert.assertTrue(aliceChain.validate(alice.getTrustRoots()));
    }

}