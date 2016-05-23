package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.InvalidBlockException;
import com.nimbusds.jose.jwk.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.net.URI;
import java.security.Security;

public class IdentityTest {
    URI _mintUri;
    URI _aliceUri;

    @BeforeTest
    public void suiteSetUp() {
        Security.addProvider(new BouncyCastleProvider());
        _mintUri = URI.create("uri:clique:mint");
        _aliceUri = URI.create("uri:clique:alice");
    }

    @BeforeMethod
    public void testSetUp() {
        SdkCommon.setTransport(new TransportLocal());
        SdkCommon.getTrustRoots().clear();
    }

    @Test
    public void newSelfAssertingIdentityTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Assert.assertEquals(mint.getAcct(), _mintUri);
    }

    @Test
    public void newMintAssertedIdentityTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);
        Assert.assertEquals(alice.getAcct(), _aliceUri);
    }

    @Test
    public void getKeyPairTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);
        ECKey key1 = alice.getActiveKeyPair();
        Assert.assertNotNull(key1);
        String pkt1 = key1.computeThumbprint().toString();
        ECKey key2 = alice.getKeyPair(pkt1);
        Assert.assertNotNull(key2);
        Assert.assertEquals(key2, key1);
    }

    @Test
    public void rotateKeyPairTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);
        ECKey oldKey = alice.getActiveKeyPair();
        Assert.assertNotNull(oldKey);
        ECKey newKey = alice.rotateKeyPair();
        Assert.assertNotNull(newKey);
        ECKey key = alice.getActiveKeyPair();
        Assert.assertNotNull(key);
        Assert.assertEquals(key, newKey);
        Assert.assertNotEquals(key, oldKey);
    }

    @Test
    public void blockDuplicateIdentitiesOnOneTransportTest() throws Exception {
        new Identity(_mintUri);
        Assert.assertThrows(IllegalArgumentException.class, () -> new Identity(_mintUri));
        SdkCommon.setTransport(new TransportLocal());
        new Identity(_mintUri);
        Assert.assertThrows(IllegalArgumentException.class, () -> new Identity(_mintUri));
    }

    @Test
    public void newPublicIdentityGetAcctTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);

        PublicIdentity alicePublic = new PublicIdentity(_aliceUri);
        Assert.assertNotNull(alicePublic);
        Assert.assertEquals(alicePublic.getAcct(), alice.getAcct());
    }

    @Test
    public void newUntrustedPublicIdentityTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        new Identity(mint, _aliceUri);
        SdkCommon.getTrustRoots().clear();
        Assert.assertThrows(InvalidBlockException.class, () -> new PublicIdentity(_aliceUri));
    }

    @Test
    public void publicIdentityGetPublicKeyTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);

        ECKey key1 = alice.getActiveKeyPair();
        Assert.assertNotNull(key1);
        Assert.assertTrue(key1.isPrivate());
        Assert.assertNotNull(key1.getD());

        PublicIdentity alicePublic = new PublicIdentity(_aliceUri);
        Assert.assertNotNull(alicePublic);

        ECKey pubkey1 = alicePublic.getActivePublicKey();
        Assert.assertNotNull(pubkey1);
        Assert.assertFalse(pubkey1.isPrivate());
        Assert.assertNull(pubkey1.getD());
        Assert.assertEquals(pubkey1.computeThumbprint(), key1.computeThumbprint());

        ECKey pubkey2 = alicePublic.getPublicKey(key1.computeThumbprint().toString());
        Assert.assertNotNull(pubkey2);
        Assert.assertFalse(pubkey2.isPrivate());
        Assert.assertNull(pubkey2.getD());
        Assert.assertEquals(pubkey2.computeThumbprint(), key1.computeThumbprint());
    }
}