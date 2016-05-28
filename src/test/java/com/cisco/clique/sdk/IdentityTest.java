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

import static org.testng.Assert.*;

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
        assertEquals(mint.getAcct(), _mintUri);
    }

    @Test
    public void newMintAssertedIdentityTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);
        assertEquals(alice.getAcct(), _aliceUri);
    }

    @Test
    public void getKeyPairTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);
        ECKey key1 = alice.getActiveKeyPair();
        assertNotNull(key1);
        String pkt1 = key1.computeThumbprint().toString();
        ECKey key2 = alice.getKeyPair(pkt1);
        assertNotNull(key2);
        assertEquals(key2, key1);
    }

    @Test
    public void rotateKeyPairTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);
        ECKey oldKey = alice.getActiveKeyPair();
        assertNotNull(oldKey);
        ECKey newKey = alice.rotateKeyPair();
        assertNotNull(newKey);
        ECKey key = alice.getActiveKeyPair();
        assertNotNull(key);
        assertEquals(key, newKey);
        assertNotEquals(key, oldKey);
    }

    @Test
    public void blockDuplicateIdentitiesOnOneTransportTest() throws Exception {

        ThrowingRunnable newMintIdentity = new ThrowingRunnable() {
            @Override
            public void run() throws Exception {
                new Identity(_mintUri);
            }
        };

        new Identity(_mintUri);
        assertThrows(IllegalArgumentException.class, newMintIdentity);
        SdkCommon.setTransport(new TransportLocal());
        new Identity(_mintUri);
        assertThrows(IllegalArgumentException.class, newMintIdentity);
    }

    @Test
    public void newPublicIdentityGetAcctTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);

        PublicIdentity alicePublic = new PublicIdentity(_aliceUri);
        assertNotNull(alicePublic);
        assertEquals(alicePublic.getAcct(), alice.getAcct());
    }

    @Test
    public void validationStateCachingAndTrustRootTest() throws Exception {

        // create mint as a self-asserted identity and have it issue an identity for alice (cached to transport)
        new Identity(new Identity(_mintUri), _aliceUri);

        // now clear the trust roots
        SdkCommon.getTrustRoots().clear();

        // this fetch will still succeed because the cached identity was already validated (incremental validation)
        PublicIdentity alice = new PublicIdentity(_aliceUri);
        assertNotNull(alice);

        // now clear the identity's validation state
        alice.resetValidator();

        // it's still okay because the mint's identity state is still cached and considered valid
        alice = new PublicIdentity(_aliceUri);
        assertNotNull(alice);

        // now clear both mint and identity's validation states
        PublicIdentity mint = new PublicIdentity(_mintUri);
        assertNotNull(mint);
        mint.resetValidator();
        alice = new PublicIdentity(_aliceUri);
        assertNotNull(alice);
        alice.resetValidator();

        // fails to revalidate because validation starts from scratch and mint is no longer a trust root
        assertThrows(InvalidBlockException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                new PublicIdentity(_aliceUri);
            }
        });
    }

    @Test
    public void publicIdentityGetPublicKeyTest() throws Exception {
        Identity mint = new Identity(_mintUri);
        Identity alice = new Identity(mint, _aliceUri);

        ECKey key1 = alice.getActiveKeyPair();
        assertNotNull(key1);
        Assert.assertTrue(key1.isPrivate());
        assertNotNull(key1.getD());

        PublicIdentity alicePublic = new PublicIdentity(_aliceUri);
        assertNotNull(alicePublic);

        ECKey pubkey1 = alicePublic.getActivePublicKey();
        assertNotNull(pubkey1);
        assertFalse(pubkey1.isPrivate());
        assertNull(pubkey1.getD());
        assertEquals(pubkey1.computeThumbprint(), key1.computeThumbprint());

        ECKey pubkey2 = alicePublic.getPublicKey(key1.computeThumbprint().toString());
        assertNotNull(pubkey2);
        assertFalse(pubkey2.isPrivate());
        assertNull(pubkey2.getD());
        assertEquals(pubkey2.computeThumbprint(), key1.computeThumbprint());
    }

    @Test
    public void serializeDeserializePublicIdentity() throws Exception {
        new Identity(new Identity(_mintUri), _aliceUri);
        PublicIdentity alicePublic1 = new PublicIdentity(_aliceUri);
        assertNotNull(alicePublic1);
        String alicePublicSerialized = alicePublic1.serialize();
        assertNotNull(alicePublicSerialized);
        PublicIdentity alicePublic2 = new PublicIdentity(alicePublicSerialized);
        assertEquals(alicePublic2, alicePublic1);
    }

    @Test
    public void serializeDeserializeIdentity() throws Exception {
        Identity alice1 = new Identity(new Identity(_mintUri), _aliceUri);
        String aliceSerialized = alice1.serialize();
        assertNotNull(aliceSerialized);
        Identity alice2 = new Identity(aliceSerialized);
        assertEquals(alice2, alice1);
    }
}