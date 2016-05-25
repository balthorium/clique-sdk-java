package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.InvalidBlockException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.net.URI;
import java.security.Security;

import static org.testng.Assert.*;

public class PolicyTest {
    URI _mintUri, _aliceUri,_bobUri, _chuckUri,_dianeUri, _resourceUri;
    Identity _alice, _bob, _chuck, _diane;
    String _readPrivilege;
    String _writePrivilege;

    @BeforeTest
    public void suiteSetUp() {
        Security.addProvider(new BouncyCastleProvider());
        _mintUri = URI.create("uri:clique:mint");
        _aliceUri = URI.create("uri:clique:alice");
        _bobUri = URI.create("uri:clique:bob");
        _chuckUri = URI.create("uri:clique:chuck");
        _dianeUri = URI.create("uri:clique:diane");

        _resourceUri = URI.create("uri:some:protected:resource");
        _readPrivilege = "read";
        _writePrivilege = "write";
    }

    @BeforeMethod
    public void testSetUp() throws Exception {
        SdkCommon.setTransport(new TransportLocal());
        SdkCommon.getTrustRoots().clear();
        Identity mint = new Identity(_mintUri);
        _alice = new Identity(mint, _aliceUri);
        _bob = new Identity(mint, _bobUri);
        _chuck = new Identity(mint, _chuckUri);
        _diane = new Identity(mint, _dianeUri);
    }

    @Test
    public void newPolicyTest() throws Exception {

        PublicIdentity bobPublic = PublicIdentity.get(_bobUri);

        Policy policy = Policy.create(_alice, _resourceUri)
                .viralGrant(_alice, _readPrivilege)
                .grant(bobPublic, _writePrivilege)
                .commit();

        policy.update(_alice)
                .grant(bobPublic, _readPrivilege)
                .commit();

        assertTrue(policy.hasPrivilege(_alice, _readPrivilege));
        assertFalse(policy.hasPrivilege(_alice, _writePrivilege));
        assertTrue(policy.hasPrivilege(bobPublic, _readPrivilege));
        assertTrue(policy.hasPrivilege(bobPublic, _writePrivilege));
    }

    @Test
    public void viralPrivilegeTest() throws Exception {

        // alice does this
        {
            PublicIdentity bobPublic = PublicIdentity.get(_bobUri);

            Policy.create(_alice, _resourceUri)
                    .viralGrant(bobPublic, _readPrivilege)
                    .grant(bobPublic, _writePrivilege)
                    .commit();
        }

        // bob does this
        {
            PublicIdentity chuckPublic = PublicIdentity.get(_chuckUri);

            Policy policy = Policy.get(_resourceUri);
            assertNotNull(policy);
            policy.update(_bob)
                    .grant(chuckPublic, _readPrivilege)
                    .commit();

            assertTrue(policy.hasPrivilege(chuckPublic, _readPrivilege));
        }

        // chuck does this
        {
            Policy policy = Policy.get(_resourceUri);
            assertNotNull(policy);
            assertTrue(policy.hasPrivilege(_chuck, _readPrivilege));
            assertFalse(policy.hasPrivilege(_chuck, _writePrivilege));

            PublicIdentity dianePublic = PublicIdentity.get(_dianeUri);

            assertThrows(InvalidBlockException.class, () -> policy.update(_chuck)
                    .grant(dianePublic, _readPrivilege)
                    .commit());

            assertFalse(policy.hasPrivilege(dianePublic, _readPrivilege));
        }
    }
}