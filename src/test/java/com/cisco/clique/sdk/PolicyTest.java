package com.cisco.clique.sdk;

import com.cisco.clique.sdk.chains.InvalidBlockException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.net.URI;
import java.security.Security;
import java.util.HashSet;

import static org.testng.Assert.*;

public class PolicyTest {
    Clique _clique;
    URI _mintUri, _aliceUri, _bobUri, _chuckUri, _dianeUri, _resourceUri;
    Identity _alice, _bob, _chuck, _diane;
    String _readPrivilege;
    String _writePrivilege;

    @BeforeTest
    public void suiteSetUp() {
        Security.addProvider(new BouncyCastleProvider());
        _clique = Clique.getInstance();
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
        _clique.setTransport(new TransportLocal());
        _clique.setTrustRoots(new HashSet<String>());

        Identity mint = _clique.createIdentity(_mintUri);
        _alice = _clique.createIdentity(mint, _aliceUri);
        _bob = _clique.createIdentity(mint, _bobUri);
        _chuck = _clique.createIdentity(mint, _chuckUri);
        _diane = _clique.createIdentity(mint, _dianeUri);
    }

    @Test
    public void newPolicyTest() throws Exception {

        PublicIdentity bobPublic = _clique.getPublicIdentity(_bobUri);

        Policy policy = _clique.createPolicy(_alice, _resourceUri)
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
            PublicIdentity bobPublic = _clique.getPublicIdentity(_bobUri);

            _clique.createPolicy(_alice, _resourceUri)
                    .viralGrant(bobPublic, _readPrivilege)
                    .grant(bobPublic, _writePrivilege)
                    .commit();
        }

        // bob does this
        {
            PublicIdentity chuckPublic = _clique.getPublicIdentity(_chuckUri);

            Policy policy = _clique.getPolicy(_resourceUri);
            assertNotNull(policy);
            policy.update(_bob)
                    .grant(chuckPublic, _readPrivilege)
                    .commit();

            assertTrue(policy.hasPrivilege(chuckPublic, _readPrivilege));
        }

        // chuck does this
        {
            final Policy policy = _clique.getPolicy(_resourceUri);
            assertNotNull(policy);
            assertTrue(policy.hasPrivilege(_chuck, _readPrivilege));
            assertFalse(policy.hasPrivilege(_chuck, _writePrivilege));

            final PublicIdentity dianePublic = _clique.getPublicIdentity(_dianeUri);
            assertThrows(InvalidBlockException.class, new ThrowingRunnable() {
                @Override
                public void run() throws Exception {
                    policy.update(_chuck)
                            .grant(dianePublic, _readPrivilege)
                            .commit();
                }
            });
            assertFalse(policy.hasPrivilege(dianePublic, _readPrivilege));
        }
    }
}