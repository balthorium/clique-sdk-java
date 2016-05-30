package com.cisco.clique.sdk;

import com.cisco.clique.sdk.validation.InvalidBlockException;
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
        _clique = new Clique();
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
        _clique.setTransport(new MemoryTransport());
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
                .build();

        policy.update(_alice)
                .grant(bobPublic, _readPrivilege)
                .build();

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
                    .build();
        }

        // bob does this
        {
            PublicIdentity chuckPublic = _clique.getPublicIdentity(_chuckUri);

            Policy policy = _clique.getPolicy(_resourceUri);
            assertNotNull(policy);
            policy.update(_bob)
                    .grant(chuckPublic, _readPrivilege)
                    .build();

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
                            .build();
                }
            });
            assertFalse(policy.hasPrivilege(dianePublic, _readPrivilege));
        }
    }

    @Test
    public void revokeTest() throws Exception {

        Policy policy = _clique.createPolicy(_alice, _resourceUri)
                .viralGrant(_bob, _readPrivilege)
                .viralGrant(_chuck, _readPrivilege)
                .grant(_diane, _readPrivilege)
                .build();

        assertNotNull(policy);
        assertFalse(policy.hasPrivilege(_alice, _readPrivilege));
        assertTrue(policy.hasPrivilege(_bob, _readPrivilege));
        assertTrue(policy.hasPrivilege(_chuck, _readPrivilege));
        assertTrue(policy.hasPrivilege(_diane, _readPrivilege));

        policy.update(_bob)
                .revoke(_chuck, _readPrivilege)
                .revoke(_diane, _readPrivilege)
                .build();

        assertNotNull(policy);
        assertFalse(policy.hasPrivilege(_alice, _readPrivilege));
        assertTrue(policy.hasPrivilege(_bob, _readPrivilege));
        assertFalse(policy.hasPrivilege(_chuck, _readPrivilege));
        assertFalse(policy.hasPrivilege(_diane, _readPrivilege));
    }

    @Test
    public void serializeDeserializePolicy() throws Exception {

        Policy policy1 = _clique.createPolicy(_alice, _resourceUri)
                .viralGrant(_alice, _readPrivilege)
                .viralGrant(_alice, _writePrivilege)
                .viralGrant(_bob, _readPrivilege)
                .grant(_bob, _writePrivilege)
                .build();

        assertNotNull(policy1);

        policy1.update(_bob)
                .viralGrant(_chuck, _readPrivilege)
                .grant(_diane, _readPrivilege)
                .build();

        String policySerialized = policy1.serialize();
        assertNotNull(policySerialized);
        Policy policy2 = _clique.deserializePolicy(policySerialized);
        assertEquals(policy2, policy1);

        assertTrue(policy2.hasPrivilege(_alice, _readPrivilege));
        assertTrue(policy2.hasPrivilege(_alice, _writePrivilege));
        assertTrue(policy2.hasPrivilege(_bob, _readPrivilege));
        assertTrue(policy2.hasPrivilege(_bob, _writePrivilege));
        assertTrue(policy2.hasPrivilege(_chuck, _readPrivilege));
        assertFalse(policy2.hasPrivilege(_chuck, _writePrivilege));
        assertTrue(policy2.hasPrivilege(_diane, _readPrivilege));
        assertFalse(policy2.hasPrivilege(_diane, _writePrivilege));
    }

    @Test
    public void createBadPolicyTest() throws Exception {

        assertThrows(IllegalArgumentException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.createPolicy(_alice, null).build();
            }
        });

        assertThrows(IllegalArgumentException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.createPolicy(null, null).build();
            }
        });

        assertThrows(IllegalArgumentException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.createPolicy(null, _resourceUri).build();
            }
        });

        _clique.getTransport().clear();
        _alice.resetValidator();

        assertThrows(InvalidBlockException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.createPolicy(_alice, _resourceUri).build();
            }
        });
    }

    @Test
    public void getBadPolicyTest() throws Exception {

        assertThrows(IllegalArgumentException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.getPolicy(_resourceUri);
            }
        });

        assertThrows(IllegalArgumentException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.getPolicy(_aliceUri);
            }
        });

        assertThrows(IllegalArgumentException.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                _clique.getPolicy(null);
            }
        });
    }
}