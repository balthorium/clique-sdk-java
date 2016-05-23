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
    URI _chuckUri;
    URI _dianeUri;

    URI _resourceUri;

    Identity _alice;
    Identity _bob;
    Identity _chuck;
    Identity _diane;

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
        SdkUtils.setTransport(new MemoryTransport());
        SdkUtils.getTrustRoots().clear();
        Identity mint = new Identity(_mintUri);
        _alice = new Identity(mint, _aliceUri);
        _bob = new Identity(mint, _bobUri);
        _chuck = new Identity(mint, _chuckUri);
        _diane = new Identity(mint, _dianeUri);
    }


    @Test
    public void newPolicyTest() throws Exception {

        PublicIdentity bobPublic = new PublicIdentity(_bobUri);

        _alice.createPolicy(_resourceUri)
                .viralGrant(_alice, _readPrivilege)
                .grant(bobPublic, _writePrivilege)
                .commit();

        _alice.updatePolicy(_resourceUri)
                .grant(bobPublic, _readPrivilege)
                .commit();

        Assert.assertTrue(_alice.hasPrivilege(_resourceUri, _readPrivilege));
        Assert.assertFalse(_alice.hasPrivilege(_resourceUri, _writePrivilege));
        Assert.assertTrue(bobPublic.hasPrivilege(_resourceUri, _readPrivilege));
        Assert.assertTrue(bobPublic.hasPrivilege(_resourceUri, _writePrivilege));
    }

    @Test
    public void viralPrivilegeTest() throws Exception {

        // alice does this
        {
            PublicIdentity bobPublic = new PublicIdentity(_bobUri);

            _alice.createPolicy(_resourceUri)
                    .viralGrant(bobPublic, _readPrivilege)
                    .grant(bobPublic, _writePrivilege)
                    .commit();
        }

        // bob does this
        {
            PublicIdentity chuckPublic = new PublicIdentity(_chuckUri);

            _bob.updatePolicy(_resourceUri)
                    .grant(chuckPublic, _readPrivilege)
                    .commit();

            Assert.assertTrue(chuckPublic.hasPrivilege(_resourceUri, _readPrivilege));
        }

        // chuck does this
        {
            Assert.assertTrue(_chuck.hasPrivilege(_resourceUri, _readPrivilege));
            Assert.assertFalse(_chuck.hasPrivilege(_resourceUri, _writePrivilege));

            PublicIdentity dianePublic = new PublicIdentity(_dianeUri);

            _chuck.updatePolicy(_resourceUri)
                    .grant(dianePublic, _readPrivilege)
                    .commit();

            // Assert.assertFalse(dianePublic.hasPrivilege(_resourceUri, _readPrivilege));

            // TODO: AuthChain validation needs to be updated to make policy trust root logic modular
        }
    }
}