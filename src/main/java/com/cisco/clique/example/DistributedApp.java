package com.cisco.clique.example;

import com.cisco.clique.cache.CliqueCache;
import com.cisco.clique.sdk.AuthBlockGrant;
import com.cisco.clique.sdk.AuthChain;
import com.cisco.clique.sdk.IdChain;
import com.cisco.clique.sdk.Identity;
import com.nimbusds.jose.jwk.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URI;
import java.security.Security;


public class DistributedApp {
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            CliqueCache cc = new CliqueCache();

            // create some identities
            Identity alice = new Identity(cc, URI.create("acct:alice@example.com"));
            Identity bob = new Identity(cc, URI.create("acct:bob@example.com"));
            Identity jack = new Identity(cc, URI.create("acct:jack@example.com"));
            Identity diane = new Identity(cc, URI.create("acct:diane@example.com"));
            Identity steve = new Identity(cc, URI.create("acct:steve@example.com"));

            // create identity authority and generate a new key
            Identity example = new Identity(cc, URI.create("acct:example.com"));
            ECKey exampleKey = example.newKey();

            // write the identity authority's public key to the public key cache
            cc.getPublicKeyCache().putKey(exampleKey.toPublicJWK());

            // create an ID chain for the identity authority
            IdChain idChain = new IdChain(cc);
            idChain.newBlockBuilder()
                    .setIssuer(example.getAcct())
                    .setIssuerKey(exampleKey)
                    .setSubject(example.getAcct())
                    .setSubjectPubKey(exampleKey.toPublicJWK())
                    .build();
            cc.getChainCache().putChain(idChain);

            // create id chains and push to idchain store and public key store
            {
                Identity[] ids = {alice, bob, jack, diane, steve};
                for (Identity id : ids) {

                    // create initial key
                    ECKey key = id.newKey();
                    cc.getPublicKeyCache().putKey(key.toPublicJWK());
                    idChain = new IdChain(cc);
                    idChain.newBlockBuilder()
                            .setIssuer(example.getAcct())
                            .setIssuerKey(example.getActiveKey())
                            .setSubject(id.getAcct())
                            .setSubjectPubKey(key.toPublicJWK())
                            .build();
                    cc.getChainCache().putChain(idChain);

                    // add another key
                    key = id.newKey();
                    cc.getPublicKeyCache().putKey(key.toPublicJWK());
                    idChain.newBlockBuilder()
                            .setIssuer(id.getAcct())
                            .setIssuerKey(key)
                            .build();
                }
            }

            // alice creates an authchain
            String aliceAuthChainBlob;
            String aliceAuthChainHash;
            {
                // alice creates an authchain for some resource
                AuthChain aliceAuthChain = new AuthChain(cc);

                // alice adds primordial grants and identities to the genesis block
                aliceAuthChain.newBlockBuilder()
                        .setIssuer(alice.getAcct())
                        .setIssuerKey(alice.getActiveKey())
                        .setSubject(URI.create("xmpp:teamroom@conference.example.com"))
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.VIRAL_GRANT, "participant", alice.getAcct()))
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.VIRAL_GRANT, "participant", bob.getAcct()))
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.VIRAL_GRANT, "moderator", bob.getAcct()))
                        .build();

                // alice serializes the chain and shares it
                aliceAuthChainBlob = aliceAuthChain.serialize();
                aliceAuthChainHash = aliceAuthChain.getGenesisHash();
            }

            //
            // alice shares the hash of the authchain genesis block securely with others (out of scope for now)
            // alice shares the authchain publicly, or sends it directly to others (out of scope for now)
            //

            // bob modifies alice's auth chain
            String bobAuthChainBlob;
            {
                // bob deserializes alice's authchain
                AuthChain bobAuthChain = new AuthChain(cc, aliceAuthChainBlob);

                // bob adds a new block with grants and identities
                bobAuthChain.newBlockBuilder()
                        .setIssuer(bob.getAcct())
                        .setIssuerKey(bob.getActiveKey())
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.GRANT, "participant", jack.getAcct()))
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.VIRAL_GRANT, "participant", diane.getAcct()))
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.GRANT, "moderator", diane.getAcct()))
                        .build();

                // bob serializes the chain and shares it
                bobAuthChainBlob = bobAuthChain.serialize();
            }

            // diane modifies alice's auth chain
            String dianeAuthChainBlob;
            {
                // diane deserializes bob's authchain
                AuthChain dianeAuthChain = new AuthChain(cc, bobAuthChainBlob);

                // diane has viral grant for "participant" privilege, so she can revoke from jack, and grant to steve
                dianeAuthChain.newBlockBuilder()
                        .setIssuer(diane.getAcct())
                        .setIssuerKey(diane.getActiveKey())
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.REVOKE, "participant", jack.getAcct()))
                        .addGrant(new AuthBlockGrant(cc, AuthBlockGrant.Type.GRANT, "participant", steve.getAcct()))
                        .build();

                // diane serializes the chain and shares it
                dianeAuthChainBlob = dianeAuthChain.serialize();
            }

            // deserialize diane's authchain
            AuthChain finalAuthChain = new AuthChain(cc, dianeAuthChainBlob);

            System.out.println("Actual Serialized AuthChain:\n\n" + finalAuthChain.serialize());
            System.out.println("\n\nPretty Printed AuthChain:\n\n" + finalAuthChain.toString());

            System.out.println("Actual Serialized IdChain (mfg):\n\n" + cc.getChainCache().getChain(example.getAcct()).serialize());
            System.out.println("\n\nPretty Printed IdChain (mfg):\n\n" + cc.getChainCache().getChain(example.getAcct()).toString());

            System.out.println("Actual Serialized IdChain (device):\n\n" + cc.getChainCache().getChain(alice.getAcct()).serialize());
            System.out.println("\n\nPretty Printed IdChain (device):\n\n" + cc.getChainCache().getChain(alice.getAcct()).toString());

            System.out.println("Public Key Store:\n\n" + cc.getPublicKeyCache().toString());

            // validate the final chain
            if (finalAuthChain.validate(aliceAuthChainHash)) {
                System.out.println("\n*** validation successful ***\n");
            } else {
                System.out.println("\n*** validation failed ***\n");
            }

            // print the policy represented by the authchain
            URI[] accts = {alice.getAcct(), bob.getAcct(), jack.getAcct(), diane.getAcct(), steve.getAcct()};
            for (URI acct : accts) {
                System.out.println(acct.toString() + "\thas \"participant\" privilege: " +
                        finalAuthChain.hasPrivilege(acct, "participant"));
                System.out.println(acct.toString() + "\thas  \"moderator\"  privilege: " +
                        finalAuthChain.hasPrivilege(acct, "moderator"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
