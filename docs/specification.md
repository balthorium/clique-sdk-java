# Clique Representation Specification

_TODO: update this specification to match current implementation._

A Clique is a data structure that represents a collection of identities with associated authorization policy.  Identities may correspond to end users, devices, processes, network elements, or any other active object in a distributed application.  Authorization policy is manifest as a series of privilege grants, each of which is extended from one identity to another.  

Identities and grants are encoded within an ordered and immutable array of data blocks that permits updates only through appending new blocks.  This array is regarded as a "chain" because each block contains a logical reference to its immediately predecessor.  This reference, referred to as the "antecedent", takes the form of a cryptographic hash of the preceding block.  Each block is signed by its creator and the associated public key made discoverable through the Clique itself.  As such, the Clique structure is secure from tampering by third parties, and almost entirely self-contained.

The following sections outline a structural specification for Clique.  Note, JSON structural specifications are provided using JSON Content Rules, as defined in [https://tools.ietf.org/html/draft-newton-json-content-rules-05].


## Identity Declarations
An identity is an (acct, key) pair.  The acct value represents an account URI and must follow the scheme defined in RFC7565.  The key value represents a user's public key, and must be represented as a JSON serialized JWK following the scheme defined in RFC7515.  The only JWK key type currently supported is EC using the P-256 curve.

```
public_jwk {
	"kty" : "EC",
	"crv" : "P-256",
	"x" : string,
	"y" : string
}
```

```
identity "identity" {
	"acct" : uri,
	"key" : public_jwk
}
```

*Example*

```
{
  "acct" : "acct:alice@example.com",
  "key" : {
    "kty" : "EC",
    "crv" : "P-256",
    "x" : "6kFsljY5w2NuqbgUL-Uncm-rtwTHNXrkSh8mqXEAf6w",
    "y" : "UmMCjhozv4wQ56OU1bBqrfcQ8yUzvXIKsAtWWP8HJGg"
  }
}
```

## Grant Declarations
A grant is a (type, privilege, grantee) tuple.  The type may be one of GRANT, REVOKE, or VIRAL_GRANT.  These represent, respectively, the extension of a grant to a grantee, the revocation of a grant from a grantee, and the extension of a grant to a grantee with the additional right to grant the same privilege to others.  The privilege is any string that represents a logical authorization with semantic meaning to the application(s) that consume the Clique, but is treated as opaque by this specification.  The grantee represents an account URI and must follow the scheme defined in RFC7565.  Furthermore, the grantee attribute must match the acct attribute of an identity declared in the same or prior block in the chain.

```
grant "grant" {
	"type" : < "GRANT" "REVOKE" "VIRAL_GRANT" >,
	"privilege" : string,
	"grantee" : uri
}
```

*Example*

```
{
  "type" : "VIRAL_GRANT",
  "privilege" : "participant",
  "grantee" : "acct:alice@example.com"
}
```

## Authorization Block Payload

An authorization block represents a collection of identity and grant declarations.  Each block may contain an array of identity declarations, may contain an array of grant declarations, must include the URI of the identity that is creating the block, and must include a hash of the block that precedes it in the chain.

```
authblock {
  "creator" : uri,
  "antecedent" : string,
  "identities" : [ *: identity ],
  "grants" : [ *: grants ]
}
```

*Example*

```
{
  "antecedent" : "fa754f462333e73a2dfe8e3a6c3054db0f499a4753b4c6277c39caf6e24da8f9",
  "creator" : "acct:diane@example.com",
  "identities" : [ {
    "acct" : "acct:steve@example.com",
    "key" : {
      "kty" : "EC",
      "crv" : "P-256",
      "x" : "5jm3X_4fT7PNRZNIoHBQ9YjLpUv2HRIJW_LvEOm_G0k",
      "y" : "VRuBxOa-QjY4vmDFm4ldsAZMsAaeyWBgMWs1dgiyP6Y"
    }
  } ],
  "grants" : [ {
    "type" : "REVOKE",
    "privilege" : "participant",
    "grantee" : "acct:jack@example.com"
  }, {
    "type" : "GRANT",
    "privilege" : "participant",
    "grantee" : "acct:steve@example.com"
  } ]
}
```

The creator attribute represents an account URI and must follow the scheme defined in RFC7565.  The value of creator must also match the acct attribute of an identity declared in a previous block in the chain.  The antecedent attribute is a hex-encoded string representing the SHA-256 hash of the full serialization of the block that immediately precedes this block.  The identities attribute is a JSON array containing zero or more identity declarations, as defined above; and the grants attribute is similarly a JSON array containing zero or more grant declarations, also as defined above.  If either the identities or grants arrays are not included in the block, they are treated the same as having been present but empty.

## Genesis Block Payload

A genesis block is a special type of authorization block that appears exclusively at the beginning of an Clique.  It is very similar to an authorization block, with minor exceptions.  Unlike other blocks, a genesis block does not include an antecedent attribute.  Also, the creator attribute of a genesis block can (and must) match the acct attribute of an identity declared within the genesis block itself.  Finally, a genesis block must include a resource attribute for which the value is the URI of a network resource or object to which the authorization policies of the chain apply.

```
genesisblock {
  "creator" : uri,
  "resource" : uri,
  "identities" : [ *: identity ],
  "grants" : [ *: grants ]
}
```

*Example*

```
{
  "creator" : "acct:alice@example.com",
  "identities" : [ {
    "acct" : "acct:alice@example.com",
    "key" : {
      "kty" : "EC",
      "crv" : "P-256",
      "x" : "6kFsljY5w2NuqbgUL-Uncm-rtwTHNXrkSh8mqXEAf6w",
      "y" : "UmMCjhozv4wQ56OU1bBqrfcQ8yUzvXIKsAtWWP8HJGg"
    }
  }, {
    "acct" : "acct:bob@example.com",
    "key" : {
      "kty" : "EC",
      "crv" : "P-256",
      "x" : "aLySIu10J36IfXFcyBe8vzeOYLOnoVHIDKMW5hZC6Zs",
      "y" : "a6qYlL8QTNW8xHXPmqmWKV7x_6p1_wc1D7Ki5HgPAHI"
    }
  } ],
  "grants" : [ {
    "type" : "VIRAL_GRANT",
    "privilege" : "participant",
    "grantee" : "acct:alice@example.com"
  }, {
    "type" : "VIRAL_GRANT",
    "privilege" : "participant",
    "grantee" : "acct:bob@example.com"
  }, {
    "type" : "VIRAL_GRANT",
    "privilege" : "moderator",
    "grantee" : "acct:bob@example.com"
  } ],
  "resource" : "xmpp:teamroom@conference.example.com"
}
```

## Block Serialization

Authorization blocks and genesis blocks must be signed and serialized.  Specifically, a block must be signed using the private key that corresponds to the public key given in an identity declaration found previously in the chain (or within the same block, in the case of genesis blocks).  This identity declaration is recognized by matching its acct attribute to the creator attribute of the block being signed.  If there are more than one identity declarations that meet this criteria, the most recently appended (latest) identity declaration must be used.

```
authblock_serialized = JWS(creator_pubkey, authblock)

genesisblock_serialized = JWS(creator_pubkey, genesisblock)
```

*Example*

```
eyJhbGciOiJFUzI1NiJ9.ewogICJhbnRlY2VkZW50IiA6ICI5ZWYxZjZlNzU5YzY2MjdkODYzMjVlNDJiNTcwNTlmYzU2OGUzZDRlMzQ2NzlmOTM0Mjk3MTg4NTI4NTg5OWUxIiwKICAiY3JlYXRvciIgOiAiYWNjdDpib2JAZXhhbXBsZS5jb20iLAogICJpZGVudGl0aWVzIiA6IFsgewogICAgImFjY3QiIDogImFjY3Q6amFja0BleGFtcGxlLmNvbSIsCiAgICAia2V5IiA6IHsKICAgICAgImt0eSIgOiAiRUMiLAogICAgICAiY3J2IiA6ICJQLTI1NiIsCiAgICAgICJ4IiA6ICJXQnRWR1lJOXNQdXdrcjlzUkFPWWJFX3JYNzBCeVlPQ2x2VEQtTHZZSEl3IiwKICAgICAgInkiIDogIjhDemZ2Yy1NZlIwMXROcngxUWYtNHdUYXAtU2UxQVZoQ2hUZTNoWEtFa1kiCiAgICB9CiAgfSwgewogICAgImFjY3QiIDogImFjY3Q6ZGlhbmVAZXhhbXBsZS5jb20iLAogICAgImtleSIgOiB7CiAgICAgICJrdHkiIDogIkVDIiwKICAgICAgImNydiIgOiAiUC0yNTYiLAogICAgICAieCIgOiAiLVk0NmUyLTJ4dnRfaTVlZV9TQUQ3Y3JXMmRJekp3STA4Vk1vNEEtSzVlayIsCiAgICAgICJ5IiA6ICJyZmZPQWlPNFhDTlJOUnB2S1k2REtvaEtRYW9acHVubEFOa2VmQlRqSEFvIgogICAgfQogIH0gXSwKICAiZ3JhbnRzIiA6IFsgewogICAgInR5cGUiIDogIkdSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OmphY2tAZXhhbXBsZS5jb20iCiAgfSwgewogICAgInR5cGUiIDogIlZJUkFMX0dSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OmRpYW5lQGV4YW1wbGUuY29tIgogIH0sIHsKICAgICJ0eXBlIiA6ICJHUkFOVCIsCiAgICAicHJpdmlsZWdlIiA6ICJtb2RlcmF0b3IiLAogICAgImdyYW50ZWUiIDogImFjY3Q6ZGlhbmVAZXhhbXBsZS5jb20iCiAgfSBdCn0.56wwxFWrkNrvls_p1fR8KaMoDBJQmKgRX1IpE66_5EnqbjJR1fLHoPMcy-jMyV8RAbnGX5ZYwXThYyTuj34L9g
```

Currently the only supported signature algorithm is ECDSA using the P-256 curve and SHA-256 hashing algorithm (i.e. the ES256 algorithm as defined in RFC7518).  The only supported serialization is the JWS compact serialization, as defined in RFC7515.

## Clique Serialization

A complete authorization blockchain is represented as a JSON array, where the first element is signed and serialized genesis block, and all subsequent blocks (if any) are signed and serialized authorization blocks.

```
authchain : [ genesisblock_serialized, *: authblock_serialized ]
```

*Example*

```
[
    "eyJhbGciOiJFUzI1NiJ9.ewogICJjcmVhdG9yIiA6ICJhY2N0OmFsaWNlQGV4YW1wbGUuY29tIiwKICAiaWRlbnRpdGllcyIgOiBbIHsKICAgICJhY2N0IiA6ICJhY2N0OmFsaWNlQGV4YW1wbGUuY29tIiwKICAgICJrZXkiIDogewogICAgICAia3R5IiA6ICJFQyIsCiAgICAgICJjcnYiIDogIlAtMjU2IiwKICAgICAgIngiIDogIjZrRnNsalk1dzJOdXFiZ1VMLVVuY20tcnR3VEhOWHJrU2g4bXFYRUFmNnciLAogICAgICAieSIgOiAiVW1NQ2pob3p2NHdRNTZPVTFiQnFyZmNROHlVenZYSUtzQXRXV1A4SEpHZyIKICAgIH0KICB9LCB7CiAgICAiYWNjdCIgOiAiYWNjdDpib2JAZXhhbXBsZS5jb20iLAogICAgImtleSIgOiB7CiAgICAgICJrdHkiIDogIkVDIiwKICAgICAgImNydiIgOiAiUC0yNTYiLAogICAgICAieCIgOiAiYUx5U0l1MTBKMzZJZlhGY3lCZTh2emVPWUxPbm9WSElES01XNWhaQzZacyIsCiAgICAgICJ5IiA6ICJhNnFZbEw4UVROVzh4SFhQbXFtV0tWN3hfNnAxX3djMUQ3S2k1SGdQQUhJIgogICAgfQogIH0gXSwKICAiZ3JhbnRzIiA6IFsgewogICAgInR5cGUiIDogIlZJUkFMX0dSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OmFsaWNlQGV4YW1wbGUuY29tIgogIH0sIHsKICAgICJ0eXBlIiA6ICJWSVJBTF9HUkFOVCIsCiAgICAicHJpdmlsZWdlIiA6ICJwYXJ0aWNpcGFudCIsCiAgICAiZ3JhbnRlZSIgOiAiYWNjdDpib2JAZXhhbXBsZS5jb20iCiAgfSwgewogICAgInR5cGUiIDogIlZJUkFMX0dSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogIm1vZGVyYXRvciIsCiAgICAiZ3JhbnRlZSIgOiAiYWNjdDpib2JAZXhhbXBsZS5jb20iCiAgfSBdLAogICJyZXNvdXJjZSIgOiAieG1wcDp0ZWFtcm9vbUBjb25mZXJlbmNlLmV4YW1wbGUuY29tIgp9.bdk8jsdC0OZcjDMsMoz6lzb7sxbW8kG1scCsihNLokdDJJAmEnjYRa8ek5w2DiTxu58FNpbEdO76ud2pkD3c0w",
    "eyJhbGciOiJFUzI1NiJ9.ewogICJhbnRlY2VkZW50IiA6ICI5ZWYxZjZlNzU5YzY2MjdkODYzMjVlNDJiNTcwNTlmYzU2OGUzZDRlMzQ2NzlmOTM0Mjk3MTg4NTI4NTg5OWUxIiwKICAiY3JlYXRvciIgOiAiYWNjdDpib2JAZXhhbXBsZS5jb20iLAogICJpZGVudGl0aWVzIiA6IFsgewogICAgImFjY3QiIDogImFjY3Q6amFja0BleGFtcGxlLmNvbSIsCiAgICAia2V5IiA6IHsKICAgICAgImt0eSIgOiAiRUMiLAogICAgICAiY3J2IiA6ICJQLTI1NiIsCiAgICAgICJ4IiA6ICJXQnRWR1lJOXNQdXdrcjlzUkFPWWJFX3JYNzBCeVlPQ2x2VEQtTHZZSEl3IiwKICAgICAgInkiIDogIjhDemZ2Yy1NZlIwMXROcngxUWYtNHdUYXAtU2UxQVZoQ2hUZTNoWEtFa1kiCiAgICB9CiAgfSwgewogICAgImFjY3QiIDogImFjY3Q6ZGlhbmVAZXhhbXBsZS5jb20iLAogICAgImtleSIgOiB7CiAgICAgICJrdHkiIDogIkVDIiwKICAgICAgImNydiIgOiAiUC0yNTYiLAogICAgICAieCIgOiAiLVk0NmUyLTJ4dnRfaTVlZV9TQUQ3Y3JXMmRJekp3STA4Vk1vNEEtSzVlayIsCiAgICAgICJ5IiA6ICJyZmZPQWlPNFhDTlJOUnB2S1k2REtvaEtRYW9acHVubEFOa2VmQlRqSEFvIgogICAgfQogIH0gXSwKICAiZ3JhbnRzIiA6IFsgewogICAgInR5cGUiIDogIkdSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OmphY2tAZXhhbXBsZS5jb20iCiAgfSwgewogICAgInR5cGUiIDogIlZJUkFMX0dSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OmRpYW5lQGV4YW1wbGUuY29tIgogIH0sIHsKICAgICJ0eXBlIiA6ICJHUkFOVCIsCiAgICAicHJpdmlsZWdlIiA6ICJtb2RlcmF0b3IiLAogICAgImdyYW50ZWUiIDogImFjY3Q6ZGlhbmVAZXhhbXBsZS5jb20iCiAgfSBdCn0.56wwxFWrkNrvls_p1fR8KaMoDBJQmKgRX1IpE66_5EnqbjJR1fLHoPMcy-jMyV8RAbnGX5ZYwXThYyTuj34L9g",
    "eyJhbGciOiJFUzI1NiJ9.ewogICJhbnRlY2VkZW50IiA6ICJmYTc1NGY0NjIzMzNlNzNhMmRmZThlM2E2YzMwNTRkYjBmNDk5YTQ3NTNiNGM2Mjc3YzM5Y2FmNmUyNGRhOGY5IiwKICAiY3JlYXRvciIgOiAiYWNjdDpkaWFuZUBleGFtcGxlLmNvbSIsCiAgImlkZW50aXRpZXMiIDogWyB7CiAgICAiYWNjdCIgOiAiYWNjdDpzdGV2ZUBleGFtcGxlLmNvbSIsCiAgICAia2V5IiA6IHsKICAgICAgImt0eSIgOiAiRUMiLAogICAgICAiY3J2IiA6ICJQLTI1NiIsCiAgICAgICJ4IiA6ICI1am0zWF80ZlQ3UE5SWk5Jb0hCUTlZakxwVXYySFJJSldfTHZFT21fRzBrIiwKICAgICAgInkiIDogIlZSdUJ4T2EtUWpZNHZtREZtNGxkc0FaTXNBYWV5V0JnTVdzMWRnaXlQNlkiCiAgICB9CiAgfSBdLAogICJncmFudHMiIDogWyB7CiAgICAidHlwZSIgOiAiUkVWT0tFIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OmphY2tAZXhhbXBsZS5jb20iCiAgfSwgewogICAgInR5cGUiIDogIkdSQU5UIiwKICAgICJwcml2aWxlZ2UiIDogInBhcnRpY2lwYW50IiwKICAgICJncmFudGVlIiA6ICJhY2N0OnN0ZXZlQGV4YW1wbGUuY29tIgogIH0gXQp9.upL_Ko-FldwINWGCUNeCeSYPAS8FTR1RE03qKeVZdsKijveqKVs0HcO4VBsYwJjWWhbG_TuaDcYx8ieGBETM5g"
]
```

## Clique Validation Rules

An important property of the authorization blockchain is that it can be readily validated.  Tamper-resistence and detection are critical because Cliques may be passed among cooperating nodes of a distributed application over untrusted networks or via untrusted intermediaries.  The following validation operations must be performed before any relying party makes authorization policy decisions based on the contents of an Clique.

*Genesis Block Validation*

1. The SHA-256 hash of the first block in the chain (the genesis block) must match a known value.

2. The creator of the genesis block must match an identity declared within the genesis block.

3. The signature on the genesis block must be verifiable using the public key corresponding to the creator's identity.

4. Every grant declared in the genesis block must have a grantee that corresponds to an identity declared in the genesis block.

5. The genesis block must not contain an antecedent attribute.

*Authorization Block Validation*

1. The antecedent attribute of a block must match the SHA-256 hash of the block's immediate predecessor in the chain.

2. The creator of the block must match an identity declared in a block that occurs previously within the chain.

3. The signature on the block must be verifiable using the public key corresponding to the creator's identity.  If there exists more than one identity declaration in the preceding chain that matches the block's creator, the public key from the most recent declaration must be used for signature verification.

4. If an identity is declared within the block for which an identity declaration with the same acct attribute is found in a prior block, then that acct attribute must match the block's creator (identities may redeclare themselves within the chain as a means of rotating their key).

5. For each grant within the block, if the privilege attribute matches that of any grant declaration found earlier in the chain, then the block creator must have been previously granted that same privilege by virtue of a grant declaration of type VIRAL_GRANT.  This condition is negated if there exists an intervening grant declaration to the creator of type REVOKE.

6. For each grant within the block, if the privilege attribute does not match that of any grant declaration found earlier in the chain, then the type of the grant must be VIRAL_GRANT and the grantee must be the block creator.
