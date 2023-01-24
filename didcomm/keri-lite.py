from keri.core import eventing, coring

from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.message import Message
from didcomm.secrets.secrets_resolver_demo import  Secret
from didcomm.unpack import unpack
from didcomm.common.resolvers import ResolversConfig, SecretsResolver
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig

from typing import Optional, List
from pprint import pp
import pysodium
import base64
import json
import asyncio


'''
Proof of concept of DIDComm packing and unpacking with did:keri
- Use SICPA didcomm-python library
- Authcryypt message
- AID is Ed25519 and derive X25519 keys from same private
- Non transferable AID (no key rotations)
- TO DEFINE: how to pass the serviceEndpoint and public encryption key (DID Doc resolution) --> OOBI?
'''


def createKeriDid():
    salt = coring.Salter()
    signerEd25519 = salt.signer(transferable=False, temp=True)

    X25519_pubkey = pysodium.crypto_sign_pk_to_box_pk(signerEd25519.verfer.raw)
    X25519_pubkey_qb64 = ('C'+base64.b64encode(X25519_pubkey).decode('utf-8'))[:-1]

    serder = eventing.incept(
        keys=[signerEd25519.verfer.qb64], 
        data=[
                {"e":X25519_pubkey_qb64},
                {"se": "https://example.coom/"}
            ], 
        code=coring.MtrDex.Blake3_256 # code is for self-addressing
    )

    return {
        'did': 'did:keri:'+serder.ked['i'],
        'serder': serder,
        'signer': signerEd25519
    }


class SecretsResolverInMemory(SecretsResolver):
    def __init__(self, store: dict):
        self._store = store

    async def get_key(self, kid: str) -> Optional[Secret]:
        did = kid.split('#')[0]
        signer = self._store[did]['signer']
        X25519_pubkey = pysodium.crypto_sign_pk_to_box_pk(signer.verfer.raw)
        X25519_pubkey_b64 = base64.b64encode(X25519_pubkey).decode('utf-8')
        X25519_prikey = pysodium.crypto_sign_sk_to_box_sk(signer.raw + signer.verfer.raw)
        X25519_prikey_b64 = base64.b64encode(X25519_prikey).decode('utf-8')

        secret = Secret(
                kid= kid,
                type= VerificationMethodType.JSON_WEB_KEY_2020,
                verification_material= VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value= json.dumps(
                        {
                            'kty': 'OKP',
                            'crv': 'X25519',
                            'd': X25519_prikey_b64,
                            'x': X25519_pubkey_b64,
                            'kid': kid
                        }
                    )
                )
        )        
        return secret

    async def get_keys(self, kids: List[str]) -> List[str]:
        return kids


class DidKeriResolver(DIDResolver):
    def __init__(self, store: dict):
        self._store = store
    async def resolve(self, did: DID) -> DIDDoc:

        # This is a hack. Alice needs a way to get the KED (or DID Doc) from Bob's DID, and also the serviceEndpoint
        # OOBI? URL query parameter? DIDComm message?
        ked = self._store[did]['serder'].ked

        return DIDDoc(
            did=did,
            key_agreement_kids = [did+'#key-1'],
            authentication_kids = [],
            verification_methods = [
                VerificationMethod(
                    id = did+'#key-1',
                    type = VerificationMethodType.JSON_WEB_KEY_2020,
                    controller = did,
                    verification_material = VerificationMaterial(
                        format = VerificationMaterialFormat.JWK,
                        value = json.dumps({
                                    'kty': 'OKP',
                                    'crv': 'X25519',
                                    'x': ked['a'][0]['e'][1:]
                                })
                    )
                )
            ],
             didcomm_services = []
        )


if __name__ == "__main__":

    alice = createKeriDid()
    print("Alice's DID:", alice['did'],"\n")
    bob = createKeriDid()
    print("Bob's DID:", bob['did'],"\n")

    store = {
        alice['did']: alice,
        bob['did']: bob
    }

    secrets_resolver = SecretsResolverInMemory(store)
    did_resolver = DidKeriResolver(store)

    # Alice creates a basic message
    alice_message =  Message(
        id = "123",
        type = "https://didcomm.org/basicmessage/2.0/message",
        body = {'content': 'Hello Bob!'},
    )
    print('1-Alice creates a basic message:',alice_message.body,"\n")

    # Alice encrypts the message for Bob
    alice_message_packed = asyncio.run( pack_encrypted(
        resolvers_config = ResolversConfig(
            secrets_resolver = secrets_resolver,
            did_resolver = did_resolver
        ),
        message = alice_message,
        frm = alice['did'],
        to = bob['did'],
        sign_frm = None,
        pack_config = PackEncryptedConfig(protect_sender_id=False)
    ))
    print('2-Alice encrypts the message for Bob:')
    print(alice_message_packed.packed_msg,"\n")

    # Bob decrypts the message
    bob_message_unpacked = asyncio.run( unpack(
        resolvers_config=ResolversConfig(
            secrets_resolver=secrets_resolver,
            did_resolver=did_resolver
        ),
        packed_msg= alice_message_packed.packed_msg
    ))
    print('3-Bob decrypts the message:', bob_message_unpacked.message.body,"\n")

    # print("##########################################################","\n")
    # pp(alice['serder'].ked)
    # print("\n")
    # print(alice['did'],"\n")
    # print(alice['did']+'?kel='+base64.urlsafe_b64encode(bytes(json.dumps(alice['serder'].ked), 'utf-8')).decode('utf-8'))