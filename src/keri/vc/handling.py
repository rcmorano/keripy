# -*- encoding: utf-8 -*-
"""
keri.vc.handling module

"""

from .. import help
from keri.core.coring import dumps, Deversify
from keri.core.scheming import JSONSchema
from keri.kering import ShortageError
from keri.peer import exchanging
from keri.vc.proving import Credentialer
from keri.vc.walleting import parseCredential, buildProof

logger = help.ogler.getLogger()


class BaseHandler:
    """
    Base class for handling `exn` messages for a given resource

    Properties:
        resource is str resource
        behavior is a Behavior for this handler
    """

    def __init__(self, resource, func):
        self._resource = resource
        self._behavior = exchanging.Behavior(func=func)

    @property
    def resource(self):
        return self._resource

    @property
    def behavior(self):
        return self._behavior


class IssueHandler(BaseHandler):
    """

    """

    def __init__(self, wallet, typ=JSONSchema()):
        self.wallet = wallet
        self.typ = typ

        super(IssueHandler, self).__init__(resource="/credential/issue", func=self.handleMessage)

    def handleMessage(self, payload, pre, sigers, verfers):
        """
         {
           "vc" [
             {
               "vc": {
                  "v": "KERI10JSON00011c_", //KERI Version String
                  "x": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the Schema
                  "d": {
                       "type": [
                           "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI"
                       ],
                       "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                       "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",
                       "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                       "credentialSubject": {
                           "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                           "lei": "254900OPPU84GM83MG36"
                       },
                       "credentialSchema": {
                           "id": ""
                           "type": ""
                       },
                       "credentialStatus": {
                          "id": "",
                          "type": ""
                       }
                  }
               }, // embedded verifiable credential
               "proof": "-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE
                     -d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA"
               }
           ]   //list of verifiable credentials
        }
        Parameters:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """

        envelopes = payload["verifiableCredential"]

        for envlop in envelopes:
            crd = envlop["vc"]
            proof = envlop["proof"]

            vs = crd["v"]

            kind, version, size = Deversify(vs)
            raw = dumps(ked=crd, kind=kind)
            if len(raw) != size:
                raise ValueError("invalid length {} for credential = {}".format(size, crd))

            msg = bytearray(raw)
            msg.extend(proof.encode("utf-8"))

            parseCredential(ims=msg, wallet=self.wallet, typ=self.typ)


        return None, None


class RequestHandler(BaseHandler):
    """
        Processor for a credential request with input descriptors in the payload used to
        match saved credentials based on a schema.  The payload of the request is expected to
        have the following format:

             {
                "submission_requirements": [{
                   "name": "Proof of LEI",
                   "rule": "pick",
                   "count": 1,
                   "from": "A"
                 }]
                "input_descriptors": [
                   {
                      "x":"EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA",
                      "group": ["A"],
                   }
                ],
                "format": {
                   "cesr": {
                     "proof_type": ["Ed25519Signature2018"]
                   }
                }
             }

    """

    def __init__(self, wallet, typ=JSONSchema()):
        self.wallet = wallet
        self.typ = typ

        super(RequestHandler, self).__init__(resource="/presentation/request", func=self.handleMessage)


    def handleMessage(self, payload, pre, sigers, verfers):
        """
        Process presentation request message with sender identifier, sigs and verfers

        Parameters:
            payload is dict representing the body of a /presentation/request message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/request message
            verfers is list of Verfers of the keys used to sign the message

        """

        descriptors = payload["input_descriptors"]

        matches = []
        for descriptor in descriptors:
            said = descriptor["x"]
            credentials = self.wallet.getCredentials(said)
            if len(credentials) > 0:
                vc = credentials[0][0].pretty()
                logger.info("Presenting Credential for schema %s:\n VC=%s", said, vc)
                matches.append(credentials[0])

        if len(matches) > 0:
            pe = presentation_exchange(matches)
            return "/presentation/proof", pe

        else:
            return None, None


class ProofHandler(BaseHandler):
    """
    Processor for responding to presentation proof peer to peer message.  The payload of the message
    is expected to have the following format:

        {
          "presentation_submission": {
              "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
              "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
              "descriptor_map": [
                   {
                     "id": "gleif_vlei",
                     "format": "cesr",
                     "path": "$.verifiableCredential[0]"
                   }
              ]
          },
          "verifiableCredential": [
              {
                "vc": {
                   "v": "KERI10JSON00011c_", //KERI Version String
                   "x": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the Schema
                   "q": {
                        "type": [
                            "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI"
                        ],
                        "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                        "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of
                        the issuer
                        "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                        "credentialSubject": {
                            "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                            "lei": "254900OPPU84GM83MG36"
                        }
                    } // embedded verifiable credential
                }
                "proof": "-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE
                -YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI
                -AABAALK_6pkUjCx76CTE7pNrKlhC84ewgZbs-4ciTvLcxkwUaWX7ukpr55P9RtJhlHxdtz3kN0zfM0HrtFitKuPy3BA"
              }
           ]
        }
    """

    def __init__(self, callback, typ=JSONSchema()):
        self.typ = typ
        self.callback = callback

        super(ProofHandler, self).__init__(resource="/presentation/proof", func=self.handleMessage)


    def handleMessage(self, payload, pre, sigers, verfers):
        """

        Parameters:
            payload is dict representing the body of a /presentation/proof message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/proof message
            verfers is list of Verfers of the keys used to sign the message
        """

        if "presentation_submission" not in payload:
            raise ValueError("invalid presentation proof payload")

        if "verifiableCredential" not in payload:
            raise ValueError("invalid presentation proof payload")


        pe = payload["presentation_submission"]
        vcs = payload["verifiableCredential"]

        if "descriptor_map" not in pe:
            raise ValueError("invalud presentation submission in proof payload")

        dm = pe["descriptor_map"]

        for idx, descriptor in enumerate(dm):
            # TODO:  Find verifiable credential in vcs based on `path`
            vc = vcs[idx]
            self.callback(pre, vc)


        return None, None




def envelope(msg, typ=JSONSchema()):
    """
    Returns a dict of a VC split into the "vc" and "proof"

    Parameters:
        msg: bytes of verifiable credential to split
        typ: schema type of the VC
    """

    ims = bytearray(msg)
    try:
        creder = Credentialer(raw=ims, typ=typ)
    except ShortageError as e:
        raise e
    else:
        del ims[:creder.size]

    return dict(
        vc=creder.crd,
        proof=ims.decode("utf-8")
    )


def presentation_exchange(credentials):
    dm = []
    vcs = []

    for idx, (creder, prefixer, seqner, diger, sigers) in enumerate(credentials):
        proof = buildProof(prefixer, seqner, diger, sigers)
        dm.append(dict(
            id=creder.schema,
            format="cesr",
            path="$.verifiableCredential[{}]".format(idx)
        ))

        vcs.append(dict(
            vc=creder.crd,
            proof=proof.decode("utf-8")
        ))

    d = dict(
        presentation_submission=dict(
            descriptor_map=dm
        ),
        verifiableCredential=vcs
    )

    return d
