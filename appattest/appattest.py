#
# AppAttest AttestationStatement class and helper functions
#
# Extrapolated from the steps in:
#	https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
#
# and the description of Authenticator Data:
#	https://www.w3.org/TR/webauthn/#sctn-authenticator-data
#

import base64
import cbor2
import json
import codecs

from pyasn1.codec.ber import decoder
from pyasn1.type import univ, namedtype, tag

import datetime
import time

import struct

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat._oid import ObjectIdentifier

from typing import List, Tuple

appId = None
teamId = None

nonceOID = ObjectIdentifier('1.2.840.113635.100.8.2')
nonceTag = 1

# taken from https://www.apple.com/certificateauthority/private/
aaa = b'MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD'

def _hexbytes(val: bytes) -> str:
    return codecs.encode(val, 'hex').decode()

class noncePayload(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('nonce', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, nonceTag))),
    )

class AuthenticatorData:
    __slots__ = [ '_rpid', '_flags', '_counter', '_aaguid', '_credentialId', '_credentialPublicKey' ]

    FLAG_UP = 0x01
    FLAG_RFU1 = 0x02
    FLAG_UV = 0x04
    FLAG_RFU2 = 0x38
    FLAG_AT = 0x40
    FLAG_ED = 0x80

    _authData_format = '> 32s B I'
    _authData_format1 = '> 16s H'
    _authData_format2 = '%ds'

    def __init__(self, data: bytes):
        _offset = 0
        _size = struct.calcsize(AuthenticatorData._authData_format)
        self._rpid, self._flags, self._counter = struct.unpack(AuthenticatorData._authData_format, data[_offset : _offset + _size])
        _offset += _size

        if self._flags & AuthenticatorData.FLAG_AT:
            _size = struct.calcsize(AuthenticatorData._authData_format1)
            self._aaguid, _credentialIdLength = struct.unpack(AuthenticatorData._authData_format1, data[_offset : _offset + _size])
            _offset += _size

            __authData_format = AuthenticatorData._authData_format2 % _credentialIdLength
            _size = struct.calcsize(__authData_format)
            self._credentialId = struct.unpack(__authData_format, data[_offset : _offset + _size])[0]
            _offset += _size

            self._credentialPublicKey = cbor2.loads(data[_offset :])
        else:
            self._aaguid = self._credentialId = self._credentialPublicKey = None

    def __repr__(self) -> str:
        _s = 'AuthenticatorData(%r, %#x, %d' % (self._rpid, self._flags, self._counter)
        if self._credentialId != None:
            _s += ', %r' % self._credentialId
        if self._credentialPublicKey != None:
            _s += ', %r' % self._credentialPublicKey
        _s += ')'
        return _s

    @property
    def rpid(self) -> bytes:
        return self._rpid

    @property
    def flags(self) -> bytes:
        return self._flags

    @property
    def counter(self) -> int:
        return self._counter

    @property
    def aaguid(self) -> bytes:
        return self._aaguid

    @property
    def credentialId(self) -> bytes:
        return self._credentialId

    @property
    def credentialPublicKey(self) -> bytes:
        return self._credentialPublicKey

##
## Simple-minded certificate chain validation
##
## We need a better version to be bundled in x509 but alas, it's mired
## in handwringing and bikeshedding.
##
## We need CRL and/or OCSP verification that intermediate certs haven't
## been revoked.
##
def validateCertificatePath(certificates: List[x509.Certificate]) -> bool:
    if len(certificates) != len(set(certificates)):
        return False

    now = datetime.datetime.now()

    for i in range(len(certificates)):
        subjectCert = certificates[i]

        # certificate validity window outside of current time
        if subjectCert.not_valid_before > now or \
           subjectCert.not_valid_after < now:
            return False

        if i == len(certificates) - 1:
            ## root CA's are self-signed, so compare to itself
            issuerCert = certificates[i]
        else:
            issuerCert = certificates[i + 1]

        # check for subject/issuer DN equality
        if subjectCert.issuer != issuerCert.subject:
            return False

        # Verify signature using issuer's public key
        try:
            issuerCert.public_key().verify(
                subjectCert.signature,
                subjectCert.tbs_certificate_bytes,
                ec.ECDSA(subjectCert.signature_hash_algorithm),
            )
        except InvalidSignature:
            return False

    return True

def sha256(s: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(s)
    return digest.finalize()

def verifyAppAttestAttestation(attestation: bytes, clientDataHash: bytes, keyId: bytes) -> Tuple[ec.EllipticCurvePublicKey, bytes]:
    attestationStruct = cbor2.loads(attestation)

    ## Verify format

    if attestationStruct['fmt'] != 'apple-appattest':
        raise ValueError('Attestion using wrong format')

    attStmt = attestationStruct['attStmt']

    receipt = attStmt['receipt']

    ## step 1.

    _aaa = base64.b64decode(aaa)

    certs = attStmt['x5c']
    certs.append(_aaa)

    certPath = [ x509.load_der_x509_certificate(c) for c in certs ]

    if not validateCertificatePath(certPath):
        raise RuntimeError('Invalid certificate path')

    credCert = certPath[0]

    authData = attestationStruct['authData']

    authenticatorData = AuthenticatorData(authData)

    ## step 2.

    totalData = authData + clientDataHash

    ## step 3.

    recomputedNonce = sha256(totalData)

    ## step 4.

    # don't ask... I can't explain it.
    extensionValue = credCert.extensions.get_extension_for_oid(nonceOID).value.value

    payload, rest = decoder.decode(extensionValue, asn1Spec = noncePayload())

    nonce = payload['nonce'].asOctets()

    if nonce != recomputedNonce:
        raise RuntimeError('Nonce mismatch in payload')

    ## step 5.

    pk = credCert.public_key()

    # don't get the DER of the key in its current Subject Public Key Info
    # format; it must be re-encoded into EC Uncompressed Point format...
    point = pk.public_bytes(
         serialization.Encoding.X962,
         serialization.PublicFormat.UncompressedPoint)

    pk_sha = sha256(point)

    if keyId != pk_sha:
        raise ValueError('Key identifier doesn\'t match public key SHA')

    ## step 6.

    # check AppID hash against RPID
    hash = sha256(teamId + b'.' + appId)

    if hash != authenticatorData.rpid:
        raise RuntimeError('Authenticator data contains wrong RPID')

    ## step 7.

    if authenticatorData.counter != 0:
        raise ValueError('Authenticator data sign counter non-zero')

    ## step 8.

    if authenticatorData.aaguid == 'appattestdevelop':
        pass
    elif authenticatorData.aaguid != 'appattest\0\0\0\0\0\0\0':
        pass
    else:
        raise ValueError('Authenticator data contains unexpected aaguid')

    ## step 9.

    if authenticatorData.credentialId != keyId:
        raise ValueError('Authenticator data doesn\'t match key identifier')

    return pk, receipt

