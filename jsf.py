"""
The jsf module attempts to implement
the [JSON Signature Format draft 0.81][1].

[1]: https://cyberphone.github.io/doc/security/jsf.html
"""

from base64 import urlsafe_b64encode, urlsafe_b64decode
from copy import copy
from typing import Any, Callable, Dict, List, Optional, Type, Union

from jwcrypto.common import (
    base64url_decode, base64url_encode, json_decode, json_encode)
from jwcrypto.jwk import JWK
from jwcrypto.jws import (
    InvalidJWSObject, InvalidJWSOperation, InvalidJWSSignature,
    JWSCore, JWSHeaderRegistry, default_allowed_algs)
from org.webpki.json.Canonicalize import canonicalize as _dumpb


JsonObject = Dict[str, Any]
"""
A Python dictionary representing a JSON object.

This type alias is more for documentation than type checking,
as mypy currently does not support recursive data types:
https://github.com/python/mypy/issues/731
"""


AlgorithmName = str
"""
An algorithm name, as understood by the JWCrypto library.
"""


_ALGORITHM = 'algorithm'
_PUBLICKEY = 'publicKey'
_VALUE = 'value'
_EXTENSIONS = 'extensions'
_EXCLUDES = 'excludes'
_SIGNERS = 'signers'
_CHAIN = 'chain'


_PreparePayloadHeader = Callable[[JsonObject], JsonObject]
_InstallPayloadHeader = Callable[[JsonObject], None]
_PatchHeader = Callable[[JsonObject], JsonObject]


class JSF:
    def __init__(self, payload: Optional[JsonObject] = None) -> None:
        """
        Create a JSF object.

        :param payload: The payload object.
        """
        self._payload = payload
        self.verifylog: List[str] = []
        self._allowed_algs: Optional[List[AlgorithmName]] = None

    def _check_extensions(self, extensions):
        for k in extensions:
            if k not in JWSHeaderRegistry:
                raise InvalidJWSSignature(
                    'Unknown extension: "{}"'.format(k))
            elif not JWSHeaderRegistry[k][1]:
                raise InvalidJWSSignature(
                    'Unsupported extension: "{}"'.format(k))

    @property
    def allowed_algs(self) -> List[AlgorithmName]:
        return (self._allowed_algs if self._allowed_algs is not None
                else default_allowed_algs)

    @allowed_algs.setter
    def allowed_algs(self, algs: List[AlgorithmName]) -> None:
        if (not isinstance(algs, list) or
                not all(isinstance(alg, AlgorithmName)
                        for alg in algs)):
            raise TypeError('Allowed Algs must be a list of strings')
        self._allowed_algs = algs

    @property
    def is_valid(self) -> bool:
        return self._valid

    @property
    def payload(self) -> JsonObject:
        if self._payload is None:
            raise InvalidJWSOperation("Payload not available")
        if not self.is_valid:
            raise InvalidJWSOperation("Payload not verified")
        return self._payload


    def _get_alg(self, alg: Optional[AlgorithmName],
                 header: JsonObject, error: Type[Exception]) -> AlgorithmName:
        h_alg = header.get(_ALGORITHM)
        if alg is None:
            if h_alg is None:
                raise error('No "{}" in headers'.format(_ALGORITHM))
            return h_alg
        if h_alg is not None and alg != h_alg:
            raise error(
                '"{}" mismatch, requested "{}", found "{}"'
                .format(_ALGORITHM, alg, h_alg))
        return alg

    def _add_signature(
            self, prop: str, key: JWK, alg: Optional[AlgorithmName],
            header: Optional[JsonObject],
            prepare_payload_header: _PreparePayloadHeader,
            install_payload_header: _InstallPayloadHeader) -> None:
        if self._payload is None:
            raise InvalidJWSObject('Missing Payload')

        # Check the header round-trips through JSON
        h = json_decode(json_encode(header or {}))

        self._check_extensions(h.get(_EXTENSIONS, []))

        a = self._get_alg(alg, header, ValueError)

        # Prepare payload for signature algorithm
        h.pop(_VALUE, None)
        payload = copy(self._payload)
        payload[prop] = prepare_payload_header(h)
        canonical = _dumpb(payload)

        # Calculate signature
        #
        # JWSCore would encode payload as base64 and prepend a dot,
        # but Cleartext JWS uses canonicalized JSON as Signing Input,
        # so we just use Core for its algorithm engine selection logic.
        c = JWSCore(a, key, header=None, payload='',
                    algs=self.allowed_algs)
        sig = c.engine.sign(key, canonical)

        # Put signature in place
        h[_VALUE] = base64url_encode(sig)
        install_payload_header(h)
        self._valid = True

    def add_single_signature(
            self, prop: str, key: JWK, alg: Optional[AlgorithmName] = None,
            header: Optional[JsonObject] = None) -> None:
        """
        Sign the payload with a single `key`.
        Remove any previously added signatures.

        :param prop: Place the signature object into this top-level property.

        :param alg: The signing algorithm.
        Can be omitted if provided in the `header`.

        :param header: The header providing the algorithm parameters.
        """
        self._add_signature(prop, key, alg, header,
                            lambda h: h,
                            lambda h: self._payload.update({prop: h}))

    def add_signature(
            self, prop: str, key: JWK, alg: Optional[AlgorithmName] = None,
            header: Optional[JsonObject] = None) -> None:
        """
        Add a signature using the specified key and algorithm.
        Remove the signatures added by `add_single_signature`
        or `add_chain_signature`, if any.
        This method can be used multiple times.

        :param alg: The signing algorithm.
        Can be omitted if provided in the `header`.

        :param header: The header providing the algorithm parameters.
        """
        top_level_signature = self._payload.get(prop)
        for k in top_level_signature.keys():
            if k != _SIGNERS:
                del top_level_signature[k]
        self._add_signature(prop, key, alg, header,
                            lambda h: {_SIGNERS: [h]},
                            lambda h: (self._payload
                                           .setdefault(prop, {})
                                           .setdefault(_SIGNERS, [])
                                           .append(h)))

    def add_chain_signature(
            self, prop: str, key: JWK, alg: Optional[AlgorithmName] = None,
            header: Optional[JsonObject] = None) -> None:
        """
        Add a signature to the chain using the specified key and algorithm.
        Remove the signatures added by `add_single_signature`
        or `add_signature`, if any.
        This method can be used multiple times.

        :param alg: The signing algorithm.
        Can be omitted if provided in the `header`.

        :param header: The header providing the algorithm parameters.
        """
        top_level_signature = self._payload.get(prop)
        for k in top_level_signature.keys():
            if k != _CHAIN:
                del top_level_signature[k]
        chain = top_level_signature.get(_CHAIN, [])
        self._add_signature(prop, key, alg, header,
                            lambda h: {_CHAIN: chain + [h]},
                            lambda h: (self._payload
                                           .setdefault(prop, {})
                                           .setdefault(_CHAIN, [])
                                           .append(h)))

    def _verify(self, prop: str, key: JWK, alg: Optional[AlgorithmName],
                header: JsonObject, signer: Optional[JsonObject],
                patch_header: _PatchHeader) -> None:
        a = self._get_alg(alg, signer or header, InvalidJWSSignature)

        # Prepare payload for verification algorithm
        payload = copy(self._payload)
        h = copy(header)
        s = copy(signer)
        signature = base64url_decode((s or h).pop(_VALUE))
        exclude = h.pop(_EXCLUDES, [])
        for x in exclude:
            payload.pop(x, None)

        h.update(patch_header(s))

        payload[prop] = h
        canonical = _dumpb(payload)

        # Verify signature
        if key is None:
            key = JWK(**((s or h).get(_PUBLICKEY, None)))
        c = JWSCore(a, key, header=None, payload='',
                    algs=self._allowed_algs)
        c.engine.verify(key, canonical, signature)

    def _try_verify(self, prop: str, key: Optional[JWK],
                    alg: Optional[AlgorithmName],
                    h: JsonObject, signer: Optional[JsonObject],
                    patch_header: _PatchHeader) -> None:
        try:
            self._verify(prop, key, alg, h, signer, patch_header)
            self._valid = True
        except Exception as e:
            self.verifylog.append('Failed: [{!r}]'.format(e))

    def verify(self, prop: str, key: Optional[JWK] = None,
               alg: Optional[AlgorithmName] = None) -> None:
        """
        Verify signatures on the payload using `key`.

        :param prop: The name of the top-level property in payload
        that contains the signatures.
        The JSF specification does not specify this property,
        saying it is arbitrary but unique.
        This library assumes each application will pick a sensible name.

        :param key: The verification key. If not specified, the key
        from the payload’s signature object will be used (if any).

        :param alg: The signing algorithm. Usually it is known
        from the payload’s header.

        :raises InvalidJWSSignature: if the verification fails.
        """
        self.verifylog = []
        self._valid = False
        h = self._payload.get(prop)
        if h is None:
            raise InvalidJWSSignature('No signatures available')

        self._check_extensions(h.get(_EXTENSIONS, []))

        if not _CHAIN in h and not _SIGNERS in h:
            self._try_verify(prop, key, alg, h, None, lambda _s: {})
        elif _SIGNERS in h:
            # A multiple signature is valid if any signature is valid
            for signer in h[_SIGNERS]:
                self._try_verify(prop, key, alg, h, signer,
                                 lambda s: {_SIGNERS: [s]})
        else:
            # A chain signature is valid if all signatures are valid
            # and there is at least one
            for i, signer in enumerate(h[_CHAIN]):
                try:
                    self._try_verify(prop, key, alg, h, signer,
                                     lambda s: {_CHAIN: h[_CHAIN][:i] + [s]})
                except Exception as e:
                    self.verifylog.append('Failed: [{!r}]'.format(e))
            self._valid = not self.verifylog and h[_CHAIN]

        if not self.is_valid:
            raise InvalidJWSSignature('Verification failed for all '
                                      'signatures {!r}'.format(self.verifylog))
