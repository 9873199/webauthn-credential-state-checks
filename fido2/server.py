# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.primitives import constant_time

from .cose import CoseKey
from .rpid import verify_rp_id
from .utils import websafe_decode, websafe_encode
from .webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAttachment,
    AuthenticatorData,
    AuthenticatorSelectionCriteria,
    CollectedClientData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

logger = logging.getLogger(__name__)


VerifyAttestation = Callable[[AttestationObject, bytes], None]
VerifyOrigin = Callable[[str], bool]


def _verify_origin_for_rp(rp_id: str) -> VerifyOrigin:
    return lambda o: verify_rp_id(rp_id, o)


def _validata_challenge(challenge: bytes | None) -> bytes:
    if challenge is None:
        challenge = os.urandom(32)
    else:
        if not isinstance(challenge, bytes):
            raise TypeError("Custom challenge must be of type 'bytes'.")
        if len(challenge) < 16:
            raise ValueError("Custom challenge length must be >= 16.")
    return challenge


def to_descriptor(
    credential: AttestedCredentialData, transports=None
) -> PublicKeyCredentialDescriptor:
    """Converts an AttestedCredentialData to a PublicKeyCredentialDescriptor.

    :param credential: AttestedCredentialData containing the credential ID to use.
    :param transports: Optional list of AuthenticatorTransport strings to add to the
        descriptor.
    :return: A descriptor of the credential, for use with register_begin or
        authenticate_begin.
    :rtype: PublicKeyCredentialDescriptor
    """
    return PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY,
        id=credential.credential_id,
        transports=transports,
    )


def _wrap_credentials(
    creds: (
        Sequence[
            AttestedCredentialData
            | PublicKeyCredentialDescriptor
            | WebAuthnCredential
        ]
        | None
    ),
) -> Sequence[PublicKeyCredentialDescriptor] | None:
    if creds is None:
        return None
    return [
        (
            to_descriptor(c.credential_data)
            if isinstance(c, WebAuthnCredential)
            else (
                to_descriptor(c)
                if isinstance(c, AttestedCredentialData)
                else PublicKeyCredentialDescriptor.from_dict(c)
            )
        )
        for c in creds
    ]


def _ignore_attestation(
    attestation_object: AttestationObject, client_data_hash: bytes
) -> None:
    """Ignore attestation."""


@dataclass(frozen=True)
class WebAuthnCredential:
    """A server-side record of a registered credential.

    An application needs to persist one of these for every successful
    `register_complete`, keyed in such a way that it can be looked up both by
    credential ID and by the account (user handle) it belongs to. The data is
    all taken from the signed `AuthenticatorData` of the registration, so the
    record can later be used to verify that an assertion actually belongs to
    the account that initiated the request.

    :param credential_data: The attested credential data, holding the public key
        and credential ID, as returned in the registration `AuthenticatorData`.
    :param user_handle: The user handle (user ID) of the account the credential
        was registered for, taken from the registration options.
    :param sign_count: The signature counter (`counter`) from the registration
        `AuthenticatorData`.
    :param backup_eligible: The Backup Eligibility (BE) flag from the registration
        `AuthenticatorData`. This value can never change for a credential.
    :param backup_state: The Backup State (BS) flag from the registration
        `AuthenticatorData`. This value may change between assertions.
    """

    credential_data: AttestedCredentialData
    user_handle: bytes
    sign_count: int
    backup_eligible: bool
    backup_state: bool

    @property
    def credential_id(self) -> bytes:
        """The binary credential ID of the registered credential."""
        return self.credential_data.credential_id

    @classmethod
    def from_registration(
        cls,
        user_handle: bytes,
        auth_data: AuthenticatorData,
    ) -> WebAuthnCredential:
        """Build a credential record from a successful `register_complete`.

        All per-credential values are read from the signed `AuthenticatorData`,
        never from client-provided fields.

        :param user_handle: The user handle (user ID) of the account the
            credential is registered for.
        :param auth_data: The `AuthenticatorData` returned by
            `register_complete`.
        """
        assert auth_data.credential_data is not None  # noqa: S101
        return cls(
            credential_data=auth_data.credential_data,
            user_handle=user_handle,
            sign_count=auth_data.counter,
            backup_eligible=auth_data.is_backup_eligible(),
            backup_state=auth_data.is_backed_up(),
        )


class Fido2Server:
    """FIDO2 server.

    :param rp: Relying party data as `PublicKeyCredentialRpEntity` instance.
    :param attestation: (optional) Requirement on authenticator attestation.
    :param verify_origin: (optional) Alternative function to validate an origin.
    :param verify_attestation: (optional) function to validate attestation, which is
        invoked with attestation_object and client_data_hash. It should return nothing
        and raise an exception on failure. By default, attestation is ignored.
        Attestation is also ignored if `attestation` is set to `none`.
    """

    def __init__(
        self,
        rp: PublicKeyCredentialRpEntity,
        attestation: AttestationConveyancePreference | None = None,
        verify_origin: VerifyOrigin | None = None,
        verify_attestation: VerifyAttestation | None = None,
    ):
        self.rp = PublicKeyCredentialRpEntity.from_dict(rp)
        assert self.rp.id is not None  # noqa: S101
        self._verify = verify_origin or _verify_origin_for_rp(self.rp.id)
        self.timeout = None
        self.attestation = AttestationConveyancePreference(attestation)
        self.allowed_algorithms = [
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg
            )
            for alg in CoseKey.supported_algorithms()
        ]
        self._verify_attestation = verify_attestation or _ignore_attestation
        logger.debug(f"Fido2Server initialized for RP: {self.rp}")

    def register_begin(
        self,
        user: PublicKeyCredentialUserEntity,
        credentials: (
            Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None
        ) = None,
        resident_key_requirement: ResidentKeyRequirement | None = None,
        user_verification: UserVerificationRequirement | None = None,
        authenticator_attachment: AuthenticatorAttachment | None = None,
        challenge: bytes | None = None,
        extensions=None,
    ) -> tuple[CredentialCreationOptions, Any]:
        """Return a PublicKeyCredentialCreationOptions registration object and
        the internal state dictionary that needs to be passed as is to the
        corresponding `register_complete` call.

        :param user: The dict containing the user data.
        :param credentials: The list of previously registered credentials, these can be
            of type AttestedCredentialData, or PublicKeyCredentialDescriptor.
        :param resident_key_requirement: The desired RESIDENT_KEY_REQUIREMENT level.
        :param user_verification: The desired USER_VERIFICATION level.
        :param authenticator_attachment: The desired AUTHENTICATOR_ATTACHMENT
            or None to not provide a preference (and get both types).
        :param challenge: A custom challenge to sign and verify or None to use
            OS-specific random bytes.
        :return: Registration data, internal state."""
        if not self.allowed_algorithms:
            raise ValueError("Server has no allowed algorithms.")

        challenge = _validata_challenge(challenge)
        descriptors = _wrap_credentials(credentials)
        state = self._make_internal_state(challenge, user_verification)
        logger.debug(
            "Starting new registration, existing credentials: "
            + ", ".join(d.id.hex() for d in descriptors or [])
        )

        return (
            CredentialCreationOptions(
                public_key=PublicKeyCredentialCreationOptions(
                    rp=self.rp,
                    user=PublicKeyCredentialUserEntity.from_dict(user),
                    challenge=challenge,
                    pub_key_cred_params=self.allowed_algorithms,
                    timeout=self.timeout,
                    exclude_credentials=descriptors,
                    authenticator_selection=(
                        AuthenticatorSelectionCriteria(
                            authenticator_attachment=authenticator_attachment,
                            resident_key=resident_key_requirement,
                            user_verification=user_verification,
                        )
                        if any(
                            (
                                authenticator_attachment,
                                resident_key_requirement,
                                user_verification,
                            )
                        )
                        else None
                    ),
                    attestation=self.attestation,
                    extensions=extensions,
                )
            ),
            state,
        )

    def register_complete(
        self,
        state,
        response: RegistrationResponse | Mapping[str, Any],
    ) -> AuthenticatorData:
        """Verify the correctness of the registration data received from
        the client.

        :param state: The state data returned by the corresponding
            `register_begin`.
        :param response: The registration response from the client.
        :return: The authenticator data
        """
        registration = RegistrationResponse.from_dict(response)
        client_data = registration.response.client_data
        attestation_object = registration.response.attestation_object

        if client_data.type != CollectedClientData.TYPE.CREATE:
            raise ValueError("Incorrect type in CollectedClientData.")
        if not self._verify(client_data.origin):
            raise ValueError("Invalid origin in CollectedClientData.")
        if not constant_time.bytes_eq(
            websafe_decode(state["challenge"]), client_data.challenge
        ):
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(
            self.rp.id_hash or b"", attestation_object.auth_data.rp_id_hash
        ):
            raise ValueError("Wrong RP ID hash in response.")
        if not attestation_object.auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            state["user_verification"] == UserVerificationRequirement.REQUIRED
            and not attestation_object.auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but User Verified flag not set."
            )

        if self.attestation not in (None, AttestationConveyancePreference.NONE):
            logger.debug(f"Verifying attestation of type {attestation_object.fmt}")
            self._verify_attestation(attestation_object, client_data.hash)
        # We simply ignore attestation if self.attestation == 'none', as not all
        # clients strip the attestation.

        auth_data = attestation_object.auth_data
        assert auth_data.credential_data is not None  # noqa: S101
        logger.info(
            "New credential registered: "
            + auth_data.credential_data.credential_id.hex()
        )
        return auth_data

    def authenticate_begin(
        self,
        credentials: (
            Sequence[
                AttestedCredentialData
                | PublicKeyCredentialDescriptor
                | WebAuthnCredential
            ]
            | None
        ) = None,
        user_verification: UserVerificationRequirement | None = None,
        challenge: bytes | None = None,
        extensions=None,
    ) -> tuple[CredentialRequestOptions, Any]:
        """Return a PublicKeyCredentialRequestOptions assertion object and the internal
        state dictionary that needs to be passed as is to the corresponding
        `authenticate_complete` (or `authenticate_complete_stateful`) call.

        When `credentials` are given, the request is bound to a pre-selected
        account: the credential IDs are included in the returned
        allowCredentials, and the same set (together with the account's user
        handle when `WebAuthnCredential` records are used) is embedded in the
        state. A stateful completion can then never authenticate a credential
        outside this set, even if the client sends a larger collection.

        When `credentials` is None, no account is pre-selected (discoverable
        credential / resident key flow), and the state records that fact. The
        account must instead be determined from the userHandle returned in the
        assertion.

        :param credentials: The list of previously registered credentials, these can be
            of type AttestedCredentialData, PublicKeyCredentialDescriptor, or
            WebAuthnCredential.
        :param user_verification: The desired USER_VERIFICATION level.
        :param challenge: A custom challenge to sign and verify or None to use
            OS-specific random bytes.
        :return: Assertion data, internal state."""
        challenge = _validata_challenge(challenge)
        descriptors = _wrap_credentials(credentials)
        state = self._make_internal_state(challenge, user_verification)
        if descriptors is None:
            logger.debug("Starting new authentication without credentials")
            state["user_handle"] = None
            state["allowed_credential_ids"] = None
        else:
            logger.debug(
                "Starting new authentication, for credentials: "
                + ", ".join(d.id.hex() for d in descriptors)
            )
            # Bind the request to the allowed credential IDs and the account.
            # The values are websafe-encoded so the state stays JSON
            # serializable, e.g. when stored in a browser session.
            state["allowed_credential_ids"] = [
                websafe_encode(d.id) for d in descriptors
            ]
            user_handles = {
                c.user_handle
                for c in (credentials or [])
                if isinstance(c, WebAuthnCredential)
            }
            if len(user_handles) > 1:
                raise ValueError(
                    "All credentials for an authentication must belong to the "
                    "same user handle."
                )
            state["user_handle"] = (
                websafe_encode(next(iter(user_handles))) if user_handles else None
            )

        return (
            CredentialRequestOptions(
                public_key=PublicKeyCredentialRequestOptions(
                    challenge=challenge,
                    timeout=self.timeout,
                    rp_id=self.rp.id,
                    allow_credentials=descriptors,
                    user_verification=user_verification,
                    extensions=extensions,
                )
            ),
            state,
        )

    def authenticate_complete(
        self,
        state,
        credentials: Sequence[AttestedCredentialData],
        response: AuthenticationResponse | Mapping[str, Any],
    ) -> AttestedCredentialData:
        """Verify the correctness of the assertion data received from
        the client.

        This is the low-level, stateless check: it validates the challenge,
        origin, RP ID, UP/UV flags and signature against the given
        credentials, but it does not bind the assertion to an account or check
        the signature counter and backup flags. Applications that need those
        guarantees should use `authenticate_complete_stateful` instead.

        :param state: The state data returned by the corresponding
            `authenticate_begin`.
        :param credentials: The list of previously registered credentials.
        :param response: The assertion response from the client.
        :return: The attested credential data that authenticated.
        """
        authentication = AuthenticationResponse.from_dict(response)
        credential_id = authentication.raw_id
        client_data = authentication.response.client_data
        auth_data = authentication.response.authenticator_data
        signature = authentication.response.signature

        self._verify_assertion_base(state, client_data, auth_data)

        for cred in credentials:
            if cred.credential_id == credential_id:
                self._verify_signature(cred, auth_data, client_data, signature)
                logger.info(f"Credential authenticated: {credential_id.hex()}")
                return cred
        raise ValueError("Unknown credential ID.")

    def authenticate_complete_stateful(
        self,
        state,
        credentials: Sequence[WebAuthnCredential],
        response: AuthenticationResponse | Mapping[str, Any],
    ) -> tuple[WebAuthnCredential, dict]:
        """Verify an assertion and bind it to an account, with full state checks.

        In addition to the checks performed by `authenticate_complete`
        (challenge, origin, RP ID, UP/UV and signature), this enforces that the
        assertion actually belongs to the account that initiated the request,
        and validates the signature counter and backup flags. All flag and
        counter values are taken from the signed `AuthenticatorData`; any
        client-supplied fields with the same names are ignored.

        Two flows are supported, determined by the `state` produced by
        `authenticate_begin`:

        * Pre-selected account (credentials were given to `authenticate_begin`):
          the credential ID must be part of the set bound into the state, a
          larger collection sent by the client can never widen the scope, and
          the userHandle, if the client provides one, must match the account's
          user handle byte for byte. If the client omits userHandle that is
          acceptable for this flow.
        * Discoverable credential (no credentials were given to
          `authenticate_begin`): there is no pre-selected account, so the
          userHandle returned by the authenticator is required and must match
          a registered credential; a matching credential ID alone is never
          enough to identify the account.

        On success a new `WebAuthnCredential` holding the updated sign count
        and backup state is returned together with a new state dict, which the
        application should persist in place of the old record. Nothing passed
        in by the caller is modified; on failure no record or state is changed.

        :param state: The state data returned by the corresponding
            `authenticate_begin`.
        :param credentials: The registered `WebAuthnCredential` records to
            consider. For a pre-selected account these should be exactly the
            records of the account; for a discoverable flow they can be all
            registered records, the state still constrains the outcome.
        :param response: The assertion response from the client.
        :return: The updated credential record and a new, savable state dict.
        """
        authentication = AuthenticationResponse.from_dict(response)
        credential_id = authentication.raw_id
        client_data = authentication.response.client_data
        auth_data = authentication.response.authenticator_data
        signature = authentication.response.signature
        response_user_handle = authentication.response.user_handle

        # Every check below runs against local copies; the caller's records and
        # state are only touched when building the return value on success.
        if "allowed_credential_ids" not in state or "user_handle" not in state:
            raise ValueError(
                "Invalid state: use the state returned by authenticate_begin."
            )
        allowed_ids = state["allowed_credential_ids"]
        state_user_handle = (
            websafe_decode(state["user_handle"])
            if state["user_handle"] is not None
            else None
        )

        self._verify_assertion_base(state, client_data, auth_data)

        if allowed_ids is not None:
            # Pre-selected account: the state decides which credentials may be
            # used, regardless of how many the client happens to send.
            if not any(
                constant_time.bytes_eq(websafe_decode(allowed_id), credential_id)
                for allowed_id in allowed_ids
            ):
                raise ValueError("Credential ID not allowed for this request.")
            candidates = [
                c for c in credentials if c.credential_id == credential_id
            ]
        else:
            # Discoverable credential flow: no account was selected up front,
            # so the signed userHandle is the only acceptable account hint.
            if response_user_handle is None:
                raise ValueError(
                    "userHandle is required for discoverable credential "
                    "authentication."
                )
            candidates = [
                c
                for c in credentials
                if c.credential_id == credential_id
                and constant_time.bytes_eq(c.user_handle, response_user_handle)
            ]

        if not candidates:
            raise ValueError("Unknown credential ID.")
        if len(candidates) > 1:
            raise ValueError("Multiple matching credentials found.")
        credential = candidates[0]

        if state_user_handle is not None and not constant_time.bytes_eq(
            state_user_handle, credential.user_handle
        ):
            raise ValueError("Credential does not belong to the selected user.")

        # For a pre-selected account an omitted userHandle is fine, but a
        # present one has to match the account byte for byte.
        if (
            allowed_ids is not None
            and response_user_handle is not None
            and not constant_time.bytes_eq(
                response_user_handle, credential.user_handle
            )
        ):
            raise ValueError("userHandle does not match the selected user.")

        # Verify the signature first: everything below is only meaningful once
        # the authenticator data is authenticated.
        self._verify_signature(
            credential.credential_data, auth_data, client_data, signature
        )
        self._verify_backup_flags(credential, auth_data)
        self._verify_counter(credential, auth_data)

        new_state = dict(state)
        new_state["sign_count"] = auth_data.counter
        new_credential = WebAuthnCredential(
            credential_data=credential.credential_data,
            user_handle=credential.user_handle,
            sign_count=auth_data.counter,
            backup_eligible=credential.backup_eligible,
            backup_state=auth_data.is_backed_up(),
        )
        logger.info(f"Credential authenticated: {credential_id.hex()}")
        return new_credential, new_state

    def _verify_assertion_base(
        self,
        state,
        client_data: CollectedClientData,
        auth_data: AuthenticatorData,
    ) -> None:
        """Checks shared by the stateless and stateful completion methods."""
        if client_data.type != CollectedClientData.TYPE.GET:
            raise ValueError("Incorrect type in CollectedClientData.")
        if not self._verify(client_data.origin):
            raise ValueError("Invalid origin in CollectedClientData.")
        if not constant_time.bytes_eq(
            websafe_decode(state["challenge"]), client_data.challenge
        ):
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(self.rp.id_hash or b"", auth_data.rp_id_hash):
            raise ValueError("Wrong RP ID hash in response.")
        if not auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            state["user_verification"] == UserVerificationRequirement.REQUIRED
            and not auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but user verified flag not set."
            )

    @staticmethod
    def _verify_signature(
        credential: AttestedCredentialData,
        auth_data: AuthenticatorData,
        client_data: CollectedClientData,
        signature: bytes,
    ) -> None:
        try:
            credential.public_key.verify(auth_data + client_data.hash, signature)
        except _InvalidSignature:
            raise ValueError("Invalid signature.")

    @staticmethod
    def _verify_backup_flags(
        credential: WebAuthnCredential, auth_data: AuthenticatorData
    ) -> None:
        # BS=1 together with BE=0 is an invalid authenticator state.
        if auth_data.is_backed_up() and not auth_data.is_backup_eligible():
            raise ValueError(
                "Backup State set without Backup Eligibility in authenticator "
                "data."
            )
        # Backup Eligibility is fixed for the lifetime of a credential.
        if auth_data.is_backup_eligible() != credential.backup_eligible:
            raise ValueError(
                "Backup Eligibility flag does not match the registered value."
            )

    @staticmethod
    def _verify_counter(
        credential: WebAuthnCredential, auth_data: AuthenticatorData
    ) -> None:
        # Authenticators that do not maintain a counter report 0 every time;
        # otherwise the counter must strictly increase.
        if credential.sign_count != 0 or auth_data.counter != 0:
            if auth_data.counter <= credential.sign_count:
                raise ValueError("Signature counter did not increase.")

    @staticmethod
    def _make_internal_state(
        challenge: bytes, user_verification: UserVerificationRequirement | None
    ):
        return {
            "challenge": websafe_encode(challenge),
            "user_verification": user_verification,
        }
