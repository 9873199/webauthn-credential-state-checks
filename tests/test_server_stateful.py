# Copyright (c) 2026 Yubico AB
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

"""Tests for the stateful, account-binding assertion verification.

All assertions are produced by a purely software-backed "authenticator"
(an EC key held in memory), so no browser or USB device is required.
"""

import copy
import json
import os
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fido2.cose import ES256
from fido2.server import Fido2Server, WebAuthnCredential
from fido2.utils import sha256, websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

RP_ID = "example.com"
ORIGIN = "https://example.com"


class SoftCredential:
    """A passkey backed by an in-memory ES256 key.

    It can produce authenticator data and real signatures exactly the way a
    hardware authenticator would, while every field remains under the test's
    control.
    """

    def __init__(self, user_handle, counter=0, backup_eligible=False,
                 backup_state=False):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = ES256.from_cryptography_key(
            self.private_key.public_key()
        )
        self.credential_id = b"cred-id-" + os.urandom(16)
        self.user_handle = user_handle
        self.counter = counter
        self.backup_eligible = backup_eligible
        self.backup_state = backup_state
        self.aaguid = Aaguid(b"\x01" * 16)

    @property
    def credential_data(self):
        return AttestedCredentialData.create(
            self.aaguid, self.credential_id, self.public_key
        )

    def record(self):
        """The WebAuthnCredential record an application would persist."""
        return WebAuthnCredential(
            credential_data=self.credential_data,
            user_handle=self.user_handle,
            sign_count=self.counter,
            backup_eligible=self.backup_eligible,
            backup_state=self.backup_state,
        )

    def make_auth_data(
        self,
        rp_id_hash,
        counter=None,
        backup_eligible=None,
        backup_state=None,
        up=True,
        uv=False,
    ):
        flags = 0
        if up:
            flags |= AuthenticatorData.FLAG.UP
        if uv:
            flags |= AuthenticatorData.FLAG.UV
        be = self.backup_eligible if backup_eligible is None else backup_eligible
        bs = self.backup_state if backup_state is None else backup_state
        if be:
            flags |= AuthenticatorData.FLAG.BE
        if bs:
            flags |= AuthenticatorData.FLAG.BS
        return AuthenticatorData.create(
            rp_id_hash, flags, self.counter if counter is None else counter
        )

    def sign(self, auth_data, client_data):
        return self.private_key.sign(
            auth_data + client_data.hash, ec.ECDSA(hashes.SHA256())
        )

    def make_response(
        self,
        challenge,
        rp_id_hash,
        *,
        user_handle="signed",
        counter=None,
        backup_eligible=None,
        backup_state=None,
        up=True,
        uv=False,
        raw_id=None,
        bad_signature=False,
    ):
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET, challenge, ORIGIN
        )
        auth_data = self.make_auth_data(
            rp_id_hash,
            counter=counter,
            backup_eligible=backup_eligible,
            backup_state=backup_state,
            up=up,
            uv=uv,
        )
        signature = self.sign(auth_data, client_data)
        if bad_signature:
            signature = b"\x00" * len(signature)
        if user_handle == "signed":
            handle = self.user_handle
        elif user_handle == "none":
            handle = None
        else:
            handle = user_handle  # explicit bytes override
        return AuthenticationResponse(
            raw_id=raw_id or self.credential_id,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=auth_data,
                signature=signature,
                user_handle=handle,
            ),
        )


class TestStatefulAuthentication(unittest.TestCase):
    def setUp(self):
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(name="Example", id=RP_ID)
        )
        self.rp_id_hash = self.server.rp.id_hash
        self.alice = SoftCredential(b"alice-handle", counter=10)
        self.bob = SoftCredential(b"bob-handle", counter=20)

    def _begin(self, credentials=None, **kwargs):
        options, state = self.server.authenticate_begin(
            credentials, challenge=os.urandom(32), **kwargs
        )
        return options, state

    # -- registration record ------------------------------------------------

    def test_registration_builds_credential_record(self):
        auth_data = AuthenticatorData.create(
            self.rp_id_hash,
            AuthenticatorData.FLAG.UP
            | AuthenticatorData.FLAG.AT
            | AuthenticatorData.FLAG.BE,
            7,
            self.alice.credential_data,
        )
        record = WebAuthnCredential.from_registration(
            self.alice.user_handle, auth_data
        )
        self.assertEqual(record.credential_id, self.alice.credential_id)
        self.assertEqual(record.user_handle, b"alice-handle")
        self.assertEqual(record.sign_count, 7)
        self.assertTrue(record.backup_eligible)
        self.assertFalse(record.backup_state)
        # The public key data is kept and remains usable for verification.
        self.assertEqual(
            record.credential_data.public_key, self.alice.public_key
        )

    def test_begin_binds_credentials_and_account_to_state(self):
        record = self.alice.record()
        _, state = self._begin([record])
        self.assertEqual(
            state["allowed_credential_ids"],
            [websafe_encode(self.alice.credential_id)],
        )
        self.assertEqual(state["user_handle"], websafe_encode(b"alice-handle"))
        # State must survive JSON serialization, e.g. in a browser session.
        json.loads(json.dumps(state))

    def test_begin_discoverable_flow_state(self):
        _, state = self._begin()
        self.assertIsNone(state["allowed_credential_ids"])
        self.assertIsNone(state["user_handle"])

    def test_begin_rejects_credentials_from_multiple_accounts(self):
        with self.assertRaises(ValueError):
            self._begin([self.alice.record(), self.bob.record()])

    # -- pre-selected account flow ------------------------------------------

    def test_preselected_success_omitted_user_handle(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=11
        )

        new_record, new_state = self.server.authenticate_complete_stateful(
            state, [record], response
        )

        self.assertEqual(new_record.sign_count, 11)
        self.assertEqual(new_state["sign_count"], 11)
        # The caller's record and state are not modified.
        self.assertEqual(record.sign_count, 10)
        self.assertNotIn("sign_count", state)

    def test_preselected_accepts_matching_user_handle(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, counter=11
        )
        new_record, _ = self.server.authenticate_complete_stateful(
            state, [record], response
        )
        self.assertEqual(new_record.user_handle, b"alice-handle")

    def test_preselected_rejects_mismatched_user_handle(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle=b"bob-handle",
            counter=11,
        )
        with self.assertRaisesRegex(ValueError, "userHandle"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_scope_cannot_widen_after_begin(self):
        alice_record = self.alice.record()
        bob_record = self.bob.record()
        _, state = self._begin([alice_record])
        # The client/complete call gets hold of a larger set of credentials,
        # but the state must keep the assertion within the original scope.
        response = self.bob.make_response(
            state["challenge"], self.rp_id_hash, counter=21
        )
        with self.assertRaisesRegex(ValueError, "not allowed"):
            self.server.authenticate_complete_stateful(
                state, [alice_record, bob_record], response
            )

    def test_cross_account_credential_rejected(self):
        alice_record = self.alice.record()
        _, state = self._begin([alice_record])
        response = self.bob.make_response(
            state["challenge"], self.rp_id_hash, counter=21
        )
        with self.assertRaisesRegex(ValueError, "not allowed"):
            self.server.authenticate_complete_stateful(
                state, [alice_record], response
            )

    def test_state_account_binding_cannot_be_swapped_at_complete(self):
        # The state binds Alice's handle, but the record handed to complete
        # reuses the same credential ID under Bob's handle.
        alice_record = self.alice.record()
        swapped_record = WebAuthnCredential(
            credential_data=alice_record.credential_data,
            user_handle=b"bob-handle",
            sign_count=10,
            backup_eligible=False,
            backup_state=False,
        )
        _, state = self._begin([alice_record])
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=11
        )
        with self.assertRaisesRegex(ValueError, "selected user"):
            self.server.authenticate_complete_stateful(
                state, [swapped_record], response
            )

    # -- discoverable credential flow ---------------------------------------

    def test_discoverable_success_uses_signed_user_handle(self):
        records = [self.alice.record(), self.bob.record()]
        _, state = self._begin()
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, counter=11
        )
        new_record, new_state = self.server.authenticate_complete_stateful(
            state, records, response
        )
        self.assertEqual(new_record.user_handle, b"alice-handle")
        self.assertEqual(new_record.credential_id, self.alice.credential_id)

    def test_discoverable_requires_user_handle(self):
        _, state = self._begin()
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=11
        )
        with self.assertRaisesRegex(ValueError, "userHandle is required"):
            self.server.authenticate_complete_stateful(
                state, [self.alice.record()], response
            )

    def test_discoverable_raw_id_alone_does_not_identify_account(self):
        # The assertion is signed by Alice's key, but claims Bob's user
        # handle. A matching rawId must not be enough to authenticate.
        records = [self.alice.record(), self.bob.record()]
        _, state = self._begin()
        response = self.alice.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle=b"bob-handle",
            counter=11,
        )
        with self.assertRaisesRegex(ValueError, "Unknown credential ID"):
            self.server.authenticate_complete_stateful(
                state, records, response
            )

    # -- counter -------------------------------------------------------------

    def test_counter_must_strictly_increase(self):
        record = self.alice.record()  # sign_count == 10
        for new_counter, ok in ((10, False), (9, False), (11, True)):
            _, state = self._begin([record])
            response = self.alice.make_response(
                state["challenge"],
                self.rp_id_hash,
                user_handle="none",
                counter=new_counter,
            )
            if ok:
                new_record, _ = self.server.authenticate_complete_stateful(
                    state, [record], response
                )
                self.assertEqual(new_record.sign_count, new_counter)
            else:
                with self.assertRaisesRegex(ValueError, "counter"):
                    self.server.authenticate_complete_stateful(
                        state, [record], response
                    )
                self.assertEqual(record.sign_count, 10)

    def test_zero_counters_are_accepted(self):
        cred = SoftCredential(b"alice-handle", counter=0)
        record = cred.record()
        _, state = self._begin([record])
        response = cred.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=0
        )
        new_record, _ = self.server.authenticate_complete_stateful(
            state, [record], response
        )
        self.assertEqual(new_record.sign_count, 0)

    def test_zero_to_nonzero_counter_is_accepted(self):
        cred = SoftCredential(b"alice-handle", counter=0)
        record = cred.record()
        _, state = self._begin([record])
        response = cred.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=1
        )
        new_record, _ = self.server.authenticate_complete_stateful(
            state, [record], response
        )
        self.assertEqual(new_record.sign_count, 1)

    def test_nonzero_to_zero_counter_is_rejected(self):
        record = self.alice.record()  # sign_count == 10
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=0
        )
        with self.assertRaisesRegex(ValueError, "counter"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    # -- backup flags --------------------------------------------------------

    def test_backup_state_without_backup_eligibility_is_rejected(self):
        cred = SoftCredential(
            b"alice-handle", counter=1, backup_eligible=False, backup_state=False
        )
        record = cred.record()
        _, state = self._begin([record])
        response = cred.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=2,
            backup_eligible=False,
            backup_state=True,  # illegal BS=1, BE=0 combination
        )
        with self.assertRaisesRegex(ValueError, "Backup State"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_backup_eligibility_change_is_rejected(self):
        cred = SoftCredential(
            b"alice-handle", counter=1, backup_eligible=True, backup_state=False
        )
        record = cred.record()
        _, state = self._begin([record])
        response = cred.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=2,
            backup_eligible=False,  # differs from the registered value
            backup_state=False,
        )
        with self.assertRaisesRegex(ValueError, "Backup Eligibility"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_backup_state_switch_is_accepted(self):
        cred = SoftCredential(
            b"alice-handle", counter=1, backup_eligible=True, backup_state=False
        )
        record = cred.record()
        _, state = self._begin([record])
        response = cred.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=2,
            backup_state=True,  # legitimate BS change, BE stays 1
        )
        new_record, _ = self.server.authenticate_complete_stateful(
            state, [record], response
        )
        self.assertTrue(new_record.backup_eligible)
        self.assertTrue(new_record.backup_state)

    def test_client_supplied_backup_fields_are_ignored(self):
        # Client JSON claims backup eligibility, but the signed
        # authenticator data carries the illegal BS=1, BE=0 combination.
        cred = SoftCredential(b"alice-handle", counter=1)
        record = cred.record()
        _, state = self._begin([record])
        response = cred.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=2,
            backup_eligible=False,
            backup_state=True,
        )
        data = dict(response)
        data["response"]["backupEligible"] = True
        data["response"]["backupState"] = True
        with self.assertRaisesRegex(ValueError, "Backup State"):
            self.server.authenticate_complete_stateful(
                state, [record], data
            )

    def test_client_supplied_counter_field_is_ignored(self):
        record = self.alice.record()  # stored sign_count == 10
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=3
        )
        data = dict(response)
        data["response"]["signCount"] = 999  # client-invented field
        with self.assertRaisesRegex(ValueError, "counter"):
            self.server.authenticate_complete_stateful(
                state, [record], data
            )

    # -- signature and the retained base checks ------------------------------

    def test_invalid_signature_is_rejected(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=11,
            bad_signature=True,
        )
        with self.assertRaisesRegex(ValueError, "Invalid signature"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_wrong_challenge_is_rejected(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            os.urandom(32), self.rp_id_hash, user_handle="none", counter=11
        )
        with self.assertRaisesRegex(ValueError, "Wrong challenge"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_wrong_origin_is_rejected(self):
        record = self.alice.record()
        _, state = self._begin([record])
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            state["challenge"],
            "https://evil.example",
        )
        auth_data = self.alice.make_auth_data(self.rp_id_hash, counter=11)
        response = AuthenticationResponse(
            raw_id=self.alice.credential_id,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=auth_data,
                signature=self.alice.sign(auth_data, client_data),
            ),
        )
        with self.assertRaisesRegex(ValueError, "Invalid origin"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_wrong_rp_id_hash_is_rejected(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"],
            sha256(b"other.example"),
            user_handle="none",
            counter=11,
        )
        with self.assertRaisesRegex(ValueError, "Wrong RP ID"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_user_present_flag_is_required(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=11,
            up=False,
        )
        with self.assertRaisesRegex(ValueError, "User Present"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

    def test_user_verification_is_enforced(self):
        record = self.alice.record()
        _, state = self._begin(
            [record], user_verification=UserVerificationRequirement.REQUIRED
        )
        response = self.alice.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=11,
            uv=False,
        )
        with self.assertRaisesRegex(ValueError, "User verification"):
            self.server.authenticate_complete_stateful(
                state, [record], response
            )

        # With the UV flag set the same request succeeds.
        _, state = self._begin(
            [record], user_verification=UserVerificationRequirement.REQUIRED
        )
        response = self.alice.make_response(
            state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=11,
            uv=True,
        )
        new_record, _ = self.server.authenticate_complete_stateful(
            state, [record], response
        )
        self.assertEqual(new_record.sign_count, 11)

    # -- state handling ------------------------------------------------------

    def test_state_roundtrips_through_json(self):
        record = self.alice.record()
        _, state = self._begin([record])
        restored_state = json.loads(json.dumps(state))
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=11
        )
        new_record, _ = self.server.authenticate_complete_stateful(
            restored_state, [record], response
        )
        self.assertEqual(new_record.sign_count, 11)

    def test_legacy_state_is_rejected(self):
        record = self.alice.record()
        legacy_state = {
            "challenge": websafe_encode(os.urandom(32)),
            "user_verification": None,
        }
        response = self.alice.make_response(
            legacy_state["challenge"],
            self.rp_id_hash,
            user_handle="none",
            counter=11,
        )
        with self.assertRaisesRegex(ValueError, "Invalid state"):
            self.server.authenticate_complete_stateful(
                legacy_state, [record], response
            )

    def test_failure_does_not_modify_callers_data(self):
        record = self.alice.record()
        _, state = self._begin([record])
        records_snapshot = copy.deepcopy([record])
        state_snapshot = copy.deepcopy(state)

        for response in (
            # counter regression
            self.alice.make_response(
                state["challenge"],
                self.rp_id_hash,
                user_handle="none",
                counter=5,
            ),
            # bad signature
            self.alice.make_response(
                state["challenge"],
                self.rp_id_hash,
                user_handle="none",
                counter=11,
                bad_signature=True,
            ),
        ):
            with self.assertRaises(ValueError):
                self.server.authenticate_complete_stateful(
                    state, [record], response
                )

        self.assertEqual(record, records_snapshot[0])
        self.assertEqual(state, state_snapshot)

    # -- backwards compatibility --------------------------------------------

    def test_legacy_authenticate_complete_still_works(self):
        record = self.alice.record()
        _, state = self._begin([record])
        response = self.alice.make_response(
            state["challenge"], self.rp_id_hash, user_handle="none", counter=11
        )
        cred = self.server.authenticate_complete(
            state, [record.credential_data], response
        )
        self.assertEqual(cred.credential_id, self.alice.credential_id)

    def test_legacy_authenticate_complete_unknown_credential(self):
        _, state = self._begin([self.alice.record()])
        response = self.bob.make_response(
            state["challenge"], self.rp_id_hash, counter=21
        )
        with self.assertRaisesRegex(ValueError, "Unknown credential ID"):
            self.server.authenticate_complete(
                state, [self.alice.record().credential_data], response
            )


if __name__ == "__main__":
    unittest.main()
