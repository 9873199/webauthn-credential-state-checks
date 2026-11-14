Server-side credential verification
===================================

A successfully verified assertion signature only proves that the holder of a
registered private key signed the challenge. It does **not** prove that the
credential belongs to the account that initiated the login. The application is
responsible for keeping server-side credential records and binding each
assertion to the right account. :class:`fido2.server.WebAuthnCredential` and
:meth:`fido2.server.Fido2Server.authenticate_complete_stateful` provide an
explicit, opt-in entry point which performs those checks in addition to the
cryptographic verification.

The older :meth:`fido2.server.Fido2Server.authenticate_complete` method is kept
unchanged for backwards compatibility, but it only validates the challenge,
origin, RP ID, UP/UV flags and signature. It does not check the account
binding, signature counter, or backup flags.

Persisting credential records
-----------------------------

After a successful registration, build a record from the signed
authenticator data and the account's user handle, and persist it:

.. code-block:: python

    auth_data = server.register_complete(state, response)
    credential = WebAuthnCredential.from_registration(user_handle, auth_data)
    # Store the credential in your database.

Each record contains everything needed for later verification:

* the attested credential data, including the **public key** and credential ID,
* the **user handle** of the account the credential belongs to,
* the initial **signCount**,
* the **Backup Eligibility (BE)** and **Backup State (BS)** flags.

Store the records so that they can be looked up both by credential ID (for the
pre-selected account flow) and by user handle (for the discoverable credential
flow). The values originate from the signed ``AuthenticatorData``; never
populate them from client-supplied JSON fields.

Pre-selected account flow
-------------------------

When the user first enters a username (or otherwise selects an account), pass
that account's credentials to ``authenticate_begin``. The allowed credential
IDs and the account's user handle are embedded in the returned state, which
must be kept server-side, for example in the user's session:

.. code-block:: python

    options, state = server.authenticate_begin(account_credentials)
    session["state"] = state  # keep it server-side

At completion, the state constrains which credentials may be used. Passing a
larger collection of records cannot widen the scope: a credential whose ID is
not part of the state is rejected even if it is included in the call.

.. code-block:: python

    state = session.pop("state")  # the challenge is single use
    credential, new_state = server.authenticate_complete_stateful(
        state, account_credentials, response
    )
    # Only now persist the updated record.
    save_credential(credential)

For this flow the authenticator may omit ``userHandle``; that is accepted. If
a ``userHandle`` is present it must match the account's stored user handle
byte for byte, otherwise the assertion is rejected.

Discoverable credential flow
----------------------------

With discoverable (resident) credentials the user does not select an account
first, so ``authenticate_begin`` is called without credentials:

.. code-block:: python

    options, state = server.authenticate_begin()
    session["state"] = state

There is no pre-selected account, so the ``userHandle`` returned in the
assertion is mandatory. The matching record must have both the returned
credential ID **and** the returned user handle; a matching credential ID alone
is never enough to identify the account.

Counter and backup flag checks
------------------------------

The stateful completion enforces, using values from the signed
``AuthenticatorData``:

* **Signature counter:** if either the stored counter or the new counter is
  non-zero, the new counter must be strictly greater than the stored one. If
  both are zero the assertion is accepted, as such authenticators do not
  maintain a counter.
* **Backup flags:** ``BS=1`` together with ``BE=0`` is an illegal combination
  and is rejected. The BE flag is fixed for the lifetime of a credential, so a
  value differing from the registered record is rejected. A legitimate BS
  change (while BE stays the same) is accepted.

Client-supplied JSON fields carrying the same names (for example
``backupEligible``, ``backupState`` or ``signCount``) are not trusted: only the
signed authenticator data is used.

Challenges are single use
-------------------------

The state returned by ``register_begin`` and ``authenticate_begin`` contains a
random challenge (at least 16 bytes, 32 by default) which is compared
constant-time against the client data. Treat it as a single-use, server-side
secret:

* keep the state in a session or another server-side store, never in
  client-controlled storage,
* consume it (remove it from the store) when the corresponding completion call
  arrives, whether it succeeds or fails, so the same challenge can never be
  presented twice,
* start a new ``*_begin`` call to obtain a fresh challenge for every retry.

Failure and success semantics
-----------------------------

On any validation error ``authenticate_complete_stateful`` raises an exception
and does not modify the records or state passed in by the caller. Only on
success does it return a new :class:`WebAuthnCredential` (with the updated
sign count and backup state) together with a new state dict. Persist those
returned values in place of the old record; do not mutate the inputs
yourself.
