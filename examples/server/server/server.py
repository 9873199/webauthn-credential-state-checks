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

"""
Example demo server to use a supported web browser to call the WebAuthn APIs
to register and use a credential.

See the file README.adoc in this directory for details.

Navigate to http://localhost:5000 in a supported web browser.
"""

import os

from flask import Flask, abort, jsonify, redirect, request, session

from fido2.server import Fido2Server, WebAuthnCredential
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

app = Flask(__name__, static_url_path="")
app.secret_key = os.urandom(32)  # Used for session.

rp = PublicKeyCredentialRpEntity(name="Demo server", id="localhost")
server = Fido2Server(rp)

USER_ID = b"user_id"

# Registered credentials are stored globally, in memory only. Single user
# support, state is lost when the server terminates. A real application must
# persist these records (including the user handle, sign count and backup
# flags) in a database, keyed by credential ID and user handle.
credentials: list[WebAuthnCredential] = []


@app.route("/")
def index():
    return redirect("/index.html")


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state
    print("\n\n\n\n")
    print(dict(options))
    print("\n\n\n\n")

    return jsonify(dict(options))


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    response = request.json
    print("RegistrationResponse:", response)
    auth_data = server.register_complete(session["state"], response)

    # Persist a full credential record: public key data, the account user
    # handle, sign count and backup flags, all from the signed
    # authenticator data.
    credential = WebAuthnCredential.from_registration(USER_ID, auth_data)
    credentials.append(credential)
    print("REGISTERED CREDENTIAL:", credential)
    return jsonify({"status": "OK"})


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    if not credentials:
        abort(404)

    # Binds the allowed credential IDs and the account to the server state.
    options, state = server.authenticate_begin(credentials)
    session["state"] = state

    return jsonify(dict(options))


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    if not credentials:
        abort(404)

    response = request.json
    print("AuthenticationResponse:", response)
    # pop removes the state from the session: the challenge is single use and
    # must never be accepted a second time.
    state = session.pop("state")
    credential, new_state = server.authenticate_complete_stateful(
        state,
        credentials,
        response,
    )
    # On success, persist the updated record (new sign count / backup state).
    def _matches(cred):
        return cred.credential_id == credential.credential_id

    index = next(i for i, c in enumerate(credentials) if _matches(c))
    credentials[index] = credential
    print("ASSERTION OK", new_state)
    return jsonify({"status": "OK"})


def main():
    print(__doc__)
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(host="localhost", debug=False)


if __name__ == "__main__":
    main()
