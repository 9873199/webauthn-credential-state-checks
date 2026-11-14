import pytest
from fido2.server import WebAuthnCredential
from webauthn_fixture import Authenticator,server

def test_illegal_backup_combination_is_not_saved_from_registration():
 s=server();a=Authenticator();state,response=a.registration(s,flags=0x51)
 with pytest.raises(ValueError):
  data=s.register_complete(state,response)
  WebAuthnCredential.from_registration(a.user,data)

@pytest.mark.parametrize("flags",[0x41,0x49,0x59])
def test_legal_registration_flags_are_preserved(flags):
 s=server();a=Authenticator();state,response=a.registration(s,flags=flags,counter=9)
 data=s.register_complete(state,response);r=WebAuthnCredential.from_registration(a.user,data)
 assert r.sign_count==9 and r.user_handle==a.user
 assert r.backup_eligible==bool(flags&8) and r.backup_state==bool(flags&16)
