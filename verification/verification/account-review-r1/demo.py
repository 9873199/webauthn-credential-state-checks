"""Separate offline demonstration; calls the unchanged frozen product."""
from webauthn_fixture import Authenticator,server
from fido2.server import WebAuthnCredential
import copy
s=server();a=Authenticator();b=Authenticator(b'bob',b'credential-B')
def register(auth):
 state,response=auth.registration(s);data=s.register_complete(state,response)
 return WebAuthnCredential.from_registration(auth.user,data)
ra,rb=register(a),register(b)
print('Registered two software credentials with real P-256 keys.')
_,state=s.authenticate_begin([ra]);before=copy.deepcopy((state,ra))
updated,_=s.authenticate_complete_stateful(state,[ra],a.assertion(s,state,counter=1))
assert updated.sign_count==1 and (state,ra)==before
print('Account login: ACCEPTED; saved counter advances to 1.')
def denied(label,records,response):
 try:s.authenticate_complete_stateful(state,records,response)
 except ValueError as exc:print(label+': REJECTED ('+str(exc)+')')
 else:raise AssertionError(label+' unexpectedly accepted')
denied('Other account',[ra,rb],b.assertion(s,state,counter=1,user_handle=b.user))
denied('Wrong signature',[ra],a.assertion(s,state,counter=1,corrupt=True))
denied('Counter replay',[updated],a.assertion(s,state,counter=1))
denied('Invalid backup flags',[ra],a.assertion(s,state,counter=1,flags=0x11))
_,state=s.authenticate_begin();updated,_=s.authenticate_complete_stateful(state,[ra,rb],b.assertion(s,state,counter=2,user_handle=b.user))
assert updated.user_handle==b.user
print('Discoverable login: ACCEPTED for the matching saved account.')
print('Completed offline. No browser, USB or external service used.')
state,response=a.registration(s,flags=0x51)
try:
 data=s.register_complete(state,response)
 invalid=WebAuthnCredential.from_registration(a.user,data)
except ValueError as exc:print('Registration with BS=1 / BE=0: REJECTED ('+str(exc)+')')
else:
 assert invalid.backup_state and not invalid.backup_eligible
 print('Registration with BS=1 / BE=0: ACCEPTED - validation missing.')
