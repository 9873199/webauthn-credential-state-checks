"""Independent account/flag/counter acceptance, generated offline signatures."""
import copy
from dataclasses import replace
import pytest
from fido2.server import Fido2Server,WebAuthnCredential
from fido2.webauthn import UserVerificationRequirement
from webauthn_fixture import Authenticator,server

def registered(s,a,flags=0x41,count=0):
 state,response=a.registration(s,flags=flags,counter=count)
 ad=s.register_complete(state,response)
 return WebAuthnCredential.from_registration(a.user,ad)

def reject(s,state,records,response):
 before=copy.deepcopy((state,records))
 with pytest.raises(ValueError):
  s.authenticate_complete_stateful(state,records,response)
 assert (state,records)==before

def test_selected_account_can_omit_handle_and_return_fresh_saved_record():
 s=server();a=Authenticator();rec=registered(s,a)
 _,state=s.authenticate_begin([rec]);before=copy.deepcopy((state,rec))
 new,newstate=s.authenticate_complete_stateful(state,[rec],a.assertion(s,state,counter=1))
 assert new.sign_count==1 and new.user_handle==a.user
 assert new is not rec and newstate is not state and (state,rec)==before

def test_cannot_expand_begin_scope_with_larger_completion_collection():
 s=server();a=Authenticator();b=Authenticator(b'bob',b'credential-B')
 ra=registered(s,a);rb=registered(s,b)
 _,state=s.authenticate_begin([ra])
 reject(s,state,[ra,rb],b.assertion(s,state,counter=1,user_handle=b.user))

def test_selected_handle_is_exact_bytes_even_with_correct_signature():
 s=server();a=Authenticator();r=registered(s,a);_,state=s.authenticate_begin([r])
 reject(s,state,[r],a.assertion(s,state,counter=1,user_handle=b'Alice'))
 reject(s,state,[r],a.assertion(s,state,counter=1,user_handle=b'alice\0'))

def test_selected_empty_allowlist_cannot_become_discoverable():
 s=server();a=Authenticator();r=registered(s,a);_,state=s.authenticate_begin([])
 reject(s,state,[r],a.assertion(s,state,counter=1,user_handle=a.user))

@pytest.mark.parametrize('handle',[None,b'bob',b'alice\0'])
def test_discoverable_needs_matching_handle_not_only_raw_id(handle):
 s=server();a=Authenticator();r=registered(s,a);_,state=s.authenticate_begin()
 reject(s,state,[r],a.assertion(s,state,counter=1,user_handle=handle))

def test_discoverable_selects_registered_account_by_handle():
 s=server();a=Authenticator();b=Authenticator(b'bob',b'credential-B')
 ra=registered(s,a);rb=registered(s,b);_,state=s.authenticate_begin()
 updated,_=s.authenticate_complete_stateful(state,[ra,rb],b.assertion(s,state,counter=4,user_handle=b.user))
 assert updated.user_handle==b.user and updated.credential_id==b.cid and updated.sign_count==4
 assert rb.sign_count==0

@pytest.mark.parametrize('old,new,accepted',[(0,0,True),(0,1,True),(1,0,False),(1,1,False),(1,2,True),(9,3,False)])
def test_counter_boundaries(old,new,accepted):
 s=server();a=Authenticator();r=registered(s,a,count=old);_,state=s.authenticate_begin([r])
 response=a.assertion(s,state,counter=new)
 if not accepted:reject(s,state,[r],response)
 else:
  updated,_=s.authenticate_complete_stateful(state,[r],response);assert updated.sign_count==new and r.sign_count==old

@pytest.mark.parametrize('reg_flags,new_flags,accepted',[(0x41,0x11,False),(0x41,0x09,False),(0x49,0x01,False),(0x49,0x19,True),(0x59,0x09,True)])
def test_authenticated_backup_flags(reg_flags,new_flags,accepted):
 s=server();a=Authenticator();r=registered(s,a,flags=reg_flags);_,state=s.authenticate_begin([r])
 response=a.assertion(s,state,flags=new_flags,counter=1)
 if not accepted:reject(s,state,[r],response)
 else:
  updated,_=s.authenticate_complete_stateful(state,[r],response)
  assert updated.backup_eligible==r.backup_eligible and updated.backup_state==bool(new_flags&16)
  assert r.backup_state==bool(reg_flags&16)

@pytest.mark.parametrize('bad',[
 {'corrupt':True},{'origin':'https://evil.invalid'},{'challenge':b'wrong-challenge-32-bytes-aaaaaaaa'},
 {'rp_hash':b'\0'*32},{'flags':0}])
def test_original_protocol_invariants_are_still_enforced(bad):
 s=server();a=Authenticator();r=registered(s,a);_,state=s.authenticate_begin([r])
 reject(s,state,[r],a.assertion(s,state,counter=1,**bad))

def test_user_verification_requirement_is_preserved():
 s=server();a=Authenticator();r=registered(s,a)
 _,state=s.authenticate_begin([r],user_verification=UserVerificationRequirement.REQUIRED)
 reject(s,state,[r],a.assertion(s,state,counter=1,flags=1))
 updated,_=s.authenticate_complete_stateful(state,[r],a.assertion(s,state,counter=1,flags=5))
 assert updated.sign_count==1

def test_legacy_completion_still_returns_attested_credential():
 s=server();a=Authenticator();r=registered(s,a);_,state=s.authenticate_begin([r.credential_data])
 assert s.authenticate_complete(state,[r.credential_data],a.assertion(s,state,counter=1))==r.credential_data
