"""Offline signed WebAuthn fixtures; no new product API assumptions."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import (AttestedCredentialData,AuthenticatorData,CollectedClientData,
 AuthenticationResponse,AuthenticatorAssertionResponse,RegistrationResponse,
 AuthenticatorAttestationResponse,AttestationObject)
from fido2.server import Fido2Server
class Authenticator:
 def __init__(self,user=b'alice',credential_id=b'credential-A'):
  self.user=user;self.cid=credential_id;self.private=ec.generate_private_key(ec.SECP256R1())
  self.credential=AttestedCredentialData.create(b'\0'*16,credential_id,ES256.from_cryptography_key(self.private.public_key()))
 def registration(self,server,flags=0x41,counter=0):
  _,state=server.register_begin({'id':self.user,'name':self.user.decode()},challenge=b'R'*32)
  client=CollectedClientData.create(CollectedClientData.TYPE.CREATE,b'R'*32,'https://example.com')
  ad=AuthenticatorData.create(server.rp.id_hash,flags,counter,self.credential)
  response=RegistrationResponse(raw_id=self.cid,response=AuthenticatorAttestationResponse(client_data=client,attestation_object=AttestationObject.create('none',ad,{})))
  return state,response
 def assertion(self,server,state,*,flags=1,counter=0,user_handle=None,origin='https://example.com',challenge=None,rp_hash=None,corrupt=False):
  client=CollectedClientData.create(CollectedClientData.TYPE.GET,challenge if challenge is not None else state['challenge'],origin)
  ad=AuthenticatorData.create(rp_hash if rp_hash is not None else server.rp.id_hash,flags,counter)
  data=bytes(ad)+client.hash;signature=self.private.sign(data,ec.ECDSA(hashes.SHA256()))
  self.private.public_key().verify(signature,data,ec.ECDSA(hashes.SHA256()))
  if corrupt:signature=signature[:-1]+bytes([signature[-1]^1])
  return AuthenticationResponse(raw_id=self.cid,response=AuthenticatorAssertionResponse(client_data=client,authenticator_data=ad,signature=signature,user_handle=user_handle))
def server():
 return Fido2Server({'id':'example.com','name':'Example'})
if __name__=='__main__':
 s=server();a=Authenticator();state,response=a.registration(s);ad=s.register_complete(state,response)
 _,state=s.authenticate_begin([ad.credential_data]);resp=a.assertion(s,state,counter=1,user_handle=a.user)
 assert s.authenticate_complete(state,[ad.credential_data],resp)==a.credential
 try:s.authenticate_complete(state,[ad.credential_data],a.assertion(s,state,corrupt=True))
 except ValueError:pass
 else:raise AssertionError('Corrupt signature should fail')
 print('Fixture controls PASS: real generated P-256 registration/assertion; independent signature verified; corrupt signature rejected. No browser, USB or network.')
