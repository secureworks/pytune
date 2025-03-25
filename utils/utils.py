import os
import jwt
import re
import struct
import base64
import subprocess
import requests
import binascii
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadlib.auth import Authentication
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def get_nonce():
    response = requests.post(
        url=f"https://login.microsoftonline.com/645064ee-9b6e-43db-9d46-fe81a65cfdea/oauth2/token",
        data='grant_type=srv_challenge'
        )
    return response.json()['Nonce']

def get_tenantid(domain):
    res = requests.get(f'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration')
    token_endpoint = res.json()['token_endpoint']
    return token_endpoint.split('/')[3]

def get_devicetoken(tenant, certpfx):
    nonce = get_nonce()
    tid = get_tenantid(tenant)

    certpath = f'device_cert.pem'
    keypath = f'device_key.pem'
    extract_pfx(certpfx, certpath, keypath)

    with open(certpath, "rb") as certf:
        certificate = x509.load_pem_x509_certificate(certf.read())
    with open(keypath, "rb") as keyf:
        keydata = keyf.read()
    
    os.remove(certpath)
    os.remove(keypath)

    certder = certificate.public_bytes(serialization.Encoding.DER)
    certbytes = base64.b64encode(certder)

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "x5c": certbytes.decode('utf-8'),
    }        
    payload = {
        "resource": "https://enrollment.manage.microsoft.com/",
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
        "request_nonce": nonce,
        "win_ver": "10.0.19041.1806",
        "grant_type": "device_token",
        "scope":"sid",
        "redirect_uri": "ms-aadj-redir://auth/mdm",
        "iss": "aad:brokerplugin"
    }

    reqjwt = jwt.encode(payload, algorithm='RS256', key=keydata, headers=headers)  

    res = requests.post(
        url=f'https://login.microsoftonline.com/{tid}/oauth2/token',
        data=f'windows_api_version=2.2&grant_type=urn%3aietf%3aparams%3aoauth%3agrant-type%3ajwt-bearer&request={reqjwt}'
        )
    return res.json()['access_token']

def gettokens(username, password, clientid, resource):
    auth = Authentication(username, password, None, clientid)
    auth.resource_uri = resource
    return auth.authenticate_username_password()

def deviceauth(username, password, refresh_token, certpfx, proxy):
    device_auth = DeviceAuthentication()
    device_auth.proxies = proxy
    device_auth.verify = False
    auth = Authentication()
    auth.proxies = proxy
    auth.verify = False
    device_auth.auth = auth

    device_auth.loadcert(None, None, certpfx, 'password')
    
    if password:
        response = device_auth.get_prt_with_password(username, password)
    else:        
        response = device_auth.get_prt_with_refresh_token(refresh_token)

    return response['refresh_token'], response['session_key']

def prtauth(prt, session_key, client_id, resource, redirect_uri, proxy):
    device_auth = DeviceAuthentication()
    device_auth.proxies = proxy
    device_auth.verify = False
    auth = Authentication()
    auth.proxies = proxy
    auth.verify = False
    device_auth.auth = auth

    device_auth.prt = prt
    device_auth.session_key = binascii.unhexlify(session_key)
    res = device_auth.aad_brokerplugin_prt_auth(
        client_id=client_id, 
        resource=resource,
        redirect_uri=redirect_uri,        
        )

    if 'error' in res.keys():
        print(res['error_description'])
        return None
    
    return res['access_token'], res['refresh_token']

def renew_token(refresh_token, client_id, scope, proxy):
    data = {
        'client_id':client_id,
        'grant_type':'refresh_token',
        'refresh_token':refresh_token,
        'scope':scope
    }
    
    response = requests.post(
        "https://login.microsoftonline.com/common/oAuth2/v2.0/token",
        data=data,
        proxies=proxy,
        verify=False
    )
    json = response.json()
    return json['access_token']

def token_renewal_for_enrollment(url, access_token, proxy):
    headers = {'Authorization': 'Bearer {}'.format(access_token)}

    response = requests.get(
        url=f"{url}?api-version=1.0",
        headers=headers,
        proxies=proxy,
        verify=False
    )

    return response.json()['Result']['Token']

def create_pfx(certpath, keypath, pfxpath):
    with open(certpath, 'rb') as public_key_file:
        cert_bytes = public_key_file.read()
    
    with open(keypath, 'rb') as private_key_file:
        key_bytes = private_key_file.read()
    
    certificate = load_pem_x509_certificate(cert_bytes, default_backend())
    private_key = serialization.load_pem_private_key(key_bytes, None, default_backend())

    pfx = serialization.pkcs12.serialize_key_and_certificates(
        pfxpath.encode('utf-8'),
        private_key,
        certificate,
        None,
        serialization.BestAvailableEncryption(b'password')
        )

    with open(pfxpath, 'wb') as outfile:
        outfile.write(pfx)

    return

def extract_pfx(pfxpath, certpath, keypath):
    subprocess.run(f'openssl pkcs12 -in {pfxpath} -nodes -password pass:password -out {certpath} -clcerts', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)    
    subprocess.run(f'openssl pkcs12 -in {pfxpath} -nodes -password pass:password -out {keypath} -nocerts -nodes', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return

def get_str_and_next(blob, start):
    str_size = (struct.unpack('<I', blob[start:start+0x4])[0]) * 2
    str = blob[start+0xc:start+0xc+str_size].decode('utf-16le')

    next = start+0xc+len(str)*2
    if next % 4 != 0:
        next +=+2

    return str, next

def save_encrypted_message_as_smime(encrypted_message, filename):
    
    smime_header = (
        "MIME-Version: 1.0\n"
        f'Content-Disposition: attachment; filename="{filename}"\n'
        f'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="{filename}"\n'
        "Content-Transfer-Encoding: base64\n\n"
    )

    wrapped_string = '\n'.join([encrypted_message[i:i+64] for i in range(0, len(encrypted_message), 64)])
    smime_message = smime_header + wrapped_string

    with open(filename, "w") as f:
        f.write(smime_message)

def decrypt_smime_file(filename, keypath):
    result = subprocess.run(f'cat {filename} | openssl cms -decrypt -inkey {keypath}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8')

def aes_decrypt(key, iv, content):    
    cipher = Cipher(algorithms.AES(base64.b64decode(key)), modes.CBC(base64.b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(content) + decryptor.finalize()
    return decrypted_data