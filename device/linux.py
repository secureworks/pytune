import os
import base64
import requests
from datetime import datetime
from cryptography import x509
from device.device import Device
from cryptography.hazmat.backends import default_backend
from utils.utils import prtauth, renew_token, extract_pfx

class Linux(Device):
    def __init__(self, logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy):
        super().__init__(logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        self.os_version = '22.04'
        self.ssp_version = '1.2312.35'
        self.checkin_url = None
        self.provider_name = 'LinuxEnrollmentService'
        self.cname = self.device_name

    def get_enrollment_token(self, refresh_token):
        access_token, _ = renew_token(refresh_token, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'openid offline_access profile d4ebce55-015a-49b5-a083-c84d1797ae8c/.default', self.proxy)        
        return access_token
    
    def send_enroll_request(self, enrollment_url, csr_pem, csr_token, ztdregistrationid,  is_avd, is_hejd):
        data = {
            "CertificateSigningRequest": f"-----BEGIN CERTIFICATE REQUEST-----\n{csr_pem}\n-----END CERTIFICATE REQUEST-----\n",
            "AppVersion": "0.0.0",
            "DeviceName": self.device_name
        }

        response = requests.post(
            url=f'{enrollment_url}/enroll?api-version=1.0',
            json=data,
            headers= {'Authorization': f'Bearer {csr_token}'},
            proxies=self.proxy,
            verify=False
        )
        self.logger.debug(f'received response for enrollment request:\n{response.content.decode()}')

        return response.json()
    
    def parse_enroll_response(self, enroll_response):
        if 'certificate' in enroll_response:
            cert = enroll_response['certificate']['certBlob']
            return base64.b64encode(bytes(cert))
        else:
            return None
        
    def exchange_devdetails(self, access_token):
        data = {
            "DeviceId":self.intune_deviceid,
            "DeviceName":self.device_name,
            "Manufacturer":"VMware, Inc.",
            "OSDistribution":"Ubuntu",
            "OSVersion":self.os_version
        }

        response = requests.post(
            url=f'{self.checkin_url}/details?api-version=1.0',
            json=data,
            headers= {'Authorization': f'Bearer {access_token}'},
        )

        if 'deviceFriendlyName' not in response.json():
            return False
        return True
    
    def fetch_policies(self, access_token):
        response = requests.get(
            url=f'{self.checkin_url}/policies/{self.intune_deviceid}?api-version=1.0',
            headers={'Authorization': 'Bearer {}'.format(access_token)},
        )

        return response.json()['policies']
            
    def report_policy_status(self, access_token, policies):
        current_time = datetime.now()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S')

        statuses = []
        if len(policies) != 0:
            for policy in policies:
                details = []
                for setting in policy['policySettings']:
                    details.append({
                        "RuleId":setting["ruleId"],
                        "SettingDefinitionItemId":setting["settingDefinitionItemId"],
                        "ExpectedValue":setting["value"],
                        "ActualValue":setting["value"],
                        "NewComplianceState":"Compliant",
                        "OldComplianceState":"Unknown"
                    })
                statuses.append({
                    "PolicyId":policy["policyId"],
                    "LastStatusDateTime":f'{formatted_time}-08:00',
                    "Details":details
                })

        data = {
            "DeviceId":self.intune_deviceid,
            "PolicyStatuses":statuses
        }

        response = requests.post(
            url=f'{self.checkin_url}/status?api-version=1.0',
            json=data,
            headers={'Authorization': 'Bearer {}'.format(access_token)},
        )
        return

    def checkin(self, mdmpfx):
        access_token, refresh_token = prtauth(self.prt, self.session_key, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'https://graph.microsoft.com/', None)        
        self.checkin_url = self.get_enrollment_info(access_token, 'LinuxDeviceCheckinService')        
        self.logger.info(f"resolved checkin url: {self.checkin_url}")

        access_token, _ = renew_token(refresh_token, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', '0000000a-0000-0000-c000-000000000000/.default openid offline_access profile')

        certpath = 'pytune_mdm.crt'
        keypath = 'pytune_mdm.key'
        extract_pfx(mdmpfx, certpath, keypath)
        with open(certpath, 'rb') as cert_file:
            cert_data = cert_file.read()
        os.remove(certpath)
        os.remove(keypath)

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        self.intune_deviceid = common_name[0].value

        if self.exchange_devdetails(access_token) is False:
            self.logger.alert('device may be already retired')
            return
        
        policies = self.fetch_policies(access_token)
        if len(policies) == 0:
            self.logger.info('no policies are assigned to this device')
        else:
            self.logger.success('compliance policy found!')
            i = 1
            for policy in policies:
                self.logger.alert(f'compliance policy #{i}:')
                for setting in policy['policySettings']:
                    print(f' - item : {setting["settingDefinitionItemId"]}')
                    print(f' - expected value : {setting["value"]}')
                i = i+1

        self.report_policy_status(access_token, policies)
        
        self.logger.info('checkin ended!')
             
        return 