import os
import io
import jwt
import base64
import gzip
import struct
import requests
import uuid
import json
import xmltodict
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from device.device import Device
from utils.utils import prtauth, extract_pfx, save_encrypted_message_as_smime, decrypt_smime_file, aes_decrypt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding


class Windows(Device):
    def __init__(self, logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy):
        super().__init__(logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        self.os_version = '10.0.19045.2006'
        self.ssp_version = self.os_version
        self.checkin_url = 'https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx'        
        self.provider_name = 'WindowsEnrollment'
        self.cname = 'ConfigMgrEnroll'
    
    def get_enrollment_token(self, refresh_token):
        access_token, refresh_token = prtauth(
            self.prt, self.session_key, '29d9ed98-a469-4536-ade2-f981bc1d605e', 'https://enrollment.manage.microsoft.com/', 'ms-aadj-redir://auth/mdm', self.proxy
            )
        return access_token

    def send_enroll_request(self, enrollment_url, csr_pem, csr_token, ztdregistrationid):
        claims = jwt.decode(csr_token, options={"verify_signature":False}, algorithms=['RS256'])
        hwdevid = f"{self.deviceid}{claims['tid']}".replace('-', '')
        token_b64 = base64.b64encode(csr_token.encode('utf-8')).decode('utf-8')
        message_id = str(uuid.uuid4())
        body = f'''
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
            <a:MessageID>urn:uuid:{message_id}</a:MessageID>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand="1">{enrollment_url}</a:To>
            <wsse:Security s:mustUnderstand="1">
                <wsse:BinarySecurityToken ValueType="urn:ietf:params:oauth:token-type:jwt" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">{token_b64}</wsse:BinarySecurityToken>
            </wsse:Security>
        </s:Header>
        <s:Body>
            <wst:RequestSecurityToken>
                <wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
                <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
                <wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">{csr_pem}</wsse:BinarySecurityToken>
                <ac:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
                    <ac:ContextItem Name="UXInitiated">
                        <ac:Value>true</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="HWDevID">
                        <ac:Value>{hwdevid}</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="BootstrapDomainJoin">
                        <ac:Value>true</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="NotInOobe">
                        <ac:Value>false</ac:Value>
                    </ac:ContextItem>
                    REPLACE_ZEROTOUCH_PROVISIONING
                    <ac:ContextItem Name="Locale">
                        <ac:Value>en-US</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="TargetedUserLoggedIn">
                        <ac:Value>false</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="EnrollmentData">
                        <ac:Value>null</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="OSEdition">
                        <ac:Value>72</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="DeviceName">
                        <ac:Value>{self.device_name}</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="MAC">
                        <ac:Value>00-00-00-00-00-00</ac:Value>
                    </ac:ContextItem>     
                    <ac:ContextItem Name="DeviceID">
                        <ac:Value>{self.deviceid.replace('-', '')}</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="EnrollmentType">
                        <ac:Value>Device</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="DeviceType">
                        <ac:Value>CIMClient_Windows</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="OSVersion">
                        <ac:Value>{self.os_version}</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="ApplicationVersion">
                        <ac:Value>{self.os_version}</ac:Value>
                    </ac:ContextItem>
                </ac:AdditionalContext>
            </wst:RequestSecurityToken>
        </s:Body>
    </s:Envelope>
    '''
        
        if ztdregistrationid:
            replace_str = f'''
                    <ac:ContextItem Name="ZeroTouchProvisioning">
                        <ac:Value>{ztdregistrationid}</ac:Value>
                    </ac:ContextItem>
                    '''
            body = body.replace('REPLACE_ZEROTOUCH_PROVISIONING', replace_str)
        else:
            body = body.replace('REPLACE_ZEROTOUCH_PROVISIONING', '')

        response = requests.post(
            url=enrollment_url,
            data=body,
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            proxies=self.proxy,
            verify=False
        )
        xml = ET.fromstring(response.content.decode('utf-8'))
        binary_security_token = xml.find('.//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken').text
        return base64.b64decode(binary_security_token).decode('utf-8')

    def generate_initial_syncml(self, sessionid, imei):
        syncml_data = self.generate_syncml_header(1, sessionid, imei)

        syncml_data["SyncML"]["SyncBody"] = {             
            "Alert": [],
            "Replace": {
                "CmdID": "6",
                "Item": [                             
                    {
                        "Source": {"LocURI": "./DevInfo/DevId"},
                        "Data": f"imei:{imei}",
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Man"}, 
                        "Data": self.get_syncml_data("./DevInfo/Man")["Data"]                           
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Mod"},
                        "Data": self.get_syncml_data("./DevInfo/Mod")["Data"] 
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/DmV"}, 
                        "Data": self.get_syncml_data("./DevInfo/DmV")["Data"] 
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Lang"}, 
                        "Data": self.get_syncml_data("./DevInfo/Lang")["Data"] 
                    }
                ],
            },
            "Final": None
            }          
          
        if self.hwhash:                            
                syncml_data["SyncML"]["SyncBody"]["Alert"] = [
                     {"CmdID": "2", "Data": "1201"},
                     {"CmdID": "3", "Data": "1224", "Item": {"Meta": {"Type": {"@xmlns": "syncml:metinf", "#text": "com.microsoft/MDM/LoginStatus"}},"Data": {"@xmlns": "SYNCML:SYNCML1.2", "#text":"others"}}},
                    {"CmdID": "4", "Data": "1224", "Item": {"Meta": {"Type": {"@xmlns": "syncml:metinf", "#text": "com.microsoft/MDM/BootstrapSync"}},"Data": {"@xmlns": "SYNCML:SYNCML1.2", "#text":"device"}}},
                    {"CmdID": "5", "Data": "1224", "Item": {"Meta": {"Type": {"@xmlns": "syncml:metinf", "#text": "com.microsoft/MDM/OdjSync"}},"Data": {"@xmlns": "SYNCML:SYNCML1.2", "#text":"device"}}}]

        return xmltodict.unparse(syncml_data, pretty=False)

    def get_syncml_data(self, key):
        offset = timedelta(hours=9)
        now = datetime.now()
        jst = timezone(offset)
        dt_with_tz = now.astimezone(jst)
        formatted_date = dt_with_tz.isoformat()
        data = {
            f"./DevInfo/DmV": {
                "Format": "int",
                "Data": '1.3'
            },
            f"./Vendor/MSFT/NodeCache/MS%20DM%20Server": {
                "Format": "chr",
                "Data": 'CacheVersion/Nodes/ChangedNodes/ChangedNodesData'
            },
            f"./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion": {
                "Format": "chr",
                "Data": None
            },
            f"./Vendor/MSFT/NodeCache/MS%20DM%20Server/ChangedNodes": {
                "Format": "chr",
                "Data": None
            },
            f"./Device/Vendor/MSFT/DeviceManageability/Provider/MS%20DM%20Server/ConfigInfo": {
                "Format": "chr",
                "Data": None
            },
            f"./Device/Vendor/MSFT/DeviceManageability/Provider/WMI_Bridge_Server/ConfigInfo": {
                "Format": "chr",
                "Data": None
            },
            f"./Vendor/MSFT/Policy/Config/Security/RequireRetrieveHealthCertificateOnBoot": {
                "Format": "chr",
                "Data": None
            },
            
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/ExchangeID": {
                "Format": "chr",
                "Data": self.uid
            },
            f"./Device/Vendor/MSFT/DeviceManageability/Capabilities/CSPVersions": {
                "Format": "chr",
                "Data": '&lt;?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot;?&gt;&lt;DeviceManageability Version=&quot;com.microsoft/1.1/MDM/DeviceManageability&quot;&gt;&lt;Capabilities&gt;&lt;CSPVersions&gt;&lt;CSP Node=&quot;./DevDetail&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./DevInfo&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/AssignedAccess&quot; Version=&quot;4.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/BitLocker&quot; Version=&quot;5.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/ClientCertificateInstall&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/DMClient&quot; Version=&quot;1.5&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/DeclaredConfiguration&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/DeviceManageability&quot; Version=&quot;2.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/DeviceUpdateCenter&quot; Version=&quot;2.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/EnrollmentStatusTracking&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/EnterpriseAppVManagement&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/EnterpriseDataProtection&quot; Version=&quot;4.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/EnterpriseDesktopAppManagement&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/EnterpriseModernAppManagement&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/GPCSEWrapper&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/NetworkQoSPolicy&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/OfflineDomainJoin&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/OptionalFeatures&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/PassportForWork&quot; Version=&quot;1.6&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/Policy&quot; Version=&quot;10.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/PolicyManager/DeviceLock&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/PolicyManager/Security&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/Reboot&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/RemoteLock&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/RootCATrustedCertificates&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/VPNv2&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/WindowsAdvancedThreatProtection&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/WindowsDefenderApplicationGuard&quot; Version=&quot;1.4&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/WindowsIoT&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Device/Vendor/MSFT/WindowsLicensing&quot; Version=&quot;1.4&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./SyncML/DMAcc&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./SyncML/DMS&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/ActiveSync&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/ClientCertificateInstall&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/DMClient&quot; Version=&quot;1.5&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/DMSessionActions&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/DeclaredConfiguration&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/EMAIL2&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/EnrollmentStatusTracking&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/EnterpriseAppVManagement&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/EnterpriseDesktopAppManagement&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/EnterpriseModernAppManagement&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/GPCSEWrapper&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/NodeCache&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/PassportForWork&quot; Version=&quot;1.6&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/Policy&quot; Version=&quot;10.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/PolicyManager/DeviceLock&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/PolicyManager/Security&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/PrinterProvisioning&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/RootCATrustedCertificates&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/VPNv2&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./User/Vendor/MSFT/WiFi&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/ActiveSync&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/AppLocker&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/CMPolicy&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/CMPolicyEnterprise&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/CellularSettings&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/CertificateStore&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/CleanPC&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DMClient&quot; Version=&quot;1.5&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DMSessionActions&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DeclaredConfiguration&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Defender&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DeviceLock&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DeviceStatus&quot; Version=&quot;1.5&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DeviceUpdate&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DiagnosticLog&quot; Version=&quot;1.4&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/DynamicManagement&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/EMAIL2&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/EnterpriseAPN&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/EnterpriseModernAppManagement&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Firewall&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/GPCSEWrapper&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/HealthAttestation&quot; Version=&quot;1.3&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/LanguagePackManagement&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Maps&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/MultiSIM&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/NetworkProxy&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/NodeCache&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Office&quot; Version=&quot;1.5&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/PassportForWork&quot; Version=&quot;1.6&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Personalization&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Policy/NetworkIsolation&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/PolicyManager/DeviceLock&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/PolicyManager/Security&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/RemoteFind&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/RemoteLock&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/RemoteWipe&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Reporting&quot; Version=&quot;2.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/SUPL&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/SecureAssessment&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/SecurityPolicy&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/SharedPC&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Storage&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/TPMPolicy&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/TenantLockdown&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/UnifiedWriteFilter&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Update&quot; Version=&quot;1.1&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/VPNv2&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/WiFi&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/Win32AppInventory&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/WindowsAutopilot&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/WindowsLicensing&quot; Version=&quot;1.4&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/eUICCs&quot; Version=&quot;1.2&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./Vendor/MSFT/uefi&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_AppInstallJob&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_Application&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_ApplicationFramework&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_ApplicationSetting&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_BrowserSecurityZones&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_BrowserSettings&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_Certificate&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_CertificateEnrollment&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_Client&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_ConfigSetting&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_EASPolicy&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_MgmtAuthority&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_RemoteAppUserCookie&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_RemoteApplication&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_Restrictions&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_RestrictionsUser&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_SecurityStatus&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_SecurityStatusUser&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_SideLoader&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_Updates&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_VpnApplicationTrigger&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_VpnConnection&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_WNSChannel&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_WNSConfiguration&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_WebApplication&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_WirelessProfile&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MDM_WirelessProfileXml&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MSFT_NetFirewallProfile&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/MSFT_VpnConnection&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_DisplayConfiguration&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_EncryptableVolume&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_InfraredDevice&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_LocalTime&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_LogicalDisk&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_NetworkAdapter&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_NetworkAdapterConfiguration&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_OperatingSystem&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_PhysicalMemory&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_PnPDevice&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_PortableBattery&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_Processor&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_QuickFixEngineering&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_Registry&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_Service&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_Share&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_SystemBIOS&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_SystemEnclosure&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_TimeZone&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_UTCTime&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/Win32_WindowsUpdateAgentVersion&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcAppOverride&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcGameOverride&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcGamesSettings&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcRating&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcRatingsDescriptor&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcRatingsSystem&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcSystemSettings&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcURLOverride&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcUserSettings&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;CSP Node=&quot;./cimv2/WpcWebSettings&quot; Version=&quot;1.0&quot;&gt;&lt;/CSP&gt;&lt;/CSPVersions&gt;&lt;/Capabilities&gt;&lt;/DeviceManageability&gt;'
            },            
            f"./DevDetail/Ext/Microsoft/LocalTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./Device/DevDetail/Ext/Microsoft/LocalTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./DevDetail/Ext/Microsoft/DeviceName": {
                "Format": "chr",
                "Data": self.device_name
            },
            f"./Device/DevDetail/SwV": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./DevDetail/SwV": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./Vendor/MSFT/WindowsLicensing/Edition": {
                "Format": "int",
                "Data": "4"
            },
            f"./Vendor/MSFT/Update/LastSuccessfulScanTime": {
                "Format": "chr",
                "Data": formatted_date
            },        
            f"./Vendor/MSFT/DeviceStatus/OS/Mode": {
                "Format": "int",
                "Data": "0"
            },
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID": {
                "Format": "chr",
                "Data": self.deviceid
            },
            f"./DevInfo/Man": {
                "Format": "chr",
                "Data": "Microsoft Corporation"
            },
            f"./Device/DevInfo/Lang": {
                "Format": "chr",
                "Data": "en-US"
            },
            f"./DevInfo/Lang": {
                "Format": "chr",
                "Data": "en-US"
            },
            f"./Device/DevDetail/Ext/Microsoft/OSPlatform": {
                "Format": "chr",
                "Data": "Windows 10 Enterprise"
            },
            f"./Device/Vendor/MSFT/DeviceInformation/Version": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./DevInfo/Mod": {
                "Format": "chr",
                "Data": "VMware7.1"
            },     
            f"./Vendor/MSFT/DeviceStatus/OS/Edition": {
                "Format": "int",
                "Data": "4"
            },
            f"./DevDetail/FwV": {
                "Format": "chr",
                "Data": "VMW71.00V.00000000.000.0000000000"
            },  
            f"./DevDetail/Ext/Microsoft/OSPlatform": {
                "Format": "chr",
                "Data": "Windows 10 Enterprise"
            },    
            f"./DevDetail/Ext/Microsoft/DNSComputerName": {
                "Format": "chr",
                "Data": self.device_name
            },                    
            f"./Device/DevInfo/DmV": {
                "Format": "chr",
                "Data": "1.3"
            },
            f"./Device/DevDetail/HwV": {
                "Format": "chr",
                "Data": "Hyper-V UEFI Release v4.0"
            },
            f"./Device/DevDetail/DevTyp": {
                "Format": "chr",
                "Data": "VMware 7.1"
            },
            f"./Device/DevDetail/OEM": {
                "Format": "chr",
                "Data": "Microsoft Corporation"
            },
            f"./DevDetail/Ext/Microsoft/ProcessorArchitecture": {
                "Format": "int",
                "Data": "9"
            },
            f"./Vendor/MSFT/DMClient/HWDevID": {
                "Format": "chr",
                "Data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },            
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/PublisherDeviceID": {
                "Format": "chr",
                "Data": None
            },
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDeviceName": {
                "Format": "chr",
                "Data": self.device_name
            },
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/ForceAadToken": {
                "Format": "int",
                "Data": 1
            },
            f"./Device/Vendor/MSFT/BitLocker/Status/DeviceEncryptionStatus": {
                "Format": "int",
                "Data": 2
            },                                    
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/AADResourceID": {
                "Format": "chr",
                "Data": "https://manage.microsoft.com/"
            },
            f"./DevDetail/Ext/DeviceHardwareData": {
                "Format":"chr",
                "Data":self.hwhash
            },
            f"./Vendor/MSFT/WindowsAutopilot/HardwareMismatchRemediationData": {
                "Format":"chr",
                "Data":None
            },
        }
        if key in data:
            return data[key]
        else:
            return None
        
    def send_syncml(self, data, certpath, keypath):
        response = requests.post(
            url=self.checkin_url,
            data=data,
            headers={
                'User-Agent': f'MSFT {self.os} OMA DM Client/2.7' , 'Content-Type': 'application/vnd.syncml.dm+xml',
                },
            cert=(certpath, keypath)
            )
        return response.content
    
    def download_apps(self, mdmpfx):
        certpath = 'pytune_mdm.crt'
        keypath = 'pytune_mdm.key'
        extract_pfx(mdmpfx, certpath, keypath)

        ime = IME(self.device_name, certpath, keypath)
        
        self.logger.info(f'downloading scripts...')
        policies = ime.request_policy()
        if len(policies) == 0:
            self.logger.error(f'available scripts not found')
        else:
            self.logger.alert(f'scripts found!')
            i = 1
            for policy in policies:
                self.logger.info(f'#{i} (policyid:{policy["PolicyId"]}):\n')
                print(policy["PolicyBody"] + '\n')
                i=i+1

        self.logger.info(f'downloading win32apps...')
        apps = ime.get_selected_app()
        if len(apps) == 0:
            self.logger.error(f'available intunewin file not found')

        for app in apps:
            self.logger.alert(f'found {app["Name"]}!')
            content_info = ime.get_content_info(app)
            upload_location = json.loads(content_info["ContentInfo"])["UploadLocation"]
            decrypt_info = ime.decrypt_decryptinfo(content_info["DecryptInfo"])            
            self.logger.info(f'downloading from {upload_location} ...')
            ime.download_decrypt_intunewin(app["Name"], upload_location, decrypt_info["EncryptionKey"], decrypt_info["IV"])
            self.logger.success(f'successfully downloaded to {app["Name"]}.intunewin!')


        os.remove(certpath)
        os.remove(keypath)

class IME():
    def __init__(self, device_name, certpath, keypath):
        self.device_name = device_name
        self.certpath = certpath
        self.keypath = keypath

    def create_request_data(self, sessionid, gateway_api, request_payload=None):
        if request_payload == None:
            request_payload_str = "[]"
        else:
            request_payload_str = json.dumps(request_payload)

        data = {
            "Key": sessionid,
            "SessionId": sessionid,
            "RequestContentType": gateway_api,
            "RequestPayload": request_payload_str,
            "ResponseContentType": None,
            "ClientInfo": json.dumps({
                "DeviceName": self.device_name,
                "OperatingSystemVersion": "10.0.19045",
                "SideCarAgentVersion": "1.83.107.0",
                "Win10SMode": False,
                "UnlockWin10SModeTenantId": None,
                "UnlockWin10SModeDeviceId": None,
                "ChannelUriInformation": None,
                "AgentExecutionStartTime": "10/11/2024 23:15:42",
                "AgentExecutionEndTime": "10/11/2024 23:15:38",
                "AgentCrashSeen": True,
                "ExtendedInventoryMap": {
                    "OperatingSystemRevisionNumber": "2006",
                    "SKU": "72",
                    "DotNetFrameworkReleaseValue": "528372"
                }
            }),
            "ResponsePayload": None,
            "EnabledFlights": None,
            "CheckinIntervalMinutes": None,
            "GenericWorkloadRequests": None,
            "GenericWorkloadResponse": None,
            "CheckinReason": "AgentRestart",
            "CheckinReasonPayload": None
        }
        return data

    def resolve_service_address(self):
        response = requests.get(
            url='https://manage.microsoft.com/RestUserAuthLocationService/RestUserAuthLocationService/Certificate/ServiceAddresses',
            cert=(self.certpath, self.keypath),
            )
        
        services = response.json()[0]["Services"]
        sidecar_url = None
        for service in services:
            if service['ServiceName'] == 'SideCarGatewayService':
                sidecar_url = service['Url']
        return sidecar_url
    
    def decrypt_decryptinfo(self, decryptinfo):
        start = decryptinfo.find('<EncryptedContent>') + len('<EncryptedContent>')
        end = decryptinfo.find('</EncryptedContent>')
        encrypted_content = decryptinfo[start:end].strip()
        smime_file = 'smime.p7m'
        save_encrypted_message_as_smime(encrypted_content, smime_file)
        decrypted_content = decrypt_smime_file(smime_file, self.keypath)
        decrypt_info = json.loads(decrypted_content)
        os.remove(smime_file)
        return decrypt_info

    def decompress_string(self, compressed_text):
        buffer = base64.b64decode(compressed_text)
        data_length = struct.unpack('I', buffer[:4])[0]        
        memory_stream = io.BytesIO(buffer[4:])
        
        with gzip.GzipFile(fileobj=memory_stream, mode='rb') as gzip_stream:
            decompressed_data = gzip_stream.read(data_length)
        
        return decompressed_data.decode('utf-8')
    
    def get_selected_app(self):

        sidecar_url = self.resolve_service_address()
        sessionid = str(uuid.uuid4())
        data = self.create_request_data(sessionid, "GetSelectedApp")

        headers = {
            'Content-Type': 'application/json',
            'Prefer': 'return-content',
        }

        response = requests.put(
            url=f'{sidecar_url}/SideCarGatewaySessions(\'{sessionid}\')?api-version=1.5',
            cert=(self.certpath, self.keypath),
            data=json.dumps(data),
            headers=headers,
            )
        
        response_payload = response.json()['ResponsePayload']
        decompressed_string = self.decompress_string(response_payload)
        return json.loads(decompressed_string)

    def get_content_info(self, assigned_app):
        sidecar_url = self.resolve_service_address()
        with open(self.certpath, 'rb') as pem_file:
            pem_data = pem_file.read()

        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        cert_base64 = base64.b64encode(cert.public_bytes(Encoding.DER)).decode('utf-8')

        request_payload = {
                "ApplicationId": assigned_app['Id'],
                "ApplicationVersion": assigned_app["Version"],
                "Intent": assigned_app["Intent"],
                "CertificateBlob": cert_base64,
                "ContentInfo": None,
                "SecondaryContentInfo": None,
                "DecryptInfo": None,
                "UploadLocation": None,
                "TargetingMethod": 0,
                "ErrorCode": None,
                "TargetType": 2,
                "InstallContext": 2,
                "EspPhase": 2,
                "ApplicationName": assigned_app['Name'],
                "AssignmentFilterIds": None,
                "ManagedInstallerStatus": 1,
                "ApplicationEnforcement": 0
            }
        sessionid = str(uuid.uuid4())
        data = self.create_request_data(sessionid, "GetContentInfo", request_payload)

        headers = {
            'Content-Type': 'application/json',
            'Prefer': 'return-content'
        }

        response = requests.put(
            url=f'{sidecar_url}/SideCarGatewaySessions(\'{sessionid}\')?api-version=1.5',
            cert=(self.certpath, self.keypath),
            data=json.dumps(data),
            headers=headers,
            )    

        response_payload = response.json()["ResponsePayload"]
        return json.loads(response_payload)

    def download_decrypt_intunewin(self, appname, upload_location, key, iv):
        response = requests.get(
            url=upload_location
        )

        decrypted_data = aes_decrypt(key, iv, response.content[48:])
        with open(f'{appname}.intunewin', 'wb') as f:
            f.write(decrypted_data)        

    def request_policy(self):
        sidecar_url = self.resolve_service_address()
        if sidecar_url == None:
            self.logger.error(f'SidecCarGatewayService not found')
            return

        sessionid = str(uuid.uuid4())
        data = self.create_request_data(sessionid, "PolicyRequest")
        headers = {
            'Content-Type': 'application/json',
            'Prefer': 'return-content'
        }

        response = requests.put(
            url=f'{sidecar_url}/SideCarGatewaySessions(\'{sessionid}\')?api-version=1.5',
            cert=(self.certpath, self.keypath),
            data=json.dumps(data),
            headers=headers,
            )    
        response_payload = response.json()["ResponsePayload"]
        return json.loads(response_payload)
