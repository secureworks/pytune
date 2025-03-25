import base64
import requests
import xml.etree.ElementTree as ET
import xmltodict
from datetime import datetime, timedelta, timezone
from device.device import Device
from utils.utils import renew_token

class Android(Device):
    def __init__(self, logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy):
        super().__init__(logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        self.os_version = '8.2.0'
        self.ssp_version = '5.0.6060.0'
        self.checkin_url = 'https://a.manage.microsoft.com/devicegatewayproxy/AndroidHandler.ashx?Platform=AndroidForWork'
        self.provider_name = 'AndroidEnrollment'
        self.cname = 'ConfigMgrEnroll'

    def generate_initial_syncml(self, sessionid, imei):
        syncml_data = self.generate_syncml_header(1, sessionid, imei)
        syncml_data["SyncML"]["SyncBody"] = { 
            "Alert": {"CmdID": "1", "Data": "0"},
            "Replace": {
                "CmdID": "2",
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
                        "Data": self.get_syncml_data("./DevInfo/Mod")["Data"],
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/DmV"}, "Data": "1.0"
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Lang"}, 
                        "Data": self.get_syncml_data("./DevInfo/Lang")["Data"]
                    }
                ],
            },
            "Final": None
            }
        return xmltodict.unparse(syncml_data, pretty=False)

    def get_enrollment_token(self, refresh_token):
        return renew_token(refresh_token, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'openid offline_access profile d4ebce55-015a-49b5-a083-c84d1797ae8c/.default', self.proxy)

    def send_enroll_request(self, enrollment_url, csr_pem, csr_token, ztdregistrationid):
        token_b64 = base64.b64encode(csr_token.encode('utf-8')).decode('utf-8')
        body = f'''
    <s:Envelope
        xmlns:s="http://www.w3.org/2003/05/soap-envelope"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
        xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
            <a:MessageID>urn:uuid:0d5a1441-5891-453b-becf-a2e5f6ea3749</a:MessageID>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand="1">{enrollment_url}</a:To>
            <wsse:Security s:mustUnderstand="1">
                <wsse:BinarySecurityToken  ValueType="urn:ietf:params:oauth:token-type:jwt" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
                {token_b64}
                </wsse:BinarySecurityToken>
            </wsse:Security>
        </s:Header>
        <s:Body>
            <wst:RequestSecurityToken>
                <wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
                <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
                <wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
                {csr_pem}
                </wsse:BinarySecurityToken>
                <ac:AdditionalContext
                    xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
                    <ac:ContextItem Name="DeviceType">
                        <ac:Value>AndroidForWork</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="ApplicationVersion">
                        <ac:Value>{self.os_version}</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="AADID">
                        <ac:Value>{self.deviceid}</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="MobileEquipmentId">
                        <ac:Value>00000000000000</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="SerialNumber">
                        <ac:Value>PYTUNE</ac:Value>
                    </ac:ContextItem>
                    <ac:ContextItem Name="Manufacturer">
                        <ac:Value>Google</ac:Value>
                    </ac:ContextItem>
                </ac:AdditionalContext>
            </wst:RequestSecurityToken>
        </s:Body>
    </s:Envelope>
    '''

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

    def get_syncml_data(self, key):
        now = datetime.now(timezone(timedelta(minutes=540)))
        formatted_date = now.strftime("%Y%m%d%H%M%S.%f%z")
        data = {
            f"./DevInfo/Lang": {
                "Format": "chr",
                "Data": "en-US"
            },
            f"./DevInfo/Man": {
                "Format": "chr",
                "Data": "Google"
            },
            f"./DevDetail/SwV": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./DevDetail/Ext/Microsoft/LocalTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./Device/DevDetail/Ext/Microsoft/LocalTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./Vendor/MSFT/DeviceLock/DevicePolicyManager/IsActivePasswordSufficient": {
                "Format": "bool",
                "Data": "true"
            },
            f"./Vendor/MSFT/WorkProfileLock/DevicePolicyManager/IsActivePasswordSufficient": {
                "Format": "bool",
                "Data": "true"
            },
            f"./Device/Vendor/MSFT/DMClient/Provider/SCConfigMgr/EntDeviceName": {
                "Format": "chr",
                "Data": self.device_name
            },
            f"./Device/DevDetail/SwV": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./Device/DevInfo/DmI": {
                "Format": "chr",
                "Data": "com.android.vending"
            },
            f"./Device/DevInfo/Man": {
                "Format": "chr",
                "Data": "Google"
            },
            f"./Device/DevInfo/Mod": {
                "Format": "chr",
                "Data": "Android SDK built for x86"
            },
            f"./DevInfo/Mod": {
                "Format": "chr",
                "Data": "Android SDK built for x86"
            },
            f"./Device/DevDetail/Ext/Microsoft/KnoxStandardCapable": {
                "Format": "bool",
                "Data": "false"
            },
            f"./Device/DevDetail/Ext/Microsoft/KnoxStandardVersion": {
                "Format": "bool",
                "Data": "false"
            },
            f"./Device/DevDetail/Ext/Microsoft/Container": {
                "Format": "chr",
                "Data": "AndroidForWork"
            },
            f"./Device/Vendor/MSFT/DeviceInformation/APILevel": {
                "Format": "int",
                "Data": "27"
            },
            f"./Device/DevDetail/Ext/Microsoft/GoogleServicesAndroidId": {
                "Format": "chr",
                "Data": "371a184e7e106668"
            },        
            f"./Device/DevDetail/Ext/Microsoft/IMEI": {
                "Format": "chr",
                "Data": "00000000000000"
            },        
            f"./Device/DevDetail/Ext/Microsoft/SerialNumber": {
                "Format": "chr",
                "Data": "PYTUNE"
            },        
            f"./Device/DevDetail/Ext/Microsoft/PNSType": {
                "Format": "chr",
                "Data": "FCM"
            },
            f"./Device/Vendor/MSFT/GCM/774944887730/ChannelStatus": {
                "Format": "chr",
                "Data": None
            },        
            f"./Device/Vendor/MSFT/GCM/774944887730/Channel": {
                "Format": "chr",
                "Data": None
            },
            f"./Device/Vendor/MSFT/FCM/InstanceId": {
                "Format": "chr",
                "Data": "abc-abcdef"
            },
            f"./Device/DevInfo/Lang": {
                "Format": "chr",
                "Data": "en-US"
            },
            f"./Device/Vendor/MSFT/GooglePlayServices/IsAvailable": {
                "Format": "bool",
                "Data": "true"
            },
            f"./Device/Vendor/MSFT/DeviceLock/DevicePolicyManager/IsSecurityProvidersUpdated": {
                "Format": "bool",
                "Data": "true"
            },
            f"./User/{self.uid}/Vendor/MSFT/EnterpriseAppManagement/EnterpriseIDs": {
                "Format": "chr",
                "Data": self.tenant
            },
            f"./User/{self.uid}/Vendor/MSFT/Scheduler/IntervalDurationSeconds": {
                "Format": "int",
                "Data": "28800"
            },
            f"./Device/DevDetail/Ext/Microsoft/OSPlatform": {
                "Format": "chr",
                "Data": self.os
            },
            f"./Device/Vendor/MSFT/DeviceInformation/Version": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./Device/DevDetail/Ext/Microsoft/ICCID": {
                "Format": "chr",
                "Data": "89014103211118510720"
            },
            f"./Device/DevDetail/Ext/Microsoft/CommercializationOperator": {
                "Format": "chr",
                "Data": self.os
            },     
            f"./Device/Vendor/MSFT/DeviceInformation/IsDeviceRooted": {
                "Format": "int",
                "Data": "0"
            },
            f"./Device/DevDetail/Ext/Microsoft/CellularTechnology": {
                "Format": "chr",
                "Data": "GSM"
            },
            f"./Device/DevDetail/FwV": {
                "Format": "chr",
                "Data": "unknown"
            },        
            f"./Device/DevDetail/Ext/Microsoft/WifiMac": {
                "Format": "chr",
                "Data": "02:00:00:44:55:66"
            },
            f"./Device/Vendor/MSFT/DeviceLock/DevicePolicyManager/IsAndroidSecurityLevelPatched": {
                "Format": "chr",
                "Data": "2018-01-05"
            },  
            f"./Device/DevDetail/Ext/Microsoft/BuildNumber": {
                "Format": "chr",
                "Data": "OSM1.180201.007"
            },  
            f"./Device/Vendor/MSFT/DeviceLock/DevicePolicyManager/StorageEncryptionStatus": {
                "Format": "int",
                "Data": "5"
            },
            f"./User/{self.uid}/Vendor/MSFT/EnterpriseAppManagement/EnterpriseApps/ManagedInventory": {
                "Format": "node",
                "Data": "android/com.android.backupconfirm/com.android.bips/com.android.bookmarkprovider/com.android.calllogbackup/com.android.captiveportallogin/com.android.carrierconfig/com.android.cellbroadcastreceiver/com.android.certinstaller/com.android.companiondevicemanager/com.android.contacts/com.android.cts.ctsshim/com.android.cts.priv.ctsshim/com.android.defcontainer/com.android.documentsui/com.android.dreams.basic/com.android.egg/com.android.emulator.smoketests/com.android.externalstorage/com.android.htmlviewer/com.android.inputdevices/com.android.keychain/com.android.location.fused/com.android.managedprovisioning/com.android.mms.service/com.android.mtp/com.android.pacprocessor/com.android.phone/com.android.printspooler/com.android.protips/com.android.providers.blockednumber/com.android.providers.calendar/com.android.providers.contacts/com.android.providers.downloads/com.android.providers.downloads.ui/com.android.providers.media/com.android.providers.partnerbookmarks/com.android.providers.settings/com.android.providers.telephony/com.android.providers.userdictionary/com.android.proxyhandler/com.android.server.telecom/com.android.settings/com.android.sharedstoragebackup/com.android.shell/com.android.statementservice/com.android.storagemanager/com.android.systemui/com.android.systemui.theme.dark/com.android.vending/com.android.vpndialogs/com.android.wallpaper.livepicker/com.android.wallpaperbackup/com.breel.geswallpapers/com.example.android.livecubes/com.example.android.softkeyboard/com.google.android.apps.nexuslauncher/com.google.android.apps.wallpaper.nexus/com.google.android.backuptransport/com.google.android.configupdater/com.google.android.ext.services/com.google.android.ext.shared/com.google.android.feedback/com.google.android.gms/com.google.android.gsf/com.google.android.onetimeinitializer/com.google.android.packageinstaller/com.google.android.partnersetup/com.google.android.printservice.recommendation/com.google.android.sdksetup/com.google.android.setupwizard/com.google.android.syncadapters.contacts/com.google.android.tts/com.google.android.webview/com.microsoft.windowsintune.companyportal/com.ustwo.lwp/jp.co.omronsoft.openwnn"
            },  
            f"./Device/DevInfo/DmV": {
                "Format": "chr",
                "Data": "1.0"
            },
            f"./Device/DevDetail/HwV": {
                "Format": "chr",
                "Data": "ranchu"
            },
            f"./Device/DevDetail/DevTyp": {
                "Format": "chr",
                "Data": "sdk_gphone_x86"
            },
            f"./Device/DevDetail/OEM": {
                "Format": "chr",
                "Data": "Google Android SDK built for x86"
            },
            f"./User/{self.uid}/Vendor/MSFT/DeviceLock/Provider/SCConfigMgr/MaxDevicePasswordFailedAttempts": {
                "Format": "int",
                "Data": "0"
            },
            f"./User/{self.uid}/Vendor/MSFT/DeviceLock/Provider/SCConfigMgr/MinDevicePasswordLength": {
                "Format": "int",
                "Data": "0"
            },
            f"./User/{self.uid}/Vendor/MSFT/DeviceLock/Provider/SCConfigMgr/DevicePasswordHistory": {
                "Format": "int",
                "Data": "0"
            },   
            f"./User/{self.uid}/Vendor/MSFT/DeviceLock/Provider/SCConfigMgr/DevicePasswordEnabled": {
                "Format": "int",
                "Data": "1"
            },
            f"./User/{self.uid}/Vendor/MSFT/DeviceLock/Provider/SCConfigMgr/DevicePasswordExpiration": {
                "Format": "int",
                "Data": "0"
            },
            f"./User/{self.uid}/Vendor/MSFT/DeviceLock/Provider/SCConfigMgr/MaxInactivityTimeDeviceLock": {
                "Format": "int",
                "Data": "0"
            },
            f"./DevDetail/Ext/Microsoft/ProcessorArchitecture": {
                "Format": "chr",
                "Data": "x86"
            },
            f"./User/{self.uid}/Vendor/MSFT/WorkProfileLock/Provider/SCConfigMgr/ResetPasswordTokenStatus": {
                "Format": "chr",
                "Data": "Inactive"
            },        
            f"./User/{self.uid}/Vendor/MSFT/WorkProfile/AuthTokenRenewal/Required": {
                "Format": "bool",
                "Data": "false"
            },
            f"./User/{self.uid}/Vendor/MSFT/WorkProfile/AuthTokenRenewal/EncryptedTokenRequired": {
                "Format": "bool",
                "Data": "false"
            },               
            f"./Device/Vendor/MSFT/WorkplaceJoin/AADID": {
                "Format": "chr",
                "Data": self.deviceid
            },
            f"./User/{self.uid}/Vendor/MSFT/Scheduler/intervalDurationSeconds": {
                "Format": "int",
                "Data": "28800"
            },
            f"./Device/Vendor/MSFT/DeviceLock/DevicePolicyManager/IsActivePasswordSufficient": {
                "Format": "bool",
                "Data": "true"
            },
        }
        if key in data:
            return data[key]
        else:
            return None