import jwt
import getpass
import argparse
from colr import color
from device.device import Device
from device.android import Android
from device.windows import Windows
from device.linux import Linux
from utils.utils import deviceauth, prtauth
from utils.logger import Logger

version = '1.1'
banner = r'''
 ______   __  __     ______   __  __     __   __     ______    
/\  == \ /\ \_\ \   /\__  _\ /\ \/\ \   /\ "-.\ \   /\  ___\   
\ \  _-/ \ \____ \  \/_/\ \/ \ \ \_\ \  \ \ \-.  \  \ \  __\   
 \ \_\    \/\_____\    \ \_\  \ \_____\  \ \_\\"\_\  \ \_____\ 
  \/_/     \/_____/     \/_/   \/_____/   \/_/ \/_/   \/_____/ 
                                                               
''' + \
f'      Faking a device to Microsft Intune (version:{version})'

class Pytune:
    def __init__(self, logger):
        self.logger = logger
        return
       
    def get_password(self, password):
        if password is None:
            password = getpass.getpass("Enter your password: ")
        return password

    def new_device(self, os, device_name, username, password, refresh_token, certpfx, proxy):
        prt = None
        session_key = None
        tenant = None
        deviceid = None
        uid = None

        if certpfx:
            if refresh_token is None:
                password = self.get_password(password)
            prt, session_key = deviceauth(username, password, refresh_token, certpfx, proxy)
            access_token, refresh_token = prtauth(prt, session_key, '29d9ed98-a469-4536-ade2-f981bc1d605e', 'https://enrollment.manage.microsoft.com/', 'ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS', proxy)
            claims = jwt.decode(access_token, options={"verify_signature":False}, algorithms=['RS256'])
            tenant = claims['upn'].split('@')[1]
            deviceid = claims['deviceid']
            uid = claims['oid']

        if os == 'Android':
            device = Android(self.logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif os == 'Windows':
            device = Windows(self.logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif os == 'Linux':
            device = Linux(self.logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        return device

    def entra_join(self, username, password, access_token, device_name, os, deviceticket, proxy):
        device = self.new_device(os, device_name, None, None, None, None, proxy)
        if access_token is None:
            password = self.get_password(password)

        device.entra_join(username, password, access_token, deviceticket)
        return

    def entra_delete(self, certpfx, proxy):
        device = Device(self.logger, None, None, None, None, None, None, None, proxy)
        device.entra_delete(certpfx)
        return

    def enroll_intune(self, os, device_name, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(os, device_name, username, password, refresh_token, certpfx, proxy)
        device.enroll_intune()

    def checkin(self, os, device_name, username, password, refresh_token, certpfx, mdmpfx, hwhash, proxy):
        device = self.new_device(os, device_name, username, password, refresh_token, certpfx, proxy)
        device.hwhash = hwhash
        device.checkin(mdmpfx)
        return

    def retire_intune(self, os, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(os, None, username, password, refresh_token, certpfx, proxy)
        device.retire_intune()
        return

    def check_compliant(self, os, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(os, None, username, password, refresh_token, certpfx, proxy)
        device.check_compliant()
        return

    def download_apps(self, device_name, mdmpfx, proxy):
        device = self.new_device('Windows', device_name, None, None, None, None, proxy)
        device.download_apps(mdmpfx)

def main():
    description = f"{banner}"
    parser = argparse.ArgumentParser(add_help=True, description=color(description, fore='deepskyblue'), formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-x', '--proxy', action='store', help='proxy to be used during authentication (format: http://proxyip:port)')
    subparsers = parser.add_subparsers(dest='command', description='pytune commands')
    
    entra_join_parser = subparsers.add_parser('entra_join', help='join device to Entra ID')
    entra_join_parser.add_argument('-u', '--username', action='store', help='username')
    entra_join_parser.add_argument('-p', '--password', action='store', help='password')
    entra_join_parser.add_argument('-a', '--access_token', action='store', help='access token for device registration service')
    entra_join_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    entra_join_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    entra_join_parser.add_argument('-D', '--deviceticket', required=False, action='store', help='device ticket')
    
    entra_delete_parser = subparsers.add_parser('entra_delete', help='delete device from Entra ID')
    entra_delete_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')

    enroll_intune_parser = subparsers.add_parser('enroll_intune', help='enroll device to Intune')
    enroll_intune_parser.add_argument('-u', '--username', action='store', help='username')
    enroll_intune_parser.add_argument('-p', '--password', action='store', help='password')
    enroll_intune_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    enroll_intune_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    enroll_intune_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    enroll_intune_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    checkin_parser = subparsers.add_parser('checkin', help='checkin to Intune')
    checkin_parser.add_argument('-u', '--username', action='store', help='username')
    checkin_parser.add_argument('-p', '--password', action='store', help='password')
    checkin_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    checkin_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    checkin_parser.add_argument('-m', '--mdmpfx', required=True, action='store', help='mdm pfx path')
    checkin_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    checkin_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    checkin_parser.add_argument('-H', '--hwhash', required=False, action='store', help='Autopilot hardware hash')

    retire_intune_parser = subparsers.add_parser('retire_intune', help='retire device from Intune')
    retire_intune_parser.add_argument('-u', '--username', action='store', help='username')
    retire_intune_parser.add_argument('-p', '--password', action='store', help='password')
    retire_intune_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    retire_intune_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    retire_intune_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    check_compliant_parser = subparsers.add_parser('check_compliant', help='check compliant status')
    check_compliant_parser.add_argument('-u', '--username', action='store', help='username')
    check_compliant_parser.add_argument('-p', '--password', action='store', help='password')
    check_compliant_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    check_compliant_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    check_compliant_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    download_apps_intune_parser = subparsers.add_parser('download_apps', help='download available win32apps and scripts (only Windows supported since I\'m lazy)')
    download_apps_intune_parser.add_argument('-m', '--mdmpfx', required=True, action='store', help='mdm pfx path')
    download_apps_intune_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')

    args = parser.parse_args()
    proxy=None
    if args.proxy:
        proxy={
            'https':args.proxy,
            'http':args.proxy
            }
        
    logger = Logger()
    pytune = Pytune(logger)

    if args.command == 'entra_join':
        pytune.entra_join(args.username, args.password, args.access_token, args.device_name, args.os, args.deviceticket, proxy)
    if args.command == 'entra_delete':
        pytune.entra_delete(args.certpfx, proxy)
    if args.command == 'enroll_intune':
        pytune.enroll_intune(args.os, args.device_name, args.username, args.password, args.refresh_token, args.certpfx, proxy)
    if args.command == 'checkin':
        pytune.checkin(args.os, args.device_name, args.username, args.password, args.refresh_token, args.certpfx, args.mdmpfx, args.hwhash, proxy)
    if args.command == 'retire_intune':
        pytune.retire_intune(args.os, args.username, args.password, args.refresh_token, args.certpfx, proxy)
    if args.command == 'check_compliant':
        pytune.check_compliant(args.os, args.username, args.password, args.refresh_token, args.certpfx, proxy)                
    if args.command == 'download_apps':
        pytune.download_apps(args.device_name, args.mdmpfx, proxy)        

if __name__ == "__main__":
    main()

