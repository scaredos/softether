# SoftEther Unofficial Client Library
__author__ = 'scaredos'  # Steven

__version__ = '0.0.1'
__maintainer__ = 'scaredos'
__email__ = 'scared@tuta.io'
__status__ = 'Production'

import json
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Using requests to disable InsecureRequestWarning
# SoftEther servers commonly have improper certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SoftEtherAPI:
    def __init__(self, ip: str, port: int, hubname: str, password: str):
        """
        Provide credentials for authentication with specified server

        :param ip: IP address of SoftEther server
        :param port: Port of SoftEther JSON-RPC API (default: 443)
        :param hubname: SoftEther username
        :param password: SoftEther password
        """
        self.ip = ip
        self.port = port
        self.hubname = hubname
        self.password = password
        self.session = requests.Session()
        self.url = f'https://{self.ip}:{self.port}/api'

    def _request_handler(self, json: dict):
        """
        Handle requests for functions

        :param json: JSON data to POST to SoftEther API
        :return: JSON response
        """
        response = self.session.post(self.url, json=json)

        if response.status_code == 200:
            return response.json()

        return False

    def authenticate(self):
        """
        Authenticate using provided credentials

        :return: A boolean indiciting whether or not it was successful
        """
        self.session.auth = (self.hubname, self.password)
        self.session.verify = False

        if self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "Test",
            "params": {
                "IntValue_u32": 0
            }
        }) != False:
            return True

        return False

    def get_server_info(self):
        """
        Get server information

        :return: Dict containing server information
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerInfo",
            "params": {}
        })

    def get_server_status(self):
        """
        Get current server status

        :return: Dict containing server statusinformation
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerStatus",
            "params": {}
        })

    def create_listener(self, port: int):
        """
        Create new TCP listener

        :param port: TCP listener port to manage
        :return: Dict containing information on new listener
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "CreateListener",
            "params": {
                "Port_u32": port,
                "Enable_bool": true
            }
        })

    def enum_listener(self):
        """
        Get list of TCP listeners

        :return: Dict containing list of listeners
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumListener",
            "params": {}
        })

    def delete_listener(self, port: int):
        """
        Delete TCP listener

        :param port: TCP listener port to manage
        :return: Dict containing listener status
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DeleteListener",
            "params": {
                "Port_u32": port
            }
        })

    def manage_listener(self, port: int, enabled: bool):
        """
        Enable/disable TCP listener

        :param port: TCP listener port to manage
        :param enabled: Status of TCP listener
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnableListener",
            "params": {
                "Port_u32": port,
                "Enable_bool": enabled
            }
        })

    def set_server_password(self, password: str):
        """
        Set VPN server administrator password

        :param password: Plaintext password for VPN server
        :return: Dict indicating new password
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetServerPassword",
            "params": {
                "PlainTextPassword_str": password
            }
        })

    def set_server_cert(self, certBin: str, keyBin: str):
        """
        Set SSL certificate and private key of VPN server

        :param certBin: SSL certificate
        :param keyBin: SSL private key
        :return: Dict indicating status of certificate
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetServerCert",
            "params": {
                "Cert_bin": certBin,
                "Key_bin": keyBin
            }
        })

    def get_server_cert(self):
        """
        Get SSL certificate and private key of VPN server

        :return: Dict indicating status of certificate
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerCert",
            "params": {}
        })

    def get_server_cipher(self):
        """
        Get encrypted algorithm used for VPN communication

        :return: Dict indicating encrypted algorithm
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerCipher",
            "params": {}
        })

    def set_server_cipher(self, cipher: str):
        """
        Set encryption algorithm for VPN communication

        :param cipher: Compatible SoftEther algorithm (AES128-SHA)
        :return: Dict indicating encrypted algorithm
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetServerCipher",
            "params": {
                "String_str": cipher
            }
        })

    def create_hub(self, hubname: str, adminpass: str, online: bool, maxsession: int, noenum: bool, hubtype: int):
        """
        Create new Virtual Hub

        :param hubname: Name of virtual hub
        :param adminpass: Administrator password of virtual hub
        :param online: Online flag
        :param maxsession: Maximum number of VPN sessions
        :param noenum: No Enum Flag
        :param hubtype: Type of virtual hub (0: standalone, 1: static, 2: dyanmic)
        :return: Information of hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "CreateHub",
            "params": {
                "HubName_str": hubname,
                "AdminPasswordPlainText_str": adminpass,
                "Online_bool": online,
                "MaxSession_u32": maxsession,
                "NoEnum_bool": noenum,
                "HubType_u32": hubtype
            }
        })

    def set_hub(self, hubname: str, adminpass: str, online: bool, maxsession: int, noenum: bool, hubtype: int):
        """
        Manage Virtual Hub

        :param hubname: Name of virtual hub
        :param adminpass: Administrator password of virtual hub
        :param online: Online flag
        :param maxsession: Maximum number of VPN sessions
        :param noenum: No Enum Flag
        :param hubtype: Type of virtual hub (0: standalone, 1: static, 2: dyanmic)
        :return: Information of hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetHub",
            "params": {
                "HubName_str": hubname,
                "AdminPasswordPlainText_str": adminpass,
                "Online_bool": online,
                "MaxSession_u32": maxsession,
                "NoEnum_bool": noenum,
                "HubType_u32": hubtype
            }
        })

    def get_hub(self, hubname: str):
        """
        Get hub information by name

        :param hubname: Name of virtual hub
        :return: Information of hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetHub",
            "params": {
                "HubName_str": hubname
            }
        })

    def enum_hub(self):
        """
        Get list of virtual hubs

        :return: List of virtual hubs
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumHub",
            "params": {}
        })

    def delete_hub(self, hubname: str):
        """
        Delete virtual hub

        :param hubname: Name of virtual hub
        :return: Dict of hub deleteds
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DeleteHub",
            "params": {
                "HubName_str": hubname
            }
        })

    def enum_connection(self):
        """
        Get list of TCP connections

        :return: Dict containg list of TCP connections
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumConnection",
            "params": {}
        })

    def disconnect_connection(self, connectName: str):
        """
        Disconnect TCP connection by name

        :param connectName: Connection name
        :return: TCP connection disconnected
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DisconnectConnection",
            "params": {
                "Name_str": connectName
            }
        })

    def get_connection_info(self, connectName: str):
        """
        Get TCP connection information by name

        :param connectName: Connection name
        :return: Connection information
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetConnectionInfo",
            "params": {
                "Name_str": connectName
            }
        })

    def set_hub_online(self, hubname: str, online: bool = True):
        """
        Switch Virtual Hub online/offline

        :param hubname: Name of virtual hub
        :param online: Online flag (default: True)
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetHubOnline",
            "params": {
                "HubName_str": hubname,
                "Online_bool": online
            }
        })

    def get_hub_status(self, hubname: str):
        """
        Get hub status

        :param hubname: Name of virtual hub
        :return: Status of hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetHubStatus",
            "params": {
                "HubName_str": hubname
            }
        })

    def get_hub_log(self, hubname: str):
        """
        Get hub logs

        :param hubname: Name of virtual hub
        :return: Logs of hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetHubLog",
            "params": {
                "HubName_str": hubname
            }
        })

    def addCa(self, hubname: str, certBin: str):
        """
        Add trusted CA certificate to Hub

        :param hubname: Name of virtual hub
        :param certBin: CA Certificate as string
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "AddCa",
            "params": {
                "HubName_str": hubname,
                "Cert_bin": certbin
            }
        })

    def enum_ca(self, hubname: str):
        """
        Get list of trusted CA certificates

        :param hubname: Name of virtual hub
        :return: List of trusted CA certificates of hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumCa",
            "params": {
                "HubName_str": hubname
            }
        })

    def create_user(self, hubname: str, name: str, realname: str, note: str, expiretime: str, authpassword: str):
        """
        Create User

        :param hubname: Name of hub to create user within
        :param name: User name
        :param realname: Use real name
        :param note: User note
        :param expiretime: Time that user expires (FORMAT: 2020-08-01T12:24:36.123)
        :param authpassword: Password for user
        :return: User information
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "CreateUser",
            "params": {
                "HubName_str": hubname,
                "Name_str": name,
                "Realname_utf": realname,
                "Note_utf": note,
                "ExpireTime_dt": expiretime,
                "AuthType_u32": 1,
                "Auth_Password_str": authpassword,
            }
        })

    def set_user(self, hubname: str, name: str, realname: str, note: str, expiretime: str, authpassword: str):
        """
        Change user settings

        :param hubname: Name of hub to update user within
        :param name: User name
        :param realname: Use real name
        :param note: User note
        :param expiretime: Time that user expires (FORMAT: 2020-08-01T12:24:36.123)
        :param authpassword: Password for user
        :return: User information
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetUser",
            "params": {
                "HubName_str": hubname,
                "Name_str": name,
                "Realname_utf": realname,
                "Note_utf": note,
                "ExpireTime_dt": expiretime,
                "AuthType_u32": 1,
                "Auth_Password_str": authpassword,
            }
        })

    def get_user(self, hubname: str, name: str):
        """
        Change user settings

        :param hubname: Name of hub to get user within
        :param name: User name
        :return: User information
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetUser",
            "params": {
                "HubName_str": hubname,
                "Name_str": name
            }
        })

    def delete_user(self, hubname: str, name: str):
        """
        Delete User

        :param hubname: Name of hub to delete user within
        :param name: User name
        :return: User information
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DeleteUser",
            "params": {
                "HubName_str": hubname,
                "Name_str": name
            }
        })

    def enum_user(self, hubname: str):
        """
        Get list of users

        :param hubname: Name of virtual hub
        :return: Dict with list of users
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumUser",
            "params": {
                "HubName_str": hubname
            }
        })

    # TODO:
    # Add group management functions
    #     - SetGroup
    #     - DeleteGroup
    #     - CreateGroup
    #     - GetGroup
    #     - EnumGroup

    def enumSession(self, hubname: str):
        """
        Get list of VPN sessions

        :param hubname: Name of virtual hub
        :return: List of VPN sessions
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumSession",
            "params": {
                "HubName_str": hubname
            }
        })

    def getSessionStatus(self, hubname: str, name: str):
        """
        Get status of session

        :param hubname: Name of virtual hub
        :param name: Name of session
        :return: Status of session
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetSessionStatus",
            "params": {
                "HubName_str": hubname,
                "Name_str": name
            }
        })

    def delete_session(self, hubname: str, name: str):
        """
        Delete session

        :param hubname: Name of virtual hub
        :param name: Name of session
        :return: Status of session
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DeleteSession",
            "params": {
                "HubName_str": hubname,
                "Name_str": name
            }
        })

    # TODO:
    # Add MAC and iptable functions
    #   - EnumIpTable
    #   - DeleteIpTable
    #   - EnumMacTable
    #   - DeleteMacTable

    def enable_secure_nat(self, hubname: str):
        """
        Enable SecureNAT (Virtual NAT and DHCP Server)

        :param hubname: Name of virtual hub
        :return: Virtual hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnableSecureNAT",
            "params": {
                "HubName_str": hubname
            }
        })

    def disable_secure_nat(self, hubname: str):
        """
        Disable SecureNAT (Virtual NAT and DHCP Server)

        :param hubname: Name of virtual hub
        :return: Virtual hub
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DisableSecureNAT",
            "params": {
                "HubName_str": hubname
            }
        })

    def reboot_server(self):
        """
        Reboot server

        :return: Server status
        """
        return self._request_handler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "RebootServer",
            "params": {}
        })


# TODO:
# Add all other functions that are non-essential to most users
