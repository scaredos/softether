# SoftEther Unofficial Client Library
__author__ = 'scaredos'

__version__ = '0.0.1'
__maintainer__ = 'scaredos'
__email__ = 'scared@tuta.io'
__status__ = 'Production'

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

"""
To disable InsecureRequestWarning:

    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
"""


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

    def requestHandler(self, json: dict):
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

        if self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "Test",
            "params": {
                "IntValue_u32": 0
            }
        }) != False:
            return True

        return False

    def getServerInfo(self):
        """
        Get server information

        :return: Dict containing server information
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerInfo",
            "params": {}
        })

    def getServerStatus(self):
        """
        Get current server status

        :return: Dict containing server statusinformation
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerStatus",
            "params": {}
        })

    def createListener(self, port: int):
        """
        Create new TCP listener

        :param port: TCP listener port to manage
        :return: Dict containing information on new listener
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "CreateListener",
            "params": {
                "Port_u32": port,
                "Enable_bool": true
            }
        })

    def enumListener(self):
        """
        Get list of TCP listeners

        :return: Dict containing list of listeners
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumListener",
            "params": {}
        })

    def deleteListener(self, port: int):
        """
        Delete TCP listener

        :param port: TCP listener port to manage
        :return: Dict containing listener status
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DeleteListener",
            "params": {
                "Port_u32": port
            }
        })

    def manageListener(self, port: int, enabled: bool):
        """
        Enable/disable TCP listener

        :param port: TCP listener port to manage
        :param enabled: Status of TCP listener
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnableListener",
            "params": {
                "Port_u32": port,
                "Enable_bool": enabled
            }
        })

    def setServerPassword(self, password: str):
        """
        Set VPN server administrator password

        :param password: Plaintext password for VPN server
        :return: Dict indicating new password
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetServerPassword",
            "params": {
                "PlainTextPassword_str": password
            }
        })

    def setServerCert(self, certBin: str, keyBin: str):
        """
        Set SSL certificate and private key of VPN server

        :param certBin: SSL certificate
        :param keyBin: SSL private key
        :return: Dict indicating status of certificate
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetServerCert",
            "params": {
                "Cert_bin": certBin,
                "Key_bin": keyBin
            }
        })

    def getServerCert(self):
        """
        Get SSL certificate and private key of VPN server

        :return: Dict indicating status of certificate
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerCert",
            "params": {}
        })

    def getServerCipher(self):
        """
        Get encrypted algorithm used for VPN communication

        :return: Dict indicating encrypted algorithm
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetServerCipher",
            "params": {}
        })

    def setServerCipher(self, cipher: str):
        """
        Set encryption algorithm for VPN communication

        :param cipher: Compatible SoftEther algorithm (AES128-SHA)
        :return: Dict indicating encrypted algorithm
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetServerCipher",
            "params": {
                "String_str": cipher
            }
        })

    def createHub(self, hubname: str, adminpass: str, online: bool, maxsession: int, noenum: bool, hubtype: int):
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
        return self.requestHandler(json={
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

    def setHub(self, hubname: str, adminpass: str, online: bool, maxsession: int, noenum: bool, hubtype: int):
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
        return self.requestHandler(json={
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

    def getHub(self, hubname: str):
        """
        Get hub information by name

        :param hubname: Name of virtual hub
        :return: Information of hub
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetHub",
            "params": {
                "HubName_str": hubname
            }
        })

    def enumHub(self):
        """
        Get list of virtual hubs

        :return: List of virtual hubs
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumHub",
            "params": {}
        })

    def deleteHub(self, hubname: str):
        """
        Delete virtual hub

        :param hubname: Name of virtual hub
        :return: Dict of hub deleteds
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DeleteHub",
            "params": {
                "HubName_str": hubname
            }
        })

    def enumConnection(self):
        """
        Get list of TCP connections

        :return: Dict containg list of TCP connections
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumConnection",
            "params": {}
        })

    def disconnectConnection(self, connectName: str):
        """
        Disconnect TCP connection by name

        :param connectName: Connection name
        :return: TCP connection disconnected
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "DisconnectConnection",
            "params": {
                "Name_str": connectName
            }
        })

    def getConnectionInfo(self, connectName: str):
        """
        Get TCP connection information by name

        :param connectName: Connection name
        :return: Connection information
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetConnectionInfo",
            "params": {
                "Name_str": connectName
            }
        })

    def setHubOnline(self, hubname: str, online: bool = True):
        """
        Switch Virtual Hub online/offline

        :param hubname: Name of virtual hub
        :param online: Online flag (default: True)
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetHubOnline",
            "params": {
                "HubName_str": hubname,
                "Online_bool": online
            }
        })

    def getHubStatus(self, hubname: str):
        """
        Get hub status

        :param hubname: Name of virtual hub
        :return: Status of hub
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "GetHubStatus",
            "params": {
                "HubName_str": hubname
            }
        })

    def getHubLog(self, hubname: str):
        """
        Get hub logs

        :param hubname: Name of virtual hub
        :return: Logs of hub
        """
        return self.requestHandler(json={
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
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "AddCa",
            "params": {
                "HubName_str": hubname,
                "Cert_bin": certbin
            }
        })

    def enumCa(self, hubname: str):
        """
        Get list of trusted CA certificates

        :param hubname: Name of virtual hub
        :return: List of trusted CA certificates of hub
        """
        return self.requestHandler(json={
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "EnumCa",
            "params": {
                "HubName_str": hubname
            }
        })
