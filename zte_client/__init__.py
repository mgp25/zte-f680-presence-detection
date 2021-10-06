import re
import requests
import logging
import hashlib
from random import random
from collections import namedtuple

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(filename='debug.log', level=logging.DEBUG)

Device = namedtuple('Device', ['host_name', 'ip_address', 'ipv6_address', 'mac_address'])
get_text = lambda element: element.text

class ZteClient():

    def __init__(self, password, host='192.168.1.1', user='1234'):
        self.host = host
        self.user = user
        self.password = password
        self.baseUrl = 'http://{}/'.format(host)
        self.cookie_jar = requests.cookies.RequestsCookieJar()
        self.cookie_jar.set('_TESTCOOKIESUPPORT', '1')

    def __getValue(self, ck, source, init=False):
        if init:
            matches = re.search(ck, source)
            return matches.groups()[0]
        else:
            matches = re.findall(ck, source)
            matches = [i.encode().decode('unicode-escape') for i in matches]
            return matches

    def login(self):
        try:
            login_token, login_check_token = self.__get_login_token()
            self.login_cookies = self.__post_login_and_get_cookies(login_token, login_check_token)

        except requests.exceptions.RequestException:
            err_msg = 'Failed to perform login'
            _LOGGER.exception(err_msg)
            raise Exception(err_msg)

    def __get_login_token(self):
        r1 = r' createHiddenInput\("Frm_Logintoken", "(\d+)"\)'
        r2 = r' createHiddenInput\("Frm_Loginchecktoken", "(\d+)"\)'
        response = requests.get(self.baseUrl, timeout=30, verify=False, cookies=self.cookie_jar).text
        login_token = self.__getValue(r1, response, True)
        login_check_token = self.__getValue(r2, response, True)
        _LOGGER.debug('Got login token: {0} and login check token: {1}'.format(login_token, login_check_token))
        return login_token, login_check_token

    def __post_login_and_get_cookies(self, login_token, login_check_token):
        pwd_random = str(round(random()*89999999)+10000000)
        encodedPassword = hashlib.sha256((self.password + pwd_random).encode('utf-8')).hexdigest()
        data = {
            'action': 'login', 
            'Username': self.user,
            'Password': encodedPassword,
            'Frm_Logintoken': login_token,
            'UserRandomNum': pwd_random,
            'Frm_Loginchecktoken': login_check_token,
            'port': ''
        }
        response = requests.post(self.baseUrl, timeout=30, verify=False, data=data, cookies=self.cookie_jar, allow_redirects=False)
        cookies = response.cookies
        self.cookie_jar.update(cookies)
        _LOGGER.debug('Got login cookie: {}'.format(cookies.items()))
        requests.get(self.baseUrl, timeout=30, verify=False, cookies=cookies)
        return cookies

    def get_connected_devices(self):
        try:
            devices = self.__get_connected_devices()
            return devices
        except requests.exceptions.RequestException:
            _LOGGER.exception('Failed to get devices devices')

    def __get_connected_devices(self):

        ad_mac_addresses = []
        ad_ipv4_addresses = []
        ad_hostnames = []

        r1 = r'Transfer_meaning\(\'MACAddr\d+\',\'(.*)\'\)'
        r2 = r'Transfer_meaning\(\'IPAddr\d+\',\'(.*)\'\)'
        r3 = r'Transfer_meaning\(\'HostName\d+\',\'(.*)\'\)'
        device_list_url = self.baseUrl + 'getpage.gch'
        params = {
            'pid': '1002', 
            'nextpage': 'net_dhcp_dynamic_t.gch'
        }
        response = requests.get(device_list_url, timeout=30, verify=False, cookies=self.cookie_jar, params=params).text
        mac_addresses = self.__getValue(r1, response)
        ipv4_addresses = self.__getValue(r2, response)
        hostnames = self.__getValue(r3, response)

        r1 = r'Transfer_meaning\(\'ADMACAddress\d+\',\'(.*)\'\)'
        r2 = r'Transfer_meaning\(\'ADIPAddress\d+\',\'(.*)\'\)'
        device_list_url = self.baseUrl + 'getpage.gch'
        params = {
            'pid': '1002', 
            'nextpage': 'net_wlanm_assoc1_t.gch'
        }
        response = requests.get(device_list_url, timeout=30, verify=False, cookies=self.cookie_jar, params=params).text

        ad_mac_addresses.extend(self.__getValue(r1, response))
        ad_ipv4_addresses.extend(self.__getValue(r2, response))
        
        device_list_url = self.baseUrl + 'getpage.gch'
        params = {
            'pid': '1002', 
            'nextpage': 'net_wlanm_assoc2_t.gch'
        }
        response = requests.get(device_list_url, timeout=30, verify=False, cookies=self.cookie_jar, params=params).text

        ad_mac_addresses.extend(self.__getValue(r1, response))
        ad_ipv4_addresses.extend(self.__getValue(r2, response))
        ipv6_addresses = [''] * len(ad_ipv4_addresses)


        for idx, mac in enumerate(mac_addresses):
            if mac in ad_mac_addresses:
                ad_hostnames.append(hostnames[idx])

        devices = list(map(self.__instance_to_device, ad_mac_addresses, ad_ipv4_addresses, ipv6_addresses, ad_hostnames))
        _LOGGER.debug('Found {} devices'.format(len(devices)))
        return devices

    def __instance_to_device(self, mac_addresses, ipv4_addresses, ipv6_addresses, hostnames):
        return Device(hostnames, ipv4_addresses, ipv6_addresses, mac_addresses)