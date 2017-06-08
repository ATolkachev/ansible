#!/usr/bin/python
# encoding: utf-8

import subprocess
from ansible.module_utils.basic import *
from netaddr import IPNetwork

def get_priv_interface_info_for_ip(ip):
    network_config = subprocess.Popen(["/usr/sbin/ip", "-o", "addr", "show"], stdout=subprocess.PIPE)
    result = network_config.stdout.read()
    interface = ""
    network = ''
    ip_addr = ip
    for str in result.split("\n"):
        if 'inet ' in str:
            if ip in str:
                interface = str[3:str.find(" ", 3)]
                network = IPNetwork(str[str.find("net", 3) + 4:str.find("/", 3) + 3]).cidr

    return interface, ip_addr, network

def get_pub_interface_info_for_ip(ip):
    network_config = subprocess.Popen(["/usr/sbin/ip", "-o", "addr", "show"], stdout=subprocess.PIPE)
    result = network_config.stdout.read()
    interface = ''
    network = ''
    ip_addr = ''
    for str in result.split("\n"):
        if 'inet ' in str:
            if ip not in str and '127.0.0.1' not in str:
                print str
                interface = str[3:str.find(" ", 3)]
                network = IPNetwork(str[str.find("net", 3) + 4:str.find("/", 3) + 3]).cidr
                ip_addr = str[str.find("net", 3) + 4:str.find("/", 3)]

    return interface, ip_addr, network

def main(argv=None):
    if argv is None:
        argv = sys.argv

    fields = {"ip": {"required": True, "type": "str"}}
    module = AnsibleModule(argument_spec=fields)
    my_ip = module.params['ip']
    ifname_priv, ip_priv, network_priv = get_priv_interface_info_for_ip(my_ip)
    ifname_pub, ip_pub, network_pub = get_pub_interface_info_for_ip(my_ip)


    module.exit_json(changed=True, ifname_priv=ifname_priv, ip_priv=my_ip, network_priv=str(network_priv), ifname_pub=ifname_pub, ip_pub=ip_pub, network_pub=str(network_pub))


if __name__ == '__main__':
    main()
