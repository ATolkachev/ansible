#!/usr/bin/python
# encoding: utf-8

import subprocess
from ansible.module_utils.basic import *

def get_cidr(ipaddr):
    addr = ipaddr[0:ipaddr.find("/")].split(".")
    mask = int(ipaddr[ipaddr.find("/") + 1:])

    wildcard = 32 - mask
    bin_addr = (int(addr[0]) << 24) + (int(addr[1]) << 16) + (int(addr[2]) << 8) + int(addr[3])
    cidr_bin = bin_addr - (bin_addr % (2 ** wildcard))
    cidr = '.'.join([str(cidr_bin >> (i << 3) & 0xFF) for i in range(4)[::-1]])

    return "{0}/{1}".format(cidr, mask)

def get_priv_interface_info_for_ip(ip, network_config):
    interface = ""
    network = ''
    ip_addr = ip
    for str in network_config.split("\n"):
        if 'inet ' in str:
            if ip in str:
                interface = str[3:str.find(" ", 3)]
                network = get_cidr(str[str.find("net", 3) + 4:str.find("/", 3) + 3])

    return interface, ip_addr, network

def get_pub_interface_info_for_ip(ip, network_config):
    interface = ''
    network = ''
    ip_addr = ''
    for str in network_config.split("\n"):
        if 'inet ' in str:
            if ip not in str and '127.0.0.1' not in str:
                interface = str[3:str.find(" ", 3)]
                network = get_cidr(str[str.find("net", 3) + 4:str.find("/", 3) + 3])
                ip_addr = str[str.find("net", 3) + 4:str.find("/", 3)]

    return interface, ip_addr, network

def main(argv=None):
    if argv is None:
        argv = sys.argv

    fields = {"ip": {"required": True, "type": "str"}}
    module = AnsibleModule(argument_spec=fields)
    my_ip = module.params['ip']
    network_config = subprocess.Popen(["/usr/sbin/ip", "-o", "addr", "show"], stdout=subprocess.PIPE)
    result = network_config.stdout.read()
    ifname_priv, ip_priv, network_priv = get_priv_interface_info_for_ip(my_ip, result)
    ifname_pub, ip_pub, network_pub = get_pub_interface_info_for_ip(my_ip, result)


    module.exit_json(changed=True, ifname_priv=ifname_priv, ip_priv=my_ip, network_priv=str(network_priv), ifname_pub=ifname_pub, ip_pub=ip_pub, network_pub=str(network_pub))


if __name__ == '__main__':
    main()
