from json import load, loads, dump
import os
import re
import shlex
import subprocess
import time
import httplib
import base64
import ConfigParser
import logging
import sys
from novaclient.client import Client
from tempest import config

CONF = config.CONF

# infoblox config file
NEUTRON_CONF = "/etc/neutron/neutron.conf"

parser = ConfigParser.SafeConfigParser()
parser.read(NEUTRON_CONF)
CONDITIONAL_CONF = parser.get('DEFAULT', 'conditional_config')
MEMBERS_CONF = parser.get('DEFAULT', 'infoblox_members_config')
mat = re.search("https://(.*)/wapi/.*", parser.get('DEFAULT', 'infoblox_wapi'))
GRID_VIP = mat.group(1)
USERNAME = parser.get('DEFAULT', 'infoblox_username')
PASSWORD = parser.get('DEFAULT', 'infoblox_password')

log_level = logging.INFO
if "DEBUG" in os.environ and os.environ['DEBUG'] == "1":
    log_level = logging.DEBUG
logging.basicConfig(
    level=log_level,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


def segmentation_range():
    rangearr = ""
    plugin = "/etc/neutron/plugin.ini"
    parser.read(plugin)
    if(parser.get("ml2", "tenant_network_types") == "vxlan"):
        rangearr = parser.get('ml2_type_vxlan', 'vni_ranges')
        array = rangearr.split(':')
        return range(int(array[0]), int(array[1]))
    elif(parser.get("ml2", "tenant_network_types") == "gre"):
        rangearr = parser.get('ml2_type_gre', 'tunnel_id_ranges')
        array = rangearr.split(':')
        return range(int(array[0]), int(array[1]))
    else:
        rangearr = parser.get('ml2_type_vlan', 'network_vlan_ranges')
        array = rangearr.split(':')
        return range(int(array[1]), int(array[2]))

def get_admin_user_id():
    cmd = "keystone --os-username " + CONF.identity.admin_username + " --os-password " + CONF.identity.admin_password + \
        " --os-tenant-name " + CONF.identity.admin_tenant_name + " --os-auth-url " + CONF.identity.uri \
        + " user-list"
    args = shlex.split(cmd.encode('utf-8'))
    p1 = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    cmd = "grep admin"
    args = shlex.split(cmd.encode('utf-8'))
    p2 = subprocess.Popen(
        args,
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    cmd = "awk '{print $2}'"
    args = shlex.split(cmd.encode('utf-8'))
    p3 = subprocess.Popen(
        args,
        stdin=p2.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    output, error = p3.communicate()
    logger.info("admin user %s", output)
    return output.strip()

def get_neutron_user_id():
    cmd = "keystone --os-username " + CONF.identity.admin_username + " --os-password " + CONF.identity.admin_password + \
        " --os-tenant-name " + CONF.identity.admin_tenant_name + " --os-auth-url " + CONF.identity.uri \
        + " user-list"
    args = shlex.split(cmd.encode('utf-8'))
    p1 = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    cmd = "grep neutron"
    args = shlex.split(cmd.encode('utf-8'))
    p2 = subprocess.Popen(
        args,
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    cmd = "awk '{print $2}'"
    args = shlex.split(cmd.encode('utf-8'))
    p3 = subprocess.Popen(
        args,
        stdin=p2.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    output, error = p3.communicate()
    logger.info("neutron user %s", output)
    return output.strip()


def a_record_setup(action=None):
    parser = ConfigParser.SafeConfigParser()

    if action:
        parser.read(NEUTRON_CONF)
        parser.set('DEFAULT', 'use_host_records_for_ip_allocation', 'False')
        parser.write(open(NEUTRON_CONF, 'w'))
    else:
        parser.read(NEUTRON_CONF)
        parser.set('DEFAULT', 'use_host_records_for_ip_allocation', 'True')
        parser.write(open(NEUTRON_CONF, 'w'))


def set_configopt(config_dict):
    data = load(open(CONDITIONAL_CONF))
    data = config_dict[0:]
    dump(data, open(CONDITIONAL_CONF, 'w'))

def get_members():
    json_data = open(MEMBERS_CONF)
    data = load(json_data)
    json_data.close()
    member_list = []
    for i in data:
        member_list.append(i['name'])
    return member_list

def service_restart():
    """
    Restarts Neutron Server Service
    """
    cmd = "service neutron-server restart"
    args = shlex.split(cmd.encode('utf-8'))
    p = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    output, error = p.communicate()
    if p.returncode == 0:
        logger.info("Service Restarted Successfully")
    else:
        logger.error("Failed to Restart Service")


class InfobloxNIOStest():

    def __init__(self, cred):

        nova_credentials = {}

        nova_credentials['username'] = cred.username
        nova_credentials['auth_url'] = CONF.identity.uri
        nova_credentials['api_key'] = cred.password
        nova_credentials['version'] = '2'
        nova_credentials['project_id'] = cred.tenant_name

        self.nova_client = Client(**nova_credentials)

    def wapi_get_request(self, object_type, args):
        auth = base64.encodestring("%s:%s" % (USERNAME, PASSWORD))
        auth_header = {}
        auth_header['content-type'] = "application/json"
        auth_header['Authorization'] = "Basic %s" % (auth)
        conn = httplib.HTTPSConnection(GRID_VIP)
        req = "/wapi/v1.4.1/" + object_type + "?" + args
        conn.request("GET", req, headers=auth_header)
        response = conn.getresponse()
        return response.status, response.read()

    def get_fqdn_from_domain_suffix_pattern(
            self,
            network,
            subnet,
            external=None):
        '''
        Gets Zone name from domain_suffix_pattern in conditional.conf
        '''

        json_data = open(CONDITIONAL_CONF)
        data = load(json_data)
        json_data.close()
        domainsuffixpat = data[0]['domain_suffix_pattern']
        if external:
            domainsuffixpat = data[1]['domain_suffix_pattern']
        if re.search("{subnet_id}", domainsuffixpat):
            domainsuffixpat = re.sub(
                "{subnet_id}",
                subnet['id'],
                domainsuffixpat)
        if re.search("{subnet_name}", domainsuffixpat):
            domainsuffixpat = re.sub(
                "{subnet_name}",
                subnet['name'],
                domainsuffixpat)
        if re.search("{network_name}", domainsuffixpat):
            domainsuffixpat = re.sub(
                "{network_name}",
                network['name'],
                domainsuffixpat)
        if re.search("{network_id}", domainsuffixpat):
            domainsuffixpat = re.sub(
                "{network_id}",
                network['id'],
                domainsuffixpat)
        if re.search("{tenant_id}", domainsuffixpat):
            domainsuffixpat = re.sub(
                "{tenant_id}",
                network['tenant_id'],
                domainsuffixpat)

        return domainsuffixpat

    def get_host_from_hostname_pattern(self, instanceobj, network, subnet):
        '''
        Gets Host name from hostname_pattern in conditional.conf
        '''

        json_data = open(CONDITIONAL_CONF)
        data = load(json_data)
        json_data.close()
        fqdn = self.get_fqdn_from_domain_suffix_pattern(network, subnet)
        hostpat = data[0]['hostname_pattern']
        ipadd = instanceobj.addresses[network['name']][0]['addr']
        ipsplit = ipadd.split(".")
        ipadd = ipadd.replace(".", "-")

        if re.search("{tenant_id}", hostpat):
            hostpat = re.sub("{tenant_id}", network['tenant_id'], hostpat)

        if re.search("{subnet_id}", hostpat):
            hostpat = re.sub("{subnet_id}", subnet['id'], hostpat)

        if re.search("{subnet_name}", hostpat):
            hostpat = re.sub("{subnet_name}", subnet['name'], hostpat)

        if re.search("{network_name}", hostpat):
            hostpat = re.sub("{network_name}", network['name'], hostpat)

        if re.search("{network_id}", hostpat):
            hostpat = re.sub("{network_id}", network['id'], hostpat)

        if re.search("{ip_address}", hostpat):
            hostpat = re.sub("{ip_address}", ipadd, hostpat)

        if re.search("{ip_address_octet1}", hostpat):
            hostpat = re.sub("{ip_address_octet1}", ipsplit[0], hostpat)

        if re.search("{ip_address_octet2}", hostpat):
            hostpat = re.sub("{ip_address_octet2}", ipsplit[1], hostpat)

        if re.search("{ip_address_octet3}", hostpat):
            hostpat = re.sub("{ip_address_octet3}", ipsplit[2], hostpat)

        if re.search("{ip_address_octet4\}", hostpat):
            hostpat = re.sub("{ip_address_octet4}", ipsplit[3], hostpat)

        return hostpat + "." + fqdn

    def get_dns_view_name(self):

        json_data = open(CONDITIONAL_CONF)
        data = load(json_data)
        json_data.close()
        dns_view = ''
        if data[0]['dns_view']:
            dns_view = data[0]['dns_view']
        else:
            if data[0]['network_name'] == "default":
                dns_view = "default"
            else:
                dns_view = "default." + data[0]['network_name']
        return dns_view

    def search_console_log(self, server):
        """
        Searches the given Regular Expression in the Console Log of an Instance

        It takes Instance Name and Regular Expression as arguemnts.
        """
        regex = "Lease of .* obtained"
        name = server.name
        if server:
            logger.debug("Retrieving Console Log from the instance '%s'", name)
            console_log = server.get_console_output()
            logger.debug("Console Log :- \n '%s'", console_log)
            matches = re.search(regex, console_log)
            return matches
        else:
            logger.error("Instance '%s' does not exist", name)
            return None

    def launch_instance(self, name, image, flavor, nic_d):
        """
        Return Server Object if the instance is launched successfully
        It takes Instance Name and the Network Name it should be associated
        with as arguments.
        """

        instance = self.nova_client.servers.create(name=name, image=image,
                                                   flavor=flavor, nics=nic_d)
        logger.info("Launched Instance '%s', waiting for it to boot", name)
        time.sleep(180)
        # while instance.status != 'Active':
        # time.sleep(5)
        return instance

    def terminate_instance(self, server):
        """
        Terminates an instance

        It takes Instance Name as argument.
        """
        if server:
            self.nova_client.servers.delete(server)
            time.sleep(60)
            logger.info("Terminated Instance '%s'", server.name)
        else:
            logger.error("Instance '%s' does not exist", server.name)

    def associate_floating_ip_to_server(self, floating_ip_id, port_id):
        """Associate the provided floating IP to a specific server."""
        cmd = "neutron floatingip-associate --os-username " + CONF.identity.admin_username + " --os-password " + CONF.identity.admin_password + \
            " --os-tenant-name " + CONF.identity.admin_tenant_name + " --os-auth-url " + CONF.identity.uri + " " + floating_ip_id + \
            " " + port_id
        logger.info(cmd)
        args = shlex.split(cmd.encode('utf-8'))
        p = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        output, error = p.communicate()
        if p.returncode == 0:
            time.sleep(150)
            logger.info("Associated Ip to Host Successfully")

    def disassociate_floating_ip_from_server(self, floating_ip_id):
        """Disassociate the provided floating IP from a specific server."""
        cmd = "neutron floatingip-associate --os-username " + CONF.identity.admin_username + " --os-password " + CONF.identity.admin_password + \
            " --os-tenant-name " + CONF.identity.admin_tenant_name + " --os-auth-url " + CONF.identity.uri + " " \
            + floating_ip_id
        args = shlex.split(cmd.encode('utf-8'))
        p = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        output, error = p.communicate()
        if p.returncode == 0:
            time.sleep(100)
            logger.info("Disassociated Ip from Host Successfully")

    def ping_ip_address(self, ip_address):
        cmd = "ping -c5 -w5 %s" % (ip_address)
        logger.info(cmd)
        args = shlex.split(cmd.encode('utf-8'))
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        proc.wait()
        output, error = proc.communicate()
        success = proc.returncode == 0
        return success
