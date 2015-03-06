import netaddr
import testtools
from json import loads
import ConfigParser
import re
import shlex
import subprocess
import time
import os
from tempest.thirdparty.infoblox.scenarios import base as ibbase
from tempest.api.network import base
from tempest import clients
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest import test

CONF = config.CONF

member = []
member = ibbase.get_members()

Neutron_user_id = ibbase.get_neutron_user_id()
Segment_range = ibbase.segmentation_range()


class Condition_subnet_range_InfobloxScenario12(base.BaseNetworkTest):

    _baseconfig = [
        {
            "require_dhcp_relay": True,
            "network_view": "tempest",
            "domain_suffix_pattern": "{tenant_id}.cloud.global.com",
            "hostname_pattern": "host-{network_name}-{subnet_name}",
            "condition" : "subnet_range:25.0.0.0/24",
            "dhcp_members": "<next-available-member>",
            "is_external": False
        },
        {
            "require_dhcp_relay": True,
            "network_view": "naggappan_tempest",
            "domain_suffix_pattern": "{subnet_name}.cloud.ext.com",
            "hostname_pattern": "host-{network_name}-{subnet_name}",
            "dhcp_members": "<next-available-member>",
            "condition": "tenant",
            "is_external": True
        }
    ]

    _arecord = 0

    _external = False
    _snet_range_creation = False

    @classmethod
    #@test.safe_setup
    def setUpClass(self):

        if(self._arecord):
            ibbase.a_record_setup(self._arecord)

        ibbase.set_configopt(self._baseconfig)
        ibbase.service_restart()
        time.sleep(30)

        super(Condition_subnet_range_InfobloxScenario12, self).setUpClass()

        self.ib = ibbase.InfobloxNIOStest(
            self.isolated_creds.get_credentials('primary'))

        self.network_type = ibbase.parser.get("ml2", "tenant_network_types")
        # create network
        network_name = data_utils.rand_name('test-network')
        resp, body = self.client.create_network(name=network_name)
        self.network = body['network']

        # create subnet
        try:
            subnet_name = data_utils.rand_name('test-subnet')
            cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
            mask_bits = CONF.network.tenant_network_mask_bits
            resp, body = self.client.create_subnet(
                name=subnet_name,
                network_id=self.network['id'],
                cidr=str(cidr),
                ip_version=4
            )
            self.subnet = body['subnet']
        except:
           self._snet_range_creation = True
           subnet_name = data_utils.rand_name('test-subnet')
           #cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
           #mask_bits = CONF.network.tenant_network_mask_bits
           cidr = "25.0.0.0/24"
           resp, body = self.client.create_subnet(
               name=subnet_name,
               network_id=self.network['id'],
               cidr=str(cidr),
               ip_version=4
           )
           self.subnet = body['subnet']
# create server
        server_name = data_utils.rand_name('test-server')
        flavor = CONF.compute.flavor_ref
        image_id = CONF.compute.image_ref
        kwargs = {'net-id': self.network['id']},
        self.instance = self.ib.launch_instance(
            server_name,
            image_id,
            flavor,
            kwargs)
        self.host_name = self.ib.get_host_from_hostname_pattern(
            self.instance,
            self.network,
            self.subnet)
        self.internal_dhcp_ip = self.client.list_ports(device_owner="network:dhcp", network_id=self.network['id'])[1]['ports'][0]['fixed_ips'][0]['ip_address']

    @test.attr(type='smoke')
    def test_condition_with_snet_range(self):
        if self._snet_range_creation:
            self.assertEqual(1,1)
        else:
            self.fail(" subnet CIDR %s got created and it is not in specified range in condition config" % (str(cidr)))

    @test.attr(type='smoke')
    def test_Zone_added_to_NIOS(self):
        fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(
            self.network,
            self.subnet)
        args = "fqdn=%s" % (fqdn)
        code, msg = self.ib.wapi_get_request("zone_auth", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(loads(msg)[0]['fqdn'], fqdn)
        else:
            self.fail("Zone %s is not added to NIOS" % fqdn)

    @test.attr(type='smoke')
    def test_Rev_Zone_added_to_NIOS(self):
        args = "fqdn=%s" % (self.subnet['cidr'])
        code, msg = self.ib.wapi_get_request("zone_auth", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(loads(msg)[0]['fqdn'], self.subnet['cidr'])
        else:
            self.fail(
                "Reverse Zone %s is not added to NIOS" %
                self.subnet['cidr'])

    @test.attr(type='smoke')
    def test_Host_record_added_to_NIOS(self):
        args = "name=%s" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(loads(msg)[0]['name'], self.host_name)
        else:
            self.fail("Host %s is not added to NIOS" % self.host_name)

    @test.attr(type='smoke')
    def test_Network_added_to_NIOS(self):
        args = "network=%s" % (self.subnet['cidr'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(loads(msg)[0]['network'], self.subnet['cidr'])
        else:
            self.fail("Network %s is not added to NIOS" % self.subnet['cidr'])

    @test.attr(type='smoke')
    def test_DHCP_Lease_from_NIOS_for_instance(self):
        match_obj_for_lease_msg = self.ib.search_console_log(self.instance)
        self.assertNotEqual(match_obj_for_lease_msg, None)

# EA Test For Instance Object

    @test.attr(type='smoke')
    def test_EA_VM_ID(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['VM ID']['value'],
                self.instance.id)
        else:
            self.fail(
                "EA for instance ID %s does not match with NIOS" %
                self.instance.id)

    @test.attr(type='smoke')
    def test_EA_VM_NAME(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['VM Name']['value'],
                self.instance.name)
        else:
            self.fail(
                "EA for instance ID %s does not match with NIOS" %
                self.instance.name)

    @test.attr(type='smoke')
    def test_EA_IP_Type(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['IP Type']['value'],
                "Fixed")
        else:
            self.fail(
                "EA IP Type for %s does not match " % self.instance.id)

    @test.attr(type='smoke')
    def test_EA_Tenant_ID(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Tenant ID']['value'],
                self.instance.tenant_id)
        else:
            self.fail(
                "EA for tenant ID %s does not match with NIOS" %
                self.instance.tenant)

    @test.attr(type='smoke')
    def test_EA_Account(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Account']['value'],
                Neutron_user_id)
        else:
            self.fail(
                "EA for user ID % does not match with NIOS" %
                self.instance.user_id)

    @test.attr(type='smoke')
    def test_EA_Port_ID(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Port ID']['value'],
                self.client.list_ports(
                    device_owner="compute:None")[1]['ports'][0]['id'])
        else:
            self.fail(
                "EA for PORT ID % does not match with NIOS" %
                self.client.list_ports(
                    device_owner="compute:None")[1]['ports'][0]['id'])

    @test.attr(type='smoke')
    def test_EA_Port_Attached_Device_ID_for_instance(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Port Attached Device - Device ID']['value'],
                self.client.list_ports(
                    ubnet_id=self.subnet['id'], device_owner="compute:None")[1]['ports'][0]['device_id'])
        else:
            self.fail(
                "EA for Port Attached Device - Device ID % does not match with NIOS" %
                self.client.list_ports(
                    ubnet_id=self.subnet['id'], device_owner="compute:None")[1]['ports'][0]['device_id'])

    @test.attr(type='smoke')
    def test_EA_CMP_Type(self):
        args = "name=%s&_return_fields=extattrs" % (self.host_name)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['CMP Type']['value'],
                'openstack')
        else:
            self.fail("EA for cmp_type is not openstack")



#Test for Sub_Network
    @test.attr(type='smoke')
    def test_Network_ECMP_type(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Network Encap']['value'],
                self.network_type.upper())
        else:
            self.fail("EA for Network Encap doesnot match")

    @test.attr(type='smoke')
    def test_EA_Is_Shared(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Is Shared']
                ['value'], str(self.network['shared']))
        else:
            self.fail(
                "EA for Network is shared %s doesnot match %s" %
                (self.network['shared'],
                 loads(msg)[0]['extattrs']['Is Shared']['value']))


    def test_EA_network_CMP_Type(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['CMP Type']['value'],
                'openstack')
        else:
            self.fail("EA for cmp_type is not openstack")

    @test.attr(type='smoke')
    def test_EA_network_Segmentation_ID(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        self.assertTrue(int(loads(msg)[0]['extattrs']['Segmentation ID'][
                        'value']) in Segment_range,
                        "EA segmentation_id not updated")

    @test.attr(type='smoke')
    def test_EA_Network_Network_Name(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Network Name']['value'],
                self.network['name'])
        else:
            self.fail(
                "EA for network name %s doesnot match with NIOS" %
                self.network['shared'])

    @test.attr(type='smoke')
    def test_EA_Network_Subnet_Name(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Subnet Name']['value'],
                self.subnet['name'])
        else:
            self.fail(
                "EA for subnet name %s doesnot match with NIOS" %
                self.network['shared'])

    @test.attr(type='smoke')
    def test_EA_Network_Tenant_ID(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Tenant ID']['value'],
                self.subnet['tenant_id'])
        else:
            self.fail(
                "EA for Network tenant ID %s does not match with NIOS" %
                self.subnet['tenant_id'])

    @test.attr(type='smoke')
    def test_EA_Network_Subnet_ID(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Subnet ID']['value'],
                self.subnet['id'])
        else:
            self.fail(
                "EA for Network subnet ID %s does not match with NIOS" %
                self.subnet['id'])

    @test.attr(type='smoke')
    def test_EA_Network_Network_ID(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Network ID']['value'],
                self.subnet['network_id'])
        else:
            self.fail(
                "EA for Network ID %s does not match with NIOS" %
                self.subnet['network_id'])

    @test.attr(type='smoke')
    def test_EA_Network_Account(self):
        args = "network=%s&network_view=%s&_return_fields=extattrs" % (
            self.subnet['cidr'], self._baseconfig[0]['network_view'])
        code, msg = self.ib.wapi_get_request("network", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Account']['value'],
                self.isolated_creds.get_credentials('primary').user_id)
        else:
            self.fail(
                "EA for Network user ID %s does not match with NIOS " %
                self.isolated_creds.get_credentials('primary').user_id)

#Test Private Network DHCP Port EA's
    @test.attr(type='smoke')
    def test_EA_Private_Network_dhcp_Tenant_ID(self):
        fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network, self.subnet)
        dhcp_port = "dhcp-port-" + \
            self.internal_dhcp_ip.replace(".", "-") + "." + fqdn
        args = "name=%s&_return_fields=extattrs" % (dhcp_port)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Tenant ID']['value'],
                self.subnet['tenant_id'])
        else:
            self.fail("EA for cmp_type is not openstack")

    @test.attr(type='smoke')
    def test_EA_Private_Network_dhcp_VM_ID(self):
        fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network, self.subnet)
        dhcp_port = "dhcp-port-" + \
            self.internal_dhcp_ip.replace(".", "-") + "." + fqdn
        args = "name=%s&_return_fields=extattrs" % (dhcp_port)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['VM ID']['value'], "None")
        else:
            self.fail("EA for VM ID is mismatch on NIOS")

    @test.attr(type='smoke')
    def test_EA_Private_Network_dhcp_Device_ID(self):
        fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network, self.subnet)
        dhcp_port = "dhcp-port-" + \
            self.internal_dhcp_ip.replace(".", "-") + "." + fqdn
        args = "name=%s&_return_fields=extattrs" % (dhcp_port)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Port Attached Device - Device ID']['value'],
                self.client.list_ports(device_owner="network:dhcp", network_id=self.network['id'])[1]['ports'][0]['device_id'])
        else:
            self.fail(
                "EA for Port Attached Device - Device ID % does not match with NIOS" %
                self.client.list_ports(
                    subnet_id=self.network['id'], device_owner="network:dhcp")[1]['ports'][0]['device_id'])

    @test.attr(type='smoke')
    def test_EA_Private_Network_dhcp_Port_ID(self):
        fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network, self.subnet)
        dhcp_port = "dhcp-port-" + \
            self.internal_dhcp_ip.replace(".", "-") + "." + fqdn
        args = "name=%s&_return_fields=extattrs" % (dhcp_port)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['Port ID']['value'],
                self.client.list_ports(device_owner="network:dhcp", network_id=self.network['id'])[1]['ports'][0]['id'])
        else:
            self.fail(
                "EA for Port ID % does not match with NIOS" %
                self.client.list_ports(
                    subnet_id=self.network['id'], device_owner="network:dhcp")[1]['ports'][0]['id'])

    @test.attr(type='smoke')
    def test_EA_Private_Network_dhcp_IP_Type(self):
        fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network, self.subnet)
        dhcp_port = "dhcp-port-" + \
            self.internal_dhcp_ip.replace(".", "-") + "." + fqdn
        args = "name=%s&_return_fields=extattrs" % (dhcp_port)
        code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(
                loads(msg)[0]['extattrs']['IP Type']['value'], "Fixed")
        else:
            self.fail("EA IP Type for %s does not match " % dhcp_port)


    @classmethod
    def tearDownClass(self):

# delete instance
        self.ib.terminate_instance(self.instance)
# Remove subnet
        self.client.delete_subnet(self.subnet['id'])
# Delete Network
        self.client.delete_network(self.network['id'])
# delete user
        self.isolated_creds.clear_isolated_creds()

        super(Condition_subnet_range_InfobloxScenario12, self).tearDownClass()
# revert neutron config
        if(self._arecord):
            ibbase.a_record_setup()

