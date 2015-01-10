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


class MultSubnet_Create_Del_subnet_name_pattern(base.BaseNetworkTest):

    _baseconfig = [{
        "domain_suffix_pattern": "{subnet_name}.cloud.global.com",
        "network_view": "tempest",
        "is_external": False,
        "require_dhcp_relay": True,
        "hostname_pattern": "host-{ip_address}",
        "condition": "tenant",
        "dhcp_members": "<next-available-member>"
    }]

    _arecord = 0

    _external = False

    @classmethod
    #@test.safe_setup
    def setUpClass(self):

        if(self._arecord):
            ibbase.a_record_setup(self._arecord)

        ibbase.set_configopt(self._baseconfig)
        ibbase.service_restart()
        time.sleep(30)

        super(MultSubnet_Create_Del_subnet_name_pattern, self).setUpClass()

        self.ib = ibbase.InfobloxNIOStest(
            self.isolated_creds.get_credentials('primary'))

        # create network
        network_name = data_utils.rand_name('test-network')
        resp, body = self.client.create_network(name=network_name)
        self.network = body['network']

        ## get multiple subnets CIDR
        cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
        mask_bits = CONF.network.tenant_network_mask_bits
        cidrs = []
        for subnet_cidr in cidr.subnet(mask_bits):
            cidrs.append(subnet_cidr)
        subnet_names = ['snet1', 'snet2']
        self.subnet = []
        # create subnet1
        #subnet_name = data_utils.rand_name('test-subnet')
        mask_bits = CONF.network.tenant_network_mask_bits
        for i in range(len(subnet_names)):
            resp, body = self.client.create_subnet(
                name=subnet_names[i],
                network_id=self.network['id'],
                cidr=str(cidrs[i]),
                ip_version=4
            )
            self.subnet.append(body['subnet'])

    @test.attr(type='smoke')
    def test_del_both_snet_zone_should_delete(self):
         for i in self.subnet:
             self.fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network,i)
             self.client.delete_subnet(i['id'])
             args =  "fqdn=%s&view=default.%s" % (self.fqdn, self._baseconfig[0]['network_view']) 
             code, msg = self.ib.wapi_get_request("zone_auth", args)
             if code == 200 and len(loads(msg)) == 0:
                 self.assertEqual(1,1)
             else:
                 self.fail("Zone %s exist in NIOS after deleting. msg: %s" % (self.fqdn,loads(msg)))

           #  self.check1_zone_added_to_NIOS(self.fqdn)
        

    @classmethod
    def tearDownClass(self):
        ## delete network
        self.client.delete_network(self.network['id'])
        super(MultSubnet_Create_Del_subnet_name_pattern, self).tearDownClass()

class Create_multiple_snet_condition_global(MultSubnet_Create_Del_subnet_name_pattern):

    _baseconfig = [{
        "domain_suffix_pattern": "{subnet_id}.cloud.global.com",
        "network_view": "tempest",
        "is_external": False,
        "require_dhcp_relay": True,
        "hostname_pattern": "host-{subnet_name}",
        "condition": "global",
        "dhcp_members": "<next-available-member>"
    }]

    def delete_snet(self):
        for subnet_i in self.subnet:
             self.fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network,subnet_i)
             self.client.delete_subnet(subnet_i['id'])

    def check_subnet_ZONE_exist_in_NIOS(self):
        for subnet_i in self.subnet:
            self.fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network,subnet_i)
            args =  "fqdn=%s&view=default.%s" % (self.fqdn, self._baseconfig[0]['network_view']) 
            code, msg = self.ib.wapi_get_request("zone_auth", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['fqdn'], self.fqdn)
            else:
                self.fail("Zone %s deleted from NIOS in condition global" % self.fqdn)
    
    def check_network_exist_in_NIOS(self):
        for subnet_i in self.subnet:
            args = "network=%s" % (subnet_i['cidr'])
            code, msg = self.ib.wapi_get_request("network", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['network'], subnet_i['cidr'])
            else:
                self.fail("Network %s got deleted from NIOS" % subnet_i['cidr'])

    def delete_network_NIOS_side_to_execute_next_case(self):
        for subnet_i in self.subnet:
            args = "network=%s" % (subnet_i['cidr'])
            code, msg = self.ib.wapi_get_request("network", args)
            if code == 200 and len(loads(msg)) > 0:
                del_object = loads(msg)[0]['_ref'].split(':')[0]
                code, msg1 = self.ib.wapi_get_request(del_object,'_method=DELETE')

    @test.skip_because(bug="1236220")
    def test_del_both_snet_zone_should_delete(self):
        pass

    @test.attr(type='smoke')
    def test_del_both_snet_zone_should_exist(self):
             self.delete_snet()
             self.check_subnet_ZONE_exist_in_NIOS()
             self.check_network_exist_in_NIOS()
             from nose.tools import set_trace; set_trace()
             self.delete_network_NIOS_side_to_execute_next_case()
             

class MultSubnet_Create_Del_network_name_pattern(base.BaseNetworkTest):


    _baseconfig = [{
        "domain_suffix_pattern": "{network_name}.cloud.global.com",
        "network_view": "tempest",
        "is_external": False,
        "require_dhcp_relay": True,
        "hostname_pattern": "host-{network_id}",
        "condition": "tenant",
        "dhcp_members": "<next-available-member>"
    }]


    _arecord = 0

    _external = False

    @classmethod
    #@test.safe_setup
    def setUpClass(self):

        if(self._arecord):
            ibbase.a_record_setup(self._arecord)

        ibbase.set_configopt(self._baseconfig)
        ibbase.service_restart()
        time.sleep(30)

        super(MultSubnet_Create_Del_network_name_pattern, self).setUpClass()

        self.ib = ibbase.InfobloxNIOStest(
            self.isolated_creds.get_credentials('primary'))

        # create network
        network_name = data_utils.rand_name('test-network')
        resp, body = self.client.create_network(name=network_name)
        self.network = body['network']

        ## get multiple subnets CIDR
        cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
        mask_bits = CONF.network.tenant_network_mask_bits
        cidrs = []
        for subnet_cidr in cidr.subnet(mask_bits):
            cidrs.append(subnet_cidr)
        subnet_names = ['snet1', 'snet2']
        self.subnet = []
        # create subnet1
        #subnet_name = data_utils.rand_name('test-subnet')
        mask_bits = CONF.network.tenant_network_mask_bits
        for i in range(len(subnet_names)):
            resp, body = self.client.create_subnet(
                name=subnet_names[i],
                network_id=self.network['id'],
                cidr=str(cidrs[i]),
                ip_version=4
            )
            self.subnet.append(body['subnet'])

    def del_snet1_zone_should_exist(self,deleted_subnet):
            fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(
            self.network, deleted_subnet)
            args =  "fqdn=%s&view=default.%s" % (self.fqdn, self._baseconfig[0]['network_view']) 
            code, msg = self.ib.wapi_get_request("zone_auth", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['fqdn'], fqdn)
            else:
                self.fail("Zone %s is not added to NIOS" % fqdn)

    def del_snet2_zone_should_delete(self,deleted_subnet):
            fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(
            self.network, deleted_subnet)
            args =  "fqdn=%s&view=default.%s" % (self.fqdn, self._baseconfig[0]['network_view']) 
            code, msg = self.ib.wapi_get_request("zone_auth", args)
            code, msg = self.ib.wapi_get_request("zone_auth", args)
            if code == 200 and len(loads(msg)) == 0:
                self.assertEqual(1,1)
            else:
                self.fail("Zone %s exist in NIOS after deleting 2nd subnet. msg: %s" % (self.fqdn,loads(msg)))

    def delete_subnet(self,subnet):
            self.client.delete_subnet(subnet['id'])
           

    @test.attr(type='smoke')
    def test_network_pattern_2nd_snet_should_delete_zone(self):
            self.fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(self.network,self.subnet[0])
            self.delete_subnet(self.subnet[0]) 
            self.del_snet1_zone_should_exist(self.subnet[0])
            self.delete_subnet(self.subnet[1]) 
            self.del_snet2_zone_should_delete(self.subnet[1])
        

    @classmethod
    def tearDownClass(self):
        ## delete network
        self.client.delete_network(self.network['id'])
        super(MultSubnet_Create_Del_network_name_pattern, self).tearDownClass()
