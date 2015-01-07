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
             args = "fqdn=%s" % (self.fqdn)
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
            args = "fqdn=%s" % (fqdn)
            code, msg = self.ib.wapi_get_request("zone_auth", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['fqdn'], fqdn)
            else:
                self.fail("Zone %s is not added to NIOS" % fqdn)

    def del_snet2_zone_should_delete(self,deleted_subnet):
            fqdn = self.ib.get_fqdn_from_domain_suffix_pattern(
            self.network, deleted_subnet)
            args = "fqdn=%s" % (fqdn)
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
