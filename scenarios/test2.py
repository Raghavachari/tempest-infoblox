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
from tempest.common.utils.data_utils import rand_name

CONF = config.CONF

Neutron_user_id = ibbase.get_neutron_user_id()
Segment_range = ibbase.segmentation_range()


class InfobloxScenario1(base.BaseNetworkTest):

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
        time.sleep(10)

        super(InfobloxScenario1, self).setUpClass()
	
	self.network1 = self.create_network()
	self.network2 = self.create_network()	

        self.ib = ibbase.InfobloxNIOStest(
       	  	self.isolated_creds.get_credentials('primary'))

        # create subnet
        cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
        mask_bits = CONF.network.tenant_network_mask_bits
	cidrs = []
	for subnet_cidr in cidr.subnet(mask_bits):
	    cidrs.append(subnet_cidr)
	names = ['snet1', 'snet2']
	networks = [self.network1['id'], self.network2['id']]
	subnet_list = []
	ip_version = [4, 4]
	for i in range(len(names)):
	    p1 = {
                'network_id': networks[i],
                'cidr': str(cidrs[(i)]),
                'name': names[i],
                'ip_version': ip_version[i]
            }
 	    subnet_list.append(p1)
	#del subnet_list[1]['name']
	resp, body = self.client.create_bulk_subnet(subnet_list)
	self.subnet = body['subnets']
	nets = [self.network1, self.network2]

        # create server
        server_name = data_utils.rand_name('test-server')
        flavor = CONF.compute.flavor_ref
        image_id = CONF.compute.image_ref
        kwargs = {'net-id': self.network2['id']},
        self.instance = self.ib.launch_instance(
            server_name,
            image_id,
            flavor,
            kwargs)
        self.host_name = self.ib.get_host_from_hostname_pattern(
            self.instance,
            self.network2,
            self.subnet[1])
    @test.attr(type='smoke')
    def test_Host_record_added_to_NIOS_multiple_network(self):
        args = "name=%s" % (self.host_name)
	code, msg = self.ib.wapi_get_request("record:host", args)
        if code == 200 and len(loads(msg)) > 0:
            self.assertEqual(loads(msg)[0]['name'], self.host_name)
        else:
            self.fail("Host %s is not added to NIOS" % self.host_name)

    @test.attr(type='smoke')
    def test_Multiple_networks_added_to_NIOS(self):
	cidr_list = []
	for x in self.subnet:
	    y = x['cidr']
	    cidr_list.append(y)
	for p in cidr_list: 
	    args = "network=%s" % (p)
            code, msg = self.ib.wapi_get_request("network", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['network'], p)
            else:
                self.fail("Network %s is not added to NIOS" % p)
       
	from nose.tools import set_trace; set_trace()
    @test.attr(type='smoke')
    def test_DHCP_Lease_from_NIOS_for_instance(self):
        match_obj_for_lease_msg = self.ib.search_console_log(self.instance)
        self.assertNotEqual(match_obj_for_lease_msg, None)


    @classmethod
    def tearDownClass(self):
        self.ib.terminate_instance(self.instance)
	# delete user
        #self.isolated_creds.clear_isolated_creds()
        # delete project
        super(InfobloxScenario1, self).tearDownClass()


