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

class MultipleInstanceCreation(base.BaseNetworkTest):
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
        super(MultipleInstanceCreation, self).setUpClass()
        self.ib = ibbase.InfobloxNIOStest(
            self.isolated_creds.get_credentials('primary'))
        # create network
        network_name = data_utils.rand_name('test-network')
        resp, body = self.client.create_network(name=network_name)
        self.network = body['network']
        # create subnet
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
        # create server
        server_name = data_utils.rand_name('test-server')
        flavor = CONF.compute.flavor_ref
        image_id = CONF.compute.image_ref
        kwargs = {'net-id': self.network['id']},
        names = ['vm1', 'vm2', 'vm3']
        self.vms = []
        self.hosts = []
        for i in range(len(names)):
            self.instance = self.ib.launch_instance(
                         server_name,
                         image_id,
                         flavor,
                         kwargs
            )
            self.host_name = self.ib.get_host_from_hostname_pattern(
                          self.instance,
                          self.network,
                          self.subnet
            )
            self.vms.append(self.instance)
            self.hosts.append(self.host_name)

    @test.attr(type='smoke')
    def test_host_records_created_for_all_instances(self):
        for i in self.hosts:
            args = "name=%s" % (i)
            code, msg = self.ib.wapi_get_request("record:host", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['name'], i)
            else:
                self.fail("Host %s is not added to NIOS" % self.hosts[i])
                
    @test.attr(type='smoke')
    def test_DHCP_Lease_from_NIOS_for_all_instances(self):
        for i in self.vms:
            match_obj_for_lease_msg = self.ib.search_console_log(i)
            self.assertNotEqual(match_obj_for_lease_msg, None)

    @classmethod
    def tearDownClass(self):
        # delete instance
        for j in self.vms:
            self.ib.terminate_instance(j)
        self.client.delete_subnet(self.subnet['id'])
        self.client.delete_network(self.network['id'])
        self.isolated_creds.clear_isolated_creds()
        # delete project
        super(MultipleInstanceCreation, self).tearDownClass()
