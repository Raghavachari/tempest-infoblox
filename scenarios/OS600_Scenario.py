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


class OS600_Scenario(base.BaseNetworkTest):


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

        super(OS600_Scenario, self).setUpClass()

        self.ib = ibbase.InfobloxNIOStest(
            self.isolated_creds.get_credentials('primary'))

        # create network
        network_name = data_utils.rand_name('test-network')
        resp, body = self.client.create_network(name=network_name)
        self.network = body['network']

        ## get multiple subnets CIDR
        cidrs = ["55.55.0.0/29", "66.66.0.0/29"]
        subnet_names = ['snet1', 'snet2']
        self.subnet = []
        for i in range(len(subnet_names)):
            resp, body = self.client.create_subnet(
                name=subnet_names[i],
                network_id=self.network['id'],
                cidr=str(cidrs[i]),
                ip_version=4
            )
            self.subnet.append(body['subnet'])

        # create server
        server_name = data_utils.rand_name('test-server')
        flavor = CONF.compute.flavor_ref
        image_id = CONF.compute.image_ref
        kwargs = {'net-id': self.network['id']},
        names = ['vm1', 'vm2', 'vm3', 'vm4', 'vm5']
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
    def test_all_host_records_added_to_NIOS(self):
        for i in self.hosts:
            args = "name=%s" % (i)
            code, msg = self.ib.wapi_get_request("record:host", args)
            if code == 200 and len(loads(msg)) > 0:
                self.assertEqual(loads(msg)[0]['name'], i)
            else:
                self.fail("Host %s is not added to NIOS" % self.hosts[i])

    @test.attr(type='smoke')
    def test_DHCP_Lease_from_NIOS_for_first_4_instances(self):
        for i in self.vms[0:4]:
            match_obj_for_lease_msg = self.ib.search_console_log(i)
            self.assertNotEqual(match_obj_for_lease_msg, None)

    @test.attr(type='smoke')
    def test_DHCP_Lease_from_NIOS_for_first_5_instance(self):
        match_obj_for_lease_msg = self.ib.search_console_log(self.vms[4])
        self.assertNotEqual(match_obj_for_lease_msg, None)

    @classmethod
    def tearDownClass(self):
        for j in self.vms:
            self.ib.terminate_instance(j)
        for x in self.subnet:
            self.client.delete_subnet(x['id'])
        self.client.delete_network(self.network['id'])
        self.isolated_creds.clear_isolated_creds()
        # delete project
        super(OS600_Scenario, self).tearDownClass()
