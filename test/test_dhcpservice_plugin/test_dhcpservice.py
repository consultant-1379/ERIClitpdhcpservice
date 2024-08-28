##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest
from mock import Mock
from netaddr.ip import IPAddress, IPNetwork

from litp.extensions.core_extension import CoreExtension
from litp.core.execution_manager import ConfigTask
from litp.core.plugin_context_api import PluginApiContext
from litp.core.model_manager import ModelManager
from litp.core.plugin_manager import PluginManager
from litp.core.validators import ValidationError
from litp.core.model_type import ItemType, Child
from litp.core.model_item import ModelItem

from network_extension.network_extension import NetworkExtension
from dhcpservice_extension.dhcpserviceextension import DhcpserviceExtension
from dhcpservice_plugin.dhcpserviceplugin import DhcpservicePlugin


class DhcpMock(Mock):
    def __init__(self, **kwargs):
        super(DhcpMock, self).__init__(**kwargs)
        self.get_vpath=lambda: "/%s/%s" % (self.item_type_id, self.item_id)


class TestDhcpservicePlugin(unittest.TestCase):

    @staticmethod
    def _set_state_xxx(items, state):
        for item in items:
            if 'applied' == state:
                item.is_applied = lambda: True
                item.is_for_removal = lambda: False
                item.is_updated = lambda: False
                item.is_initial = lambda: False
            elif 'for_removal' == state:
                item.is_applied = lambda: False
                item.is_for_removal = lambda: True
                item.is_updated = lambda: False
                item.is_initial = lambda: False
            elif 'updated' == state:
                item.is_applied = lambda: False
                item.is_for_removal = lambda: False
                item.is_updated = lambda: True
                item.is_initial = lambda: False
            elif 'initial' == state:
                item.is_applied = lambda: False
                item.is_for_removal = lambda: False
                item.is_updated = lambda: False
                item.is_initial = lambda: True

    @staticmethod
    def _set_state_applied(items):
        TestDhcpservicePlugin._set_state_xxx(items, 'applied')

    @staticmethod
    def _set_state_updated(items):
        TestDhcpservicePlugin._set_state_xxx(items, 'updated')

    @staticmethod
    def _set_state_initial(items):
        TestDhcpservicePlugin._set_state_xxx(items, 'initial')

    @staticmethod
    def _set_state_for_removal(items):
        TestDhcpservicePlugin._set_state_xxx(items, 'for_removal')

    def setUp(self):
        """
        Construct a model, sufficient for test cases
        that you wish to implement in this suite.
        """
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)

        for extension in [CoreExtension(), NetworkExtension(), DhcpserviceExtension()]:
            self.plugin_manager.add_property_types(extension.define_property_types())
            self.plugin_manager.add_item_types(extension.define_item_types())

        self.plugin_manager.add_default_model()

        self.plugin = DhcpservicePlugin()

    def setup_model(self):
        deploy_url = '/deployments/d1'
        cluster_url = deploy_url + '/clusters/c1'
        nodes_url = cluster_url + '/nodes/'

        a = self.model.create_item('deployment', deploy_url)

        b = self.model.create_item('cluster', cluster_url)

        c = self.model.create_item('node',
                                   nodes_url + 'n1',
                                   hostname='mn1')
        d = self.model.create_item('node',
                                   nodes_url + 'n2',
                                   hostname='mn2')

        for item in [a, b, c, d]:
            self.assertTrue(isinstance(item, ModelItem))

        return (c, d)

    def query(self, item_type=None, **kwargs):
        # Use ModelManager.query to find items in the model
        # properties to match desired item are passed as kwargs.
        # The use of this method is not required, but helps
        # plugin developer mimic the run-time environment
        # where plugin sees QueryItem-s.
        # LITPCDS-12247: Plugins should not access ModelItems
        return self.context.query(item_type, **kwargs)

    def test_get_dhcp_interfaces(self):

        dhcp_networks = ['storage', 'backup']

        mock_if = DhcpMock(item_id='if1',
                           item_type_id='eth',
                           device_name='eth1',
                           network_name='storage')

        mock_node = DhcpMock(item_id='n1',
                             item_type_id='node',
                             hostname="node1",
                             network_interfaces=[mock_if])

        items = [mock_if, mock_node]
        TestDhcpservicePlugin._set_state_initial(items)

        dhcp_interfaces = self.plugin._get_current_dhcp_interfaces(mock_node,
                                                                   dhcp_networks)

        self.assertEquals(dhcp_interfaces, [mock_if.device_name])

        dhcp_networks_empty = []

        dhcp_interfaces = self.plugin._get_current_dhcp_interfaces(mock_node,
                                                                   dhcp_networks_empty)

        self.assertEquals(dhcp_interfaces, [])

        # ----

        mock_if.network_name = 'mgmt'

        dhcp_interfaces = self.plugin._get_current_dhcp_interfaces(mock_node,
                                                                   dhcp_networks)

        self.assertEquals(dhcp_interfaces, [])

    def test_get_mgmt_ip_of_node(self):

        mock_if = DhcpMock(item_id='if1',
                           item_type_id='eth',
                           device_name='eth1',
                           network_name='mgmt',
                           ipaddress='192.168.0.43')

        mock_node = DhcpMock(item_id='n1',
                             item_type_id='node',
                             hostname="node1",
                             network_interfaces = [mock_if])

        mock_net = DhcpMock(item_id='net1',
                            item_type_id='network',
                            litp_management='true',
                            subnet='10.10.10.0/24')
        mock_net.name = mock_if.network_name

        context = Mock(query=lambda x, **kwargs: [mock_net])

        items = [mock_if, mock_node, mock_net]
        TestDhcpservicePlugin._set_state_initial(items)

        mgmt_ip = self.plugin._get_mgmt_ip_of_node(context, mock_node)

        self.assertEquals(mgmt_ip, mock_if.ipaddress)

        # ----

        mock_if.network_name = 'non_mgmt'

        mgmt_ip = self.plugin._get_mgmt_ip_of_node(context, mock_node)

        self.assertEquals(mgmt_ip, None)

    def test_get_peer_address(self):
        mock_if1 = DhcpMock(item_id='if1',
                            item_type_id='eth',
                            device_name='eth1',
                            network_name='mgmt',
                            ipaddress='192.168.0.42')

        mock_if2 = DhcpMock(item_id='if2',
                            item_type_id='eth',
                            device_name='eth2',
                            network_name=mock_if1.network_name,
                            ipaddress='192.168.0.43')

        svc1 = DhcpMock(item_id='s1',
                        item_type_id='dhcp-service',
                        service_name='dhcp_svc1',
                        primary='true')

        svc2 = DhcpMock(item_id='s2',
                        item_type_id='dhcp-service',
                        service_name='dhcp_svc1',
                        primary='false')

        mock_node1 = DhcpMock(item_id='n1',
                              item_type_id='node',
                              hostname='mn1',
                              network_interfaces=[mock_if1],
                              query=lambda x: [svc1])

        mock_node2 = DhcpMock(item_id='n2',
                              item_type_id='node',
                              hostname = 'mn2',
                              network_interfaces=[mock_if2],
                              query=lambda x: [svc2])

        mock_net = DhcpMock(item_id='net1',
                            item_type_id='network',
                            litp_management='true',
                            subnet='10.10.10.0/24')
        mock_net.name = mock_if1.network_name

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1, mock_node2]
            elif 'network' == query_item_type:
                return [mock_net]

        context = Mock(query=_mock_context_query)

        items = [mock_if1, mock_if2, svc1, svc2, mock_node1, mock_node2, mock_net]
        TestDhcpservicePlugin._set_state_initial(items)

        peer_address = self.plugin._get_peer_address(context, svc1)

        self.assertEquals(peer_address, mock_if2.ipaddress)

        #---

        mock_if3 = DhcpMock(item_id='if3',
                            item_type_id='eth',
                            device_name='eth3',
                            network_name=mock_if1.network_name,
                            ipaddress='10.10.10.10')

        mock_if4 = DhcpMock(item_id='if4',
                            item_type_id='eth',
                            device_name='eth4',
                            network_name=mock_if3.network_name,
                            ipaddress='10.10.10.11')

        svc3 = DhcpMock(item_id='s3',
                        item_type_id='dhcp-service',
                        service_name='dhcp_svc2',
                        primary='true')

        svc4 = DhcpMock(item_id='s4',
                        item_type_id='dhcp-service',
                        service_name='dhcp_svc2',
                        primary='false')

        mock_node1.network_interfaces = [mock_if1, mock_if3]
        mock_node1.query = lambda x: [svc1, svc3]

        mock_node2.network_interfaces = [mock_if2, mock_if4]
        mock_node2.query = lambda x: [svc2, svc4]

        items = [mock_if3, mock_if4, svc3, svc4]
        TestDhcpservicePlugin._set_state_initial(items)

        peer_address = self.plugin._get_peer_address(context, svc3)

        self.assertEquals(peer_address, mock_if4.ipaddress)

    def test_get_network_address(self):
        dhcp_subnet = DhcpMock(item_id='s1',
                               item_type_id='dhcp-subnet',
                               network_name='storage')

        mock_net1 = DhcpMock(item_id='n1',
                             item_type_id='network',
                             subnet='10.10.10.0/24')
        mock_net1.name = dhcp_subnet.network_name

        mock_net2 = DhcpMock(item_id='n2',
                             item_type_id='network',
                             subnet='192.10.10.0/24')
        mock_net2.name = 'backup'

        context = Mock(query=lambda x,
                       **kwargs: [mock_net1, mock_net2])

        items = [dhcp_subnet, mock_net1, mock_net2]
        TestDhcpservicePlugin._set_state_initial(items)

        net_address = self.plugin._get_ipv4_network_address(context, dhcp_subnet)

        self.assertEquals(net_address, IPNetwork('10.10.10.10/24'))

    def test_failover_added(self):
        mock_if1 = DhcpMock(item_id='if1',
                            item_type_id='eth',
                            device_name='eth1',
                            network_name='mgmt',
                            ipaddress='192.168.0.42',
                            ipv6address=None)
        mock_if3 = DhcpMock(item_id='if3',
                            item_type_id='eth',
                            device_name='eth3',
                            network_name='storage',
                            ipaddress='10.0.0.5',
                            ipv6address=None)

        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp-range',
                          start='10.0.0.1',
                          end='11.0.0.1')

        dhcp_subnet1 = DhcpMock(item_id='sub1',
                                item_type_id='dhcp-subnet',
                                network_name=mock_if3.network_name,
                                ranges=[range1])

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',
                        ntpservers='server 0.ie.pool.ntp.org, 10.44.86.30',
                        domainsearch='test1.com, test2.com',
                        nameservers='1.2.3.1, 10.44.86.35',
                        service_name='dhcp_serv1',
                        primary='true',
                        subnets=[dhcp_subnet1])

        def _node1_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1]
            elif 'dhcp6-service' == query_item_type:
                return []

        mock_node1 = DhcpMock(item_id='node1',
                              item_type_id='node',
                              hostname = 'mn1',
                              network_interfaces=[mock_if1, mock_if3],
                              query=_node1_dhcp_service_query)

        mock_net1 = DhcpMock(item_id='net1',
                             item_type_id='network',
                             subnet='10.10.10.0/24')
        mock_net1.name = 'backup'

        mock_net2 = DhcpMock(item_id='net2',
                             item_type_id='network',
                             subnet='192.10.10.0/24')
        mock_net2.name = mock_if3.network_name

        mock_net3 = DhcpMock(item_id='net3',
                             item_type_id='network',
                             litp_management='true',
                             subnet='10.10.10.0/24')
        mock_net3.name = mock_if1.network_name

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1]
            elif 'network' == query_item_type and kwargs:
                return [mock_net3]
            elif 'network' == query_item_type:
                return [mock_net1, mock_net2]

        items = [mock_if1, mock_if3, range1, dhcp_subnet1, svc1,
                 mock_node1, mock_net1, mock_net2, mock_net3]

        TestDhcpservicePlugin._set_state_applied(items)

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)

        self.assertEquals([], tasks)

        #---

        mock_if2 = DhcpMock(item_id='if2',
                            item_type_id='eth',
                            device_name='eth2',
                            network_name='mgmt',
                            ipaddress='192.168.0.43',
                            ipv6address=None)

        mock_if5 = DhcpMock(item_id='if5',
                            item_type_id='eth',
                            device_name='eth5',
                            network_name=mock_if3.network_name,
                            ipaddress='30.0.0.5',
                            ipv6address=None)

        range2 = DhcpMock(item_id='r1',
                          item_type_id='dhcp-range',
                          start='10.0.0.1',
                          end='11.0.0.1')

        dhcp_subnet2 = DhcpMock(item_id='sub2',
                                item_type_id='dhcp-subnet',
                                network_name=mock_if5.network_name,
                                ranges=[range2])

        svc2 = DhcpMock(item_id='svc2',
                        item_type_id='dhcp-service',
                        ntpservers='server 0.ie.pool.ntp.org, 10.44.86.30',
                        domainsearch='test1.com, test2.com',
                        nameservers='1.2.3.1, 10.44.86.35',
                        service_name=svc1.service_name,
                        primary='false',
                        subnets=[dhcp_subnet2])

        def _node2_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc2]
            elif 'dhcp6-service' == query_item_type:
                return []

        mock_node2 = DhcpMock(item_id='node2',
                              item_type_id='node',
                              hostname = 'mn2',
                              network_interfaces=[mock_if2, mock_if5],
                              query=_node2_dhcp_service_query)

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1, mock_node2]
            elif 'network' == query_item_type and kwargs:
                return [mock_net3]
            elif 'network' == query_item_type:
                return [mock_net1, mock_net2]

        TestDhcpservicePlugin._set_state_applied([mock_if2, mock_if5, mock_node2])
        TestDhcpservicePlugin._set_state_initial([svc2, range2, dhcp_subnet2])

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)

        expected_tasks = [
            ConfigTask(mock_node1, svc1,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       domainsearch=['test1.com', 'test2.com'],
                       peer_address=mock_if2.ipaddress,
                       interfaces=[mock_if3.device_name],
                       role='primary',
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       address=mock_if1.ipaddress),
            ConfigTask(mock_node1, dhcp_subnet1,
                       'Update "dhcp-subnet" on network "%s" on node "%s"' % (mock_if3.network_name, mock_node1.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet1),
                       ranges=['10.0.0.1 11.0.0.1'],
                       mask='255.255.255.0',
                       network='192.10.10.0',
                       failover='true'),
            ConfigTask(mock_node2, svc2,
                       'Configure "dhcp-service" "%s" on node "%s"' % (svc2.service_name, mock_node2.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc2),
                       peer_address=mock_if1.ipaddress,
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       interfaces=[mock_if5.device_name],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='secondary',
                       address=mock_if2.ipaddress),
            ConfigTask(mock_node2, dhcp_subnet2,
                       'Configure "dhcp-subnet" and "dhcp-range" on network "%s" on node "%s"' % (mock_if3.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet2),
                       ranges=['10.0.0.1 11.0.0.1'],
                       mask='255.255.255.0',
                       network='192.10.10.0',
                       failover='true'),
        ]
        self.assertEquals(4, len(tasks))

        self.assertEquals(set(expected_tasks), set(tasks))

        #--- Test failover removal

        TestDhcpservicePlugin._set_state_applied([svc2, range2, dhcp_subnet2])
        TestDhcpservicePlugin._set_state_for_removal([svc1])

        context = Mock(query=_mock_context_query)

        expected_tasks = [
            ConfigTask(mock_node1, svc1,
                      'Deconfigure "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                      'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       ensure='absent'),
            ConfigTask(mock_node2, svc2,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc2.service_name, mock_node2.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc2),
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       interfaces=[mock_if5.device_name],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='primary',
                       address=mock_if2.ipaddress),
            ConfigTask(mock_node2, dhcp_subnet2,
                       'Update "dhcp-subnet" on network "%s" on node "%s"' % (mock_if3.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet2),
                       ranges=['10.0.0.1 11.0.0.1'],
                       mask='255.255.255.0',
                       network='192.10.10.0')
        ]

        tasks = self.plugin.create_configuration(context)
#       for s in tasks:
#           print s.description

        self.assertEquals(set(expected_tasks), set(tasks))

    def test_new_tasks(self):
        mock_if1 = DhcpMock(item_id='if1',
                            item_type_id='eth',
                            device_name='eth1',
                            network_name='mgmt',
                            ipaddress='192.168.0.42',
                            ipv6address=None)

        mock_if2 = DhcpMock(item_id='if2',
                            item_type_id='eth',
                            device_name='eth2',
                            network_name=mock_if1.network_name,
                            ipaddress='192.168.0.43',
                            ipv6address=None)

        mock_if3 = DhcpMock(item_id='if3',
                            item_type_id='eth',
                            device_name='eth3',
                            network_name='storage',
                            ipaddress='10.0.0.5',
                            ipv6address=None)

        mock_if4 = DhcpMock(item_id='if4',
                            item_type_id='eth',
                            device_name='eth4',
                            network_name='backup',
                            ipaddress='20.0.0.5',
                            ipv6address=None)

        mock_if5 = DhcpMock(item_id='if5',
                            item_type_id='eth',
                            device_name='eth5',
                            network_name='someelse',
                            ipaddress='30.0.0.5',
                            ipv6address=None)

        mock_if6 = DhcpMock(item_id='if6',
                            item_type_id='eth',
                            device_name='eth6',
                            network_name='ipv6',
                            ipv6address='fc01::2',
                            ipaddress=None)

        mock_if7 = DhcpMock(item_id='if7',
                            device_name='eth7',
                            item_type_id='eth',
                            network_name=mock_if6.network_name,
                            ipv6address='fc01::3',
                            ipaddress=None)

        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp-range',
                          start='10.0.0.1',
                          end='11.0.0.1')

        range2 = DhcpMock(item_id='r2',
                          item_type_id='dhcp-range',
                          start='20.0.0.1',
                          end='21.0.0.1')

        range3 = DhcpMock(item_id='r3',
                          item_type_id='dhcp6-range',
                          start='fc01::10',
                          end='fc01::15')

        dhcp_subnet1 = DhcpMock(item_id='sub1',
                                item_type_id='dhcp-subnet',
                                network_name=mock_if3.network_name,
                                ranges=[range1, range2])

        dhcp_subnet2 = DhcpMock(item_id='sub2',
                                item_type_id='dhcp-subnet',
                                network_name=mock_if4.network_name,
                                ranges=[range1, range2])

        dhcp_subnet3 = DhcpMock(item_id='sub3',
                                item_type_id='dhcp6-subnet',
                                network_name=mock_if6.network_name,
                                ranges=[range3])

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',
                        ntpservers='server 0.ie.pool.ntp.org, 10.44.86.30',
                        domainsearch='test1.com, test2.com',
                        nameservers='1.2.3.1, 10.44.86.35',
                        service_name='dhcp_serv1',
                        primary='true',
                        subnets=[dhcp_subnet1, dhcp_subnet2])

        svc2 = DhcpMock(item_id='svc2',
                        service_name=svc1.service_name,
                        ntpservers='server 0.ie.pool.ntp.org, 10.44.86.30',
                        domainsearch='test1.com, test2.com',
                        nameservers='1.2.3.1, 10.44.86.35',
                        item_type_id='dhcp-service',
                        primary='false',
                        subnets=[dhcp_subnet1, dhcp_subnet2])

        svc3 = DhcpMock(item_id='svc3',
                        item_type_id='dhcp6-service',
                        ntpservers=None,
                        domainsearch=None,
                        nameservers=None,
                        service_name='dhcp_servv6',
                        primary='true',
                        subnets=[dhcp_subnet3])

        svc4 = DhcpMock(item_id='svc4',
                        item_type_id='dhcp6-service',
                        ntpservers=None,
                        domainsearch=None,
                        nameservers=None,
                        service_name=svc3.service_name,
                        primary='false',
                        subnets=[dhcp_subnet3])

        def _node1_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1]
            elif 'dhcp6-service' == query_item_type:
                return [svc3]

        def _node2_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc2]
            elif 'dhcp6-service' == query_item_type:
                return [svc4]

        mock_node1 = DhcpMock(item_id='node1',
                              item_type_id='node',
                              hostname = 'mn1',
                              network_interfaces=[mock_if1, mock_if3, mock_if5, mock_if6],
                              query=_node1_dhcp_service_query)

        mock_node2 = DhcpMock(item_id='node2',
                              item_type_id='node',
                              hostname = 'mn2',
                              network_interfaces=[mock_if2, mock_if4, mock_if7],
                              query=_node2_dhcp_service_query)

        mock_net1 = DhcpMock(item_id='net1',
                             item_type_id='network',
                             subnet='10.10.10.0/24')
        mock_net1.name = mock_if4.network_name

        mock_net2 = DhcpMock(item_id='net2',
                             item_type_id='network',
                             subnet='192.10.10.0/24')
        mock_net2.name = mock_if3.network_name

        mock_net3 = DhcpMock(item_id='net3',
                             item_type_id='network',
                             litp_management='true',
                             subnet='10.10.10.0/24')
        mock_net3.name = mock_if1.network_name

        items_for_state_mgmt = [mock_if1, mock_if2, mock_if3,
                                mock_if5, mock_if4, mock_if6, mock_if7,
                                range1, range2, range3,
                                dhcp_subnet1, dhcp_subnet2, dhcp_subnet3,
                                svc1, svc2, svc3, svc4,
                                mock_node1, mock_node2,
                                mock_net1, mock_net2, mock_net3]

        TestDhcpservicePlugin._set_state_initial(items_for_state_mgmt)
        for item in items_for_state_mgmt:
            if item.item_type_id in ['dhcp-subnet']:
                item.has_removed_dependencies=lambda: False
                item.has_updated_dependencies=lambda: False
                item.has_initial_dependencies=lambda: False

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1, mock_node2]
            elif 'network' == query_item_type and kwargs:
                return [mock_net3]
            elif 'network' == query_item_type:
                return [mock_net1, mock_net2]

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)

#       for t in tasks:
#           print t.description

        expected = [
            ConfigTask(mock_node1, svc1,
                       'Configure "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       domainsearch=['test1.com', 'test2.com'],
                       peer_address=mock_if2.ipaddress,
                       interfaces=[mock_if3.device_name],
                       role='primary',
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       address=mock_if1.ipaddress),
            ConfigTask(mock_node1, dhcp_subnet1,
                       'Configure "dhcp-subnet" and "dhcp-range" on network "%s" on node "%s"' % (mock_if3.network_name, mock_node1.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet1),
                       ranges=['10.0.0.1 11.0.0.1', '20.0.0.1 21.0.0.1'],
                       mask='255.255.255.0',
                       network='192.10.10.0',
                       failover='true'),
            ConfigTask(mock_node1, dhcp_subnet2,
                       'Configure "dhcp-subnet" and "dhcp-range" on network "%s" on node "%s"' % (mock_if4.network_name, mock_node1.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet2),
                       ranges=['10.0.0.1 11.0.0.1', '20.0.0.1 21.0.0.1'],
                       mask='255.255.255.0',
                       network='10.10.10.0',
                       failover='true'),
            ConfigTask(mock_node2, svc2,
                       'Configure "dhcp-service" "%s" on node "%s"' % (svc2.service_name, mock_node2.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc2),
                       peer_address=mock_if1.ipaddress,
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       interfaces=[mock_if4.device_name],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='secondary',
                       address=mock_if2.ipaddress),
            ConfigTask(mock_node2, dhcp_subnet1,
                       'Configure "dhcp-subnet" and "dhcp-range" on network "%s" on node "%s"' % (mock_if3.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet1),
                       ranges=['10.0.0.1 11.0.0.1', '20.0.0.1 21.0.0.1'],
                       mask='255.255.255.0',
                       network='192.10.10.0',
                       failover='true'),
            ConfigTask(mock_node2, dhcp_subnet2,
                       'Configure "dhcp-subnet" and "dhcp-range" on network "%s" on node "%s"' % (mock_if4.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet2),
                       ranges=['10.0.0.1 11.0.0.1', '20.0.0.1 21.0.0.1'],
                       mask='255.255.255.0',
                       network='10.10.10.0',
                       failover='true'),
            ConfigTask(mock_node1, svc3,
                       'Configure "dhcp6-service" "%s" on node "%s"' % (svc3.service_name, mock_node1.hostname),
                       'dhcpservice::config_server6',
                       self.plugin._gen_service_call_id(svc3),
                       interfaces=[mock_if6.device_name],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='primary'),
            ConfigTask(mock_node1, dhcp_subnet3,
                       'Configure "dhcp6-subnet" and "dhcp6-range" on network "%s" on node "%s"' % (mock_if7.network_name, mock_node1.hostname),
                       'dhcpservice::config_pool6',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet3),
                       ranges=['fc01::10 fc01::15'],
                       network='fc01::/64'),
            ConfigTask(mock_node2, svc4,
                       'Configure "dhcp6-service" "%s" on node "%s"' % (svc4.service_name, mock_node2.hostname),
                       'dhcpservice::config_server6',
                       self.plugin._gen_service_call_id(svc4),
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       interfaces=[mock_if7.device_name],
                       role='secondary'),
            ConfigTask(mock_node2, dhcp_subnet3,
                       'Configure "dhcp6-subnet" and "dhcp6-range" on network "%s" on node "%s"' % (mock_if7.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool6',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet3),
                       ranges=['fc01::10 fc01::15'],
                       network='fc01::/64')
        ]

        self.assertEquals(10, len(tasks))
        self.assertEquals(set(expected), set(tasks))

        # ----

        TestDhcpservicePlugin._set_state_applied(items_for_state_mgmt)

        svc1.applied_properties = {'primary': 'true'}
        svc1.primary = 'false'

        svc2.applied_properties = {'primary': 'false'}
        svc2.primary = 'true'

        TestDhcpservicePlugin._set_state_updated([svc1, svc2])

        updated_tasks = self.plugin.create_configuration(context)

        expected_tasks = [
            ConfigTask(mock_node1, svc1,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       domainsearch=['test1.com', 'test2.com'],
                       peer_address=mock_if2.ipaddress,
                       interfaces=[mock_if3.device_name],
                       role='secondary',
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       address=mock_if1.ipaddress),
            ConfigTask(mock_node2, svc2,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node2.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc2),
                       peer_address=mock_if1.ipaddress,
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       interfaces=[mock_if4.device_name],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='primary',
                       address=mock_if2.ipaddress)
            ]

        self.assertEquals(2, len(updated_tasks))
        self.assertEquals(set(expected_tasks), set(updated_tasks))

        TestDhcpservicePlugin._set_state_applied([svc1, svc2, svc3, svc4])

        svc1.applied_properties = {'primary': 'false'}
        svc2.applied_properties = {'primary': 'true'}
        # ----

        mock_if3.ipaddress = '30.0.0.5'
        mock_if3.applied_properties = {'network_name': mock_if3.network_name}
        mock_if3.network_name = 'someelse'

        mock_if5.ipaddress = '10.0.0.5'
        mock_if5.applied_properties = {'network_name': mock_if5.network_name}
        mock_if5.network_name = 'storage'

        TestDhcpservicePlugin._set_state_updated([mock_if3, mock_if5])

        updated_tasks = self.plugin.create_configuration(context)

        expected_tasks = [
            ConfigTask(mock_node1, svc1,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       interfaces=[mock_if5.device_name],
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='secondary',
                       address=mock_if1.ipaddress,
                       peer_address=mock_if2.ipaddress)
        ]

        #self.assertEquals(1, len(updated_tasks))
        self.assertEquals(set(expected_tasks), set(updated_tasks))

        TestDhcpservicePlugin._set_state_applied([mock_if3, mock_if5])

        # ---

        mock_bond = DhcpMock(item_id='b1',
                             item_type_id='bond',
                             device_name='bond0',
                             network_name=mock_if5.network_name,
                             ipaddress='10.0.0.5')

        mock_node1.network_interfaces=[mock_if1, mock_if3, mock_if5, mock_bond]
        TestDhcpservicePlugin._set_state_initial([mock_bond])

        mock_if5.ipaddress = None
        mock_if5.applied_properties = {'network_name': mock_if5.network_name}
        mock_if5.network_name = 'new-value'
        TestDhcpservicePlugin._set_state_updated([mock_if5])

        expected_tasks = [
            ConfigTask(mock_node1, svc1,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       interfaces=[mock_bond.device_name],
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='secondary',
                       address=mock_if1.ipaddress,
                       peer_address=mock_if2.ipaddress)
        ]

        updated_tasks = self.plugin.create_configuration(context)
        self.assertEquals(expected_tasks, updated_tasks)

        # ---

        TestDhcpservicePlugin._set_state_for_removal([mock_bond])

        mock_if5.network_name = mock_if5.applied_properties['network_name']
        mock_if5.ipaddress = '10.0.0.5'
        mock_if5.applied_properties = {'network_name': 'data'}

        expected_tasks = [
            ConfigTask(mock_node1, svc1,
                       'Update "dhcp-service" "%s" on node "%s"' % (svc1.service_name, mock_node1.hostname),
                       'dhcpservice::config_server',
                       self.plugin._gen_service_call_id(svc1),
                       interfaces=[mock_if5.device_name],
                       ntpservers=['server 0.ie.pool.ntp.org', '10.44.86.30'],
                       domainsearch=['test1.com', 'test2.com'],
                       nameservers=['1.2.3.1', '10.44.86.35'],
                       default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                       max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                       role='secondary',
                       address=mock_if1.ipaddress,
                       peer_address=mock_if2.ipaddress)
        ]

        updated_tasks = self.plugin.create_configuration(context)
        self.assertEquals(expected_tasks, updated_tasks)

        TestDhcpservicePlugin._set_state_applied([mock_if5, mock_bond])

        #---
        #Adding a range and updating another range of the same subnet
        #should result in only one pool task
        range4 = DhcpMock(item_id='r4',
                          item_type_id='dhcp-range',
                          start='20.0.0.10',
                          end='21.0.0.10')

        TestDhcpservicePlugin._set_state_initial([range4])

        dhcp_subnet1.ranges.append(range4)

        TestDhcpservicePlugin._set_state_updated([range1])

        dhcp_subnet1.network_name = 'storage'
        dhcp_subnet2.network_name = 'backup'

        updated_tasks = self.plugin.create_configuration(context)

        expected_tasks = [
        ConfigTask(mock_node1, dhcp_subnet1,
                       'Update "dhcp-subnet", update "dhcp-range" "%s", add "dhcp-range" "%s" on network "%s" on node "%s"' % (range1.item_id, range4.item_id, dhcp_subnet1.network_name, mock_node1.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet1),
                       ranges=['10.0.0.1 11.0.0.1',
                               '20.0.0.1 21.0.0.1',
                               '20.0.0.10 21.0.0.10'],
                       mask='255.255.255.0',
                       network='192.10.10.0',
                       failover='true'),
            ConfigTask(mock_node1, dhcp_subnet2,
                       'Update "dhcp-subnet", update "dhcp-range" "%s" on network "%s" on node "%s"' % (range1.item_id, dhcp_subnet2.network_name, mock_node1.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet2),
                       ranges=['10.0.0.1 11.0.0.1', '20.0.0.1 21.0.0.1'],
                       mask='255.255.255.0',
                       network='10.10.10.0',
                       failover='true'),
            ConfigTask(mock_node2, dhcp_subnet1,
                       'Update "dhcp-subnet", update "dhcp-range" "%s", add "dhcp-range" "%s" on network "%s" on node "%s"' % (range1.item_id, range4.item_id, dhcp_subnet1.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet1),
                       ranges=['10.0.0.1 11.0.0.1',
                               '20.0.0.1 21.0.0.1',
                               '20.0.0.10 21.0.0.10'],
                       mask='255.255.255.0',
                       network='192.10.10.0',
                       failover='true'),
            ConfigTask(mock_node2, dhcp_subnet2,
                       'Update "dhcp-subnet", update "dhcp-range" "%s" on network "%s" on node "%s"' % (range1.item_id, dhcp_subnet2.network_name, mock_node2.hostname),
                       'dhcpservice::config_pool',
                       DhcpservicePlugin._gen_hash_path(dhcp_subnet2),
                       ranges=['10.0.0.1 11.0.0.1', '20.0.0.1 21.0.0.1'],
                       mask='255.255.255.0',
                       network='10.10.10.0',
                       failover='true'),
        ]
        self.assertEquals(set(expected_tasks), set(updated_tasks))

    def test_get_dhcp_interfaces(self):
        mock_if1 = DhcpMock(item_id='if1',
                            item_type_id='eth',
                            device_name='eth1',
                            network_name='net1',
                            ipaddress='192.168.0.42')

        mock_if2 = DhcpMock(item_id='if2',
                            item_type_id='eth',
                            device_name='eth2',
                            network_name='net2',
                            ipaddress='10.10.0.1')

        subnet1 = DhcpMock(item_id='sub1',
                           item_type_id='dhcp-subnet',
                           network_name=mock_if1.network_name)
        subnet2 = DhcpMock(item_id='sub2',
                           item_type_id='dhcp-subnet',
                           network_name=mock_if2.network_name)

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',
                        subnets=[subnet1, subnet2])

        mock_node = DhcpMock(item_id='n1',
                             item_type_id='node',
                             hostname = 'mn1',
                             query=lambda x: [svc1],
                             network_interfaces=[mock_if1, mock_if2])

        TestDhcpservicePlugin._set_state_initial([mock_if1, mock_if2, subnet1, subnet2, svc1, mock_node])

        dhcp_interfaces = self.plugin._get_current_dhcp_interfaces(mock_node, svc1)

        expected_outcome = [mock_if1, mock_if2]

        self.assertEquals(expected_outcome, dhcp_interfaces)

        # ----
        bond = DhcpMock(item_id='b0',
                        item_type_id='bond',
                        miimon='100',
                        mode='5',
                        network_name='net1',
                        ipaddress='192.168.0.42',
                        device_name='bond0')

        TestDhcpservicePlugin._set_state_initial([bond])

        mock_if1 = DhcpMock(item_id='if1',
                            item_type_id='eth',
                            device_name='eth1',
                            master=bond.device_name)

        mock_if2 = DhcpMock(item_id='if2',
                            item_type_id='eth',
                            device_name='eth2',
                            master=bond.device_name)

        TestDhcpservicePlugin._set_state_updated([mock_if1, mock_if2])

        mock_node.network_interfaces=[mock_if1, mock_if2, bond]

        dhcp_interfaces = self.plugin._get_current_dhcp_interfaces(mock_node, svc1)

        expected_outcome = [bond]

        self.assertEquals(expected_outcome, dhcp_interfaces)

    def test_get_failover_arguments(self):
        mock_if1 = DhcpMock(item_id='if1',
                            item_type_id='eth',
                            device_name='eth1',
                            network_name='mgmt',
                            ipaddress='192.168.0.42')

        mock_if2 = DhcpMock(item_id='if2',
                            item_type_id='eth',
                            device_name='eth2',
                            network_name=mock_if1.network_name,
                            ipaddress='192.168.0.43')

        mock_if3 = DhcpMock(item_id='if3',
                            item_type_id='eth',
                            device_name='eth3',
                            network_name='net1',
                            ipaddress='192.168.0.43')

        mock_if4 = DhcpMock(item_id='if4',
                            item_type_id='eth',
                            device_name='eth4',
                            network_name='net2',
                            ipaddress='192.168.0.43')

        subnet1 = DhcpMock(item_id='sub1',
                           item_type_id='dhcp-subnet',
                           network_name=mock_if3.network_name)
        subnet2 = DhcpMock(item_id='sub2',
                           item_type_id='dhcp-subnet',
                           network_name=mock_if4.network_name)

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',
                        service_name='dhcp_svc1',
                        primary='true',
                        ntpservers='server 0.ie.pool.ntp.org, 10.44.86.30',
                        domainsearch='test1.com, test2.com',
                        nameservers='1.2.3.1, 10.44.86.35',
                        subnets=[subnet1, subnet2])

        svc2 = DhcpMock(item_id='svc2',
                        item_type_id='dhcp-service',
                        service_name='dhcp_svc1',
                        primary='false',
                        ntpservers='server 0.ie.pool.ntp.org, 10.44.86.30',
                        domainsearch='test1.com, test2.com',
                        nameservers='1.2.3.1, 10.44.86.35',
                        subnets=[subnet1, subnet2])

        mock_node1 = DhcpMock(item_id='node1',
                              item_type_id='node',
                              hostname = 'mn1',
                              network_interfaces=[mock_if1, mock_if3],
                              query=lambda x: [svc1])

        mock_node2 = DhcpMock(item_id='node2',
                              item_type_id='node',
                              hostname = 'mn2',
                              network_interfaces=[mock_if2, mock_if4],
                              query=lambda x: [svc2])

        mock_net1 = DhcpMock(item_id='net1',
                             item_type_id='network',
                             litp_management='true',
                             subnet1='10.10.10.0/24')
        mock_net1.name = mock_if1.network_name

        items = [mock_if1, mock_if2, mock_if3, mock_if4,
                 subnet1, subnet2, svc1, svc2,
                 mock_node1, mock_node2, mock_net1]
        TestDhcpservicePlugin._set_state_initial(items)

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1, mock_node2]
            elif 'network' == query_item_type:
                return [mock_net1]

        peer_nodes = [mock_node1, mock_node2]

        context = Mock(query=_mock_context_query)

        failover_kw = self.plugin._get_dhcp_config_args(peer_nodes,
                                                        context, mock_node1, svc1)

        expected_outcome = dict(role = 'primary',
                                ntpservers=['server 0.ie.pool.ntp.org',
                                            '10.44.86.30'],
                                nameservers=['1.2.3.1', '10.44.86.35'],
                                domainsearch=['test1.com', 'test2.com'],
                                address=mock_if1.ipaddress,
                                peer_address=mock_if2.ipaddress,
                                default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                                max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                                interfaces=[mock_if3.device_name])

        self.assertEquals(expected_outcome, failover_kw)

        failover_kw = self.plugin._get_dhcp_config_args(peer_nodes,
                                                        context, mock_node2, svc2)

        expected_outcome = dict(role = 'secondary',
                                ntpservers=['server 0.ie.pool.ntp.org',
                                            '10.44.86.30'],
                                nameservers=['1.2.3.1', '10.44.86.35'],
                                domainsearch=['test1.com', 'test2.com'],
                                address=mock_if2.ipaddress,
                                peer_address=mock_if1.ipaddress,
                                default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                                max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                                interfaces=[mock_if4.device_name])

        self.assertEquals(expected_outcome, failover_kw)

    def test_create_configuration(self):
        self.setup_model()
        # Invoke plugin's methods to run test cases
        # and assert expected output.
        tasks = self.plugin.create_configuration(self)
        self.assertEqual(0, len(tasks))

    def test_removal_tasks(self):

        subnet1 = DhcpMock(item_id='sub1',
                           item_type_id='dhcp-subnet',
                           network_name='storage')

        service1 = DhcpMock(item_id='svc1',
                            item_type_id='dhcp-service',
                            service_name='dhcp_svc1',
                            subnets=[subnet1])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [service1]
            elif 'dhcp6-service' == query_item_type:
                return []

        node1 = DhcpMock(item_id='n1',
                         item_type_id='node',
                         hostname='mn1',
                         query=_node_dhcp_service_query)
        context = Mock(query=lambda x: [node1])

        TestDhcpservicePlugin._set_state_initial([node1, service1, subnet1])

        tasks = self.plugin._removal_tasks(context)
        self.assertEquals([], tasks)

        # ----
        TestDhcpservicePlugin._set_state_for_removal([subnet1])

        expected = [ConfigTask(node1, subnet1,
                               'Deconfigure "dhcp-subnet" "sub1" on node "mn1"',
                               'dhcpservice::config_pool',
                               DhcpservicePlugin._gen_hash_path(subnet1),
                               ensure="absent")]

        tasks = self.plugin._removal_tasks(context)
        self.assertEquals(expected, tasks)

        # Restore states for next test
        TestDhcpservicePlugin._set_state_initial([subnet1])

        # ---

        TestDhcpservicePlugin._set_state_for_removal([service1])

        expected = [ConfigTask(node1, service1,
                               'Deconfigure "dhcp-service" "dhcp_svc1" on node "mn1"',
                               'dhcpservice::config_server',
                               self.plugin._gen_service_call_id(service1),
                               ensure='absent')]

        tasks = self.plugin._removal_tasks(context)
        self.assertEquals(expected, tasks)

    # -----------
    def test_validate_service_not_on_ms(self):
        svc = DhcpMock(item_id='svc',
                       item_type_id='dhcp-service')

        ms1 = DhcpMock(item_id='ms1',
                       item_type_id='ms',
                       query=lambda x : [svc],
                       hostname='ms1')

        TestDhcpservicePlugin._set_state_initial([svc, ms1])
        errors = DhcpservicePlugin._validate_service_not_on_ms([ms1])

        emsg = 'DHCP services may not be deployed on the Management Server "%s"' % ms1.hostname
        expected_errors = [ValidationError(item_path=ms1.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---
        ms1.query = lambda x : []
        errors = DhcpservicePlugin._validate_service_not_on_ms([ms1])
        self.assertEqual([], errors)

    def test_validate_service_names_unique(self):
        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',
                        service_name='svc1')

        # Duplicate service name
        svc2 = DhcpMock(item_id='svc2',
                        item_type_id='dhcp-service',
                        service_name=svc1.service_name)

        svc3 = DhcpMock(item_id='svc3',
                        item_type_id='dhcp6-service',
                        service_name='svc3')

        TestDhcpservicePlugin._set_state_initial([svc1, svc2, svc3])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1, svc2]
            elif 'dhcp6-service' == query_item_type:
                return [svc3]

        context = Mock(query=_node_dhcp_service_query)

        errors = DhcpservicePlugin._validate_service_names_unique(context)

        appendage = ' is not unique across all deployments'

        emsg = 'dhcp-service name "svc1"' + appendage
        expected_errors = [ValidationError(item_path=svc1.get_vpath(),
                                           error_message=emsg),
                           ValidationError(item_path=svc2.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---
        svc2.service_name = 'something_unique'
        errors = DhcpservicePlugin._validate_service_names_unique(context)
        self.assertEqual([], errors)

        # ---
        svc2.service_name = 'svc3'
        errors = DhcpservicePlugin._validate_service_names_unique(context)

        suffix = ' name "svc3"' + appendage

        emsg4 = 'dhcp-service' + suffix
        emsg6 = 'dhcp6-service' + suffix

        expected_errors = [ValidationError(item_path=svc2.get_vpath(),
                                           error_message=emsg4),
                           ValidationError(item_path=svc3.get_vpath(),
                                           error_message=emsg6)]
        self.assertEqual(expected_errors, errors)

    def test_validate_mgmt_net_not_used(self):
        mgmt_net_name = 'mgmt'

        mgmt_net = DhcpMock(item_id='net1',
                            item_type_id='network')
        mgmt_net.name = mgmt_net_name

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name=mgmt_net_name)

        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                    item_type_id='node',
                    hostname = 'mn1',
                    query=_node_dhcp_service_query)

        TestDhcpservicePlugin._set_state_initial([mgmt_net, subnet, svc, node])

        errors = DhcpservicePlugin._validate_mgmt_net_not_used(node, mgmt_net)

        suffix = ' must not reference the management network "%s"' % mgmt_net_name

        emsg = '"dhcp-subnet"' + suffix
        expected_errors = [ValidationError(item_path=subnet.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---
        subnet.network_name = 'another_net'
        errors = DhcpservicePlugin._validate_mgmt_net_not_used(node, mgmt_net)
        self.assertEqual([], errors)

        # ---

        subnet_v6 = DhcpMock(item_id='sub6',
                             item_type_id='dhcp6-subnet',
                             network_name=mgmt_net_name)

        svc_v6 = DhcpMock(item_id='svc6',
                          item_type_id='dhcp6-service',
                          subnets=[subnet_v6])

        TestDhcpservicePlugin._set_state_initial([subnet_v6, svc_v6])

        def _node_dhcp6_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return []
            elif 'dhcp6-service' == query_item_type:
                return [svc_v6]

        node.query = _node_dhcp6_service_query

        errors = DhcpservicePlugin._validate_mgmt_net_not_used(node, mgmt_net)

        emsg = '"dhcp6-subnet"' + suffix

        expected_errors = [ValidationError(item_path=subnet_v6.get_vpath(),
                                           error_message=emsg)]

        self.assertEqual(expected_errors, errors)

    def test_validate_interface_has_ip_address(self):
        nic1 = DhcpMock(item_id='if1',
                        item_type_id='eth',
                        network_name='storage',
                        ipaddress=None,
                        ipv6address=None)

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name=nic1.network_name)

        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        network_interfaces = [nic1],
                        query=_node_dhcp_service_query)

        TestDhcpservicePlugin._set_state_initial([nic1, subnet, svc, node])

        errors = DhcpservicePlugin._validate_interface_has_ip_addr(node)

        emsg = ('A network interface that references '
                'a network that is also referenced by a "dhcp-subnet", '
                'must have an IPv4 address defined')

        expected_errors = [ValidationError(item_path=nic1.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---
        subnet_v6 = DhcpMock(item_id='sub6',
                             item_type_id='dhcp6-subnet',
                             network_name='storage')

        svc_v6 = DhcpMock(item_id='svc6',
                          item_type_id='dhcp6-service',
                          subnets=[subnet_v6])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return []
            elif 'dhcp6-service' == query_item_type:
                return [svc_v6]

        node.network_interfaces = [nic1]
        node.query = _node_dhcp_service_query

        TestDhcpservicePlugin._set_state_initial([subnet_v6, svc_v6])

        all_nodes = [node]

        errors = DhcpservicePlugin._validate_interface_has_ip_addr(node)

        emsg = ('A network interface that references '
                'a network that is also referenced by a "dhcp6-subnet", '
                'must have an IPv6 address defined')

        expected_errors = [ValidationError(item_path=nic1.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # d_NIC_validation - ensure validation does not run
        # when NIC is for removal
        TestDhcpservicePlugin._set_state_for_removal([nic1])
        errors = DhcpservicePlugin._validate_interface_has_ip_addr(node)
        expected_errors = [ValidationError(item_path=nic1.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual([], errors)

    def test__validate_subnet_networks_valid(self):
        nic1 = DhcpMock(item_id='if1',
                        item_type_id='eth',
                        network_name = 'data1')
        nic2 = DhcpMock(item_id='if2',
                        item_type_id='eth',
                        network_name = 'data2')

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name='storage')

        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        network_interfaces = [nic1, nic2],
                        query=_node_dhcp_service_query)

        TestDhcpservicePlugin._set_state_initial([nic1, nic2, subnet, svc, node])

        errors = DhcpservicePlugin._validate_subnet_networks_valid(node, None)

        emsg = 'The network "storage" referenced by "dhcp-subnet" is not '\
               'configured on node "mn1"'
        expected_errors = [ValidationError(item_path=subnet.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        nic3 = DhcpMock(item_id='if3',
                        item_type_id='eth',
                        network_name = subnet.network_name)
        node.network_interfaces.append(nic3)

        net1 = DhcpMock(item_id='net1',
                        item_type_id='network',
                        subnet = None)
        net1.name = 'somethingelse1'

        net2 = DhcpMock(item_id='net2',
                        item_type_id='network',
                        subnet = None)
        net2.name = 'somethingelse2'

        net3 = DhcpMock(item_id='net3',
                        item_type_id='network',
                        subnet = None)
        net3.name = subnet.network_name

        networks = [net1, net2, net3]

        TestDhcpservicePlugin._set_state_initial([nic3, net1, net2, net3])

        errors = DhcpservicePlugin._validate_subnet_networks_valid(node, networks)

        emsg = 'Network "%s" does not have a subnet specified' % subnet.network_name
        expected_errors = [ValidationError(item_path=subnet.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        net3.subnet = '1.2.3.4/24'
        errors = DhcpservicePlugin._validate_subnet_networks_valid(node,
                                                                  networks)
        self.assertEqual([], errors)

        # ---
        subnet_v6 = DhcpMock(item_id='sub6',
                             item_type_id='dhcp6-subnet',
                             network_name='ipv6')

        svc_v6 = DhcpMock(item_id='svc6',
                          item_type_id='dhcp6-service',
                          subnets=[subnet_v6])

        def _node_dhcp6_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return []
            elif 'dhcp6-service' == query_item_type:
                return [svc_v6]

        node.query = _node_dhcp6_service_query

        TestDhcpservicePlugin._set_state_initial([subnet_v6, svc_v6])

        errors = DhcpservicePlugin._validate_subnet_networks_valid(node, None)

        emsg = ('The network "%s" referenced by "dhcp6-subnet" is not ' + \
                'configured on node "mn1"') % subnet_v6.network_name
        expected_errors = [ValidationError(item_path=subnet_v6.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---
        net4 = DhcpMock(item_id='net4',
                        item_type_id='network',
                        subnet = None)
        net4.name = 'ipv6'
        networks.append(net4)

        nic4 = DhcpMock(item_id='if4',
                        item_type_id='eth',
                        network_name = 'ipv6')
        node.network_interfaces.append(nic4)

        TestDhcpservicePlugin._set_state_initial([net4, nic4])

        errors = DhcpservicePlugin._validate_subnet_networks_valid(node, networks)

        self.assertEqual([], errors)

        # LITPCDS-10926 - throw expanded Validation Error if NIC
        # referencing subnet is for removal
        TestDhcpservicePlugin._set_state_for_removal([nic4])

        msg = 'The network "{0}" referenced by "dhcp6-subnet" is not ' \
              'configured on node "{1}" due to removal of "{2}" "{3}"'
        msg = msg.format(subnet_v6.network_name, node.hostname,
                         nic4.item_type_id, nic4.get_vpath())

        expected = ValidationError(item_path=subnet_v6.get_vpath(),
                                           error_message=msg)
        
        
        errors = DhcpservicePlugin._validate_subnet_networks_valid(node,networks)
        self.assertEqual([expected], errors)


    def test_validate_subnet_network_unique(self):

        network_name = 'storage'

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name=network_name)
        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        query=_node_dhcp_service_query)

        TestDhcpservicePlugin._set_state_initial([subnet, svc, node])

        subnet_netname_pair = (network_name, subnet.item_type_id)

        DhcpservicePlugin._all_net_names = staticmethod(lambda x,y,z: [subnet_netname_pair, subnet_netname_pair])

        errors = DhcpservicePlugin._validate_subnet_network_unique(node, None)

        emsg = 'Network "storage" may be referenced by at most one "dhcp-subnet" ' \
               'and at most one "dhcp6-subnet"'
        expected_errors = [ValidationError(item_path=subnet.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        DhcpservicePlugin._all_net_names = staticmethod(lambda x,y,z: [subnet_netname_pair])
        errors = DhcpservicePlugin._validate_subnet_network_unique(node, None)
        self.assertEqual([], errors)

        # ---

        subnet_v6 = DhcpMock(item_id='sub6',
                             item_type_id='dhcp6-subnet',
                             network_name=network_name)

        svc_v6 = DhcpMock(item_id='svc6',
                          item_type_id='dhcp6-service',
                          subnets=[subnet_v6])

        def _node_dhcp6_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return [svc_v6]

        TestDhcpservicePlugin._set_state_initial([subnet_v6, svc_v6])

        node.query = _node_dhcp6_service_query

        subnet_netname_pair_v6 = (network_name, subnet_v6.item_type_id)

        DhcpservicePlugin._all_net_names = staticmethod(lambda x,y,z: [subnet_netname_pair_v6, subnet_netname_pair])

        errors = DhcpservicePlugin._validate_subnet_network_unique(node, None)

        self.assertEqual([], errors)

        # ---
        node.query = _node_dhcp_service_query

        DhcpservicePlugin._all_net_names = staticmethod(lambda x,y,z: [subnet_netname_pair_v6, subnet_netname_pair_v6])

        errors = DhcpservicePlugin._validate_subnet_network_unique(node, None)

        self.assertEqual(expected_errors, errors)

    def test_validate_ranges_in_networks(self):
        network = DhcpMock(item_id='net1',
                           item_type_id='network',
                           subnet='10.0.0.0/24')
        network.name = 'storage'

        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp-range',
                          start='10.0.0.1',
                          end='11.0.0.1')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name='storage',
                          ranges=[range1])
        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        query=lambda x: [svc])

        TestDhcpservicePlugin._set_state_initial([network, range1, subnet, svc, node])

        networks = [network]
        errors = DhcpservicePlugin._validate_ranges_in_networks(node, networks)

        suffix = ' is not valid for network "%s"' % network.name
        emsg = '"end" address "11.0.0.1"' + suffix
        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        range1.start = '11.0.0.1'
        range1.end = '10.0.0.1'

        errors = DhcpservicePlugin._validate_ranges_in_networks(node, networks)

        emsg = '"start" address "11.0.0.1"' + suffix
        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        #---
        range1.start = '11.0.0.1'
        range1.end = '12.0.0.1'

        errors = DhcpservicePlugin._validate_ranges_in_networks(node, networks)

        emsg1 = '"start" address "11.0.0.1"' + suffix
        emsg2 = '"end" address "12.0.0.1"' + suffix
        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg1),
                           ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg2)]
        self.assertEqual(expected_errors, errors)

        # ---
        range1.start = '10.0.0.1'
        range1.end = '10.0.0.5'

        errors = DhcpservicePlugin._validate_ranges_in_networks(node, networks)
        self.assertEqual([], errors)

    def test_validate_no_range_overlaps(self):
        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp-range',
                          start='10.0.0.1',
                          end='10.0.0.5')

        range2 = DhcpMock(item_id='r2',
                          item_type_id='dhcp-range',
                          start='10.0.0.3',
                          end='10.0.0.7')

        range3 = DhcpMock(item_id='r3',
                          item_type_id='dhcp-range',
                          start='10.0.0.6',
                          end='10.0.0.8')

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name='the-dhcp-network',
                          ranges=[range1, range2, range3])
        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        query=_node_dhcp_service_query)

        TestDhcpservicePlugin._set_state_initial([range1, range2, range3, subnet, svc, node])

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        prefix = 'dhcp-range overlaps with'
        emsg1 = '%s "%s"' % (prefix, range2.get_vpath())
        emsg2 = '%s "%s"' % (prefix, range3.get_vpath())
        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg1),
                           ValidationError(item_path=range2.get_vpath(),
                                           error_message=emsg2)]
        self.assertEqual(expected_errors, errors)

        # ---

        range3.start = '10.0.0.86'
        range3.end = '10.0.0.88'

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg1)]
        self.assertEqual(expected_errors, errors)

        # ---

        range2.start = '10.0.0.33'
        range2.end = '10.0.0.37'

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        self.assertEqual([], errors)

    def test_validate_no_v6_range_overlaps(self):
        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp-range',
                          start='2001:db8::1',
                          end='2001:db8::5')

        range2 = DhcpMock(item_id='r2',
                          item_type_id='dhcp-range',
                          start='2001:db8::4',
                          end='2001:db8::9')

        range3 = DhcpMock(item_id='r3',
                          item_type_id='dhcp-range',
                          start='2001:db8::8',
                          end='2001:db8::20')

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name='the-dhcp-network',
                          ranges=[range1, range2, range3])
        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       subnets=[subnet])

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return []
            elif 'dhcp6-service' == query_item_type:
                return [svc]

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname='mn1',
                        query=_node_dhcp_service_query)

        TestDhcpservicePlugin._set_state_initial([range1, range2, range3, subnet, svc, node])

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        prefix = 'dhcp-range overlaps with'
        emsg1 = '%s "%s"' % (prefix, range2.get_vpath())
        emsg2 = '%s "%s"' % (prefix, range3.get_vpath())
        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg1),
                           ValidationError(item_path=range2.get_vpath(),
                                           error_message=emsg2)]
        self.assertEqual(expected_errors, errors)

        # ---

        range3.start = '2001:db8::11'

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        expected_errors = [ValidationError(item_path=range1.get_vpath(),
                                           error_message=emsg1)]
        self.assertEqual(expected_errors, errors)

        # ---

        range2.start = '2001:db8::6'

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        self.assertEqual([], errors)

        # ---

        range2.end = '2001:db8::6'

        errors = DhcpservicePlugin._validate_no_range_overlaps(node)

        self.assertEqual([], errors)

    def test_validate_node_service_count(self):

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',)
        svc2 = DhcpMock(item_id='svc2',
                        item_type_id='dhcp-service',)
        svc3 = DhcpMock(item_id='svc3',
                        item_type_id='dhcp6-service')

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1, svc2]
            elif 'dhcp6-service' == query_item_type:
                return [svc3]
            else:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        query=_node_dhcp_service_query)

        service_fake_path = '/x/y/z'
        node.services.get_vpath = lambda: service_fake_path

        TestDhcpservicePlugin._set_state_initial([svc1, svc2, svc3, node])

        errors = DhcpservicePlugin._validate_node_service_count(node)

        emsg = 'Node "mn1" must have at most one dhcp-service'

        expected_errors = [ValidationError(item_path=service_fake_path,
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---
        svc4 = DhcpMock(item_id='svc4',
                        item_type_id='dhcp6-service')

        def _node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1, svc2]
            elif 'dhcp6-service' == query_item_type:
                return [svc3, svc4]
            else:
                return []

        TestDhcpservicePlugin._set_state_initial([svc4])

        node.query = _node_dhcp_service_query

        errors = DhcpservicePlugin._validate_node_service_count(node)

        prefix = 'Node "mn1" must have at most one '
        emsg4 = prefix + 'dhcp-service'
        emsg6 = prefix + 'dhcp6-service'

        expected_errors = [ValidationError(item_path=service_fake_path,
                                           error_message=emsg4),
                           ValidationError(item_path=service_fake_path,
                                           error_message=emsg6)]
        self.assertEqual(expected_errors, errors)

    def test_validate_service_pairs(self):
        svc1_p = DhcpMock(item_id='svc1p',
                          item_type_id='dhcp-service',
                          primary='true',
                          service_name='svc1')
        svc1_s = DhcpMock(item_id='svc1s',
                          item_type_id='dhcp-service',
                          primary='false',
                          service_name='svc1')

        def _node_query_p (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1_p]
            else:
                return []

        def _node_query_s (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1_s]
            else:
                return []

        node1 = DhcpMock(item_id='n1',
                         item_type_id='node',
                         hostname = 'mn1',
                         query=_node_query_p)
        node1_dup = DhcpMock(item_id='n1d',
                             item_type_id='node',
                             hostname = 'mn1_dup',   # Duplicate of mn1
                             query=_node_query_p)
        node2 = DhcpMock(item_id='n2',
                         item_type_id='node',
                         hostname='mn2',
                         query=_node_query_s)
        node2_dup = DhcpMock(item_id='n2d',
                             item_type_id='node',
                             hostname = 'mn2_dup',   # Duplicate of mn2
                             query=_node_query_s)

        emsg = 'dhcp-service "svc1" must be deployed exactly once as primary and once as non-primary'

        TestDhcpservicePlugin._set_state_initial([svc1_p, svc1_s, node1, node1_dup, node2, node2_dup])

        # --- Primary tests ---

        errors = DhcpservicePlugin._validate_service_pairs(node1, [node1])

        self.assertEqual([], errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node1, [node1, node2])
        self.assertEqual([], errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node1,
                                                           [node1, node1_dup, node2])
        expected_errors = [ValidationError(item_path=svc1_p.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node1,
                                                    [node1, node2, node2_dup])
        expected_errors = [ValidationError(item_path=svc1_p.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # --- Non-Primary tests ---

        errors = DhcpservicePlugin._validate_service_pairs(node2, [node2])
        expected_errors = [ValidationError(item_path=svc1_s.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual([], errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node2,
                                                           [node1, node1_dup, node2])
        expected_errors = [ValidationError(item_path=svc1_s.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node2,
                                                           [node1, node2, node2_dup])
        expected_errors = [ValidationError(item_path=svc1_s.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

    def test_validate_service_pairs_v6(self):
        svc1_p = DhcpMock(item_id='svc1p',
                          item_type_id='dhcp6-service',
                          primary='true',
                          service_name='svc1')
        svc1_s = DhcpMock(item_id='svc1s',
                          item_type_id='dhcp6-service',
                          primary='false',
                          service_name='svc1')

        def _node_query_p (query_item_type, **kwargs):
            if 'dhcp6-service' == query_item_type:
                return [svc1_p]
            else:
                return []

        def _node_query_s (query_item_type, **kwargs):
            if 'dhcp6-service' == query_item_type:
                return [svc1_s]
            else:
                return []

        node1 = DhcpMock(item_id='n1',
                         item_type_id='node',
                         hostname = 'mn1',
                         query=_node_query_p)

        node1_dup = DhcpMock(item_id='n1d',
                             item_type_id='node',
                             hostname = 'mn1_dup',   # Duplicate of mn1
                             query=_node_query_p)
        node2 = DhcpMock(item_id='n2',
                         item_type_id='node',
                         hostname = 'mn2',
                         query=_node_query_s)
        node2_dup = DhcpMock(item_id='n2d',
                             item_type_id='node',
                             hostname = 'mn2_dup',   # Duplicate of mn2
                             query=_node_query_s)

        emsg = 'dhcp6-service "svc1" must be deployed exactly once as primary and once as non-primary'

        TestDhcpservicePlugin._set_state_initial([svc1_p, svc1_s, node1, node1_dup, node2, node2_dup])

        # --- Primary tests ---

        errors = DhcpservicePlugin._validate_service_pairs(node1, [node1])

        self.assertEqual([], errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node1,
                                                           [node1, node2])
        self.assertEqual([], errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node1,
                                                    [node1, node1_dup, node2])
        expected_errors = [ValidationError(item_path=svc1_p.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node1,
                                                    [node1, node2, node2_dup])
        expected_errors = [ValidationError(item_path=svc1_p.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # --- Non-Primary tests ---

        errors = DhcpservicePlugin._validate_service_pairs(node2, [node2])
        expected_errors = [ValidationError(item_path=svc1_s.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual([], errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node2,
                                                    [node1, node1_dup, node2])
        expected_errors = [ValidationError(item_path=svc1_s.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

        # ---

        errors = DhcpservicePlugin._validate_service_pairs(node2,
                                                    [node1, node2, node2_dup])
        expected_errors = [ValidationError(item_path=svc1_s.get_vpath(),
                                           error_message=emsg)]
        self.assertEqual(expected_errors, errors)

    def test_validate_static_ips(self):
        rng1 = DhcpMock(item_id='r1',
                        item_type_id='dhcp-range',
                        start='10.0.0.1',
                        end='10.0.0.3')
        rng2 = DhcpMock(item_id='r2',
                        item_type_id='dhcp-range',
                        start='10.0.0.5',
                        end='10.0.0.7')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name='storage',
                          ranges=[rng1, rng2])
        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp-service',
                       service_name='svc1',
                       primary='true',
                       subnets=[subnet])

        nic_1 = DhcpMock(item_id='if1',
                         item_type_id='eth',
                         network_name='storage',
                         ipaddress='10.0.0.6')
        nic_2 = DhcpMock(item_id='if2',
                         item_type_id='eth',
                         ipaddress='10.0.0.9')

        nic_3 = DhcpMock(item_id='if3',
                         item_type_id='eth',
                         ipaddress='11.0.0.1')
        nic_4 = DhcpMock(item_id='if4',
                         item_type_id='eth',
                         ipaddress='11.0.0.2')

        def node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        query=node_dhcp_service_query,
                        hostname="mn1")

        other_node = DhcpMock(item_id='n2',
                              item_type_id='node',
                              network_interfaces=[nic_1, nic_2],
                              query=lambda x :[])

        ms = DhcpMock(item_id='ms',
                      item_type_id='ms',
                      network_interfaces=[nic_3, nic_4],
                      hostname="ms1")

        items = [rng1, rng2, subnet, svc, node, nic_1, nic_2, other_node, nic_3, nic_4, ms]
        TestDhcpservicePlugin._set_state_initial(items)

        combined_nodes = [other_node] + [ms]

        errors = DhcpservicePlugin._validate_static_ips(node, combined_nodes)
        emsg = 'Static IPv4 address "10.0.0.6" lies within the dhcp-range "%s"' % rng2.get_vpath()
        expected_error = ValidationError(item_path=nic_1.get_vpath(),
                                         error_message=emsg)
        self.assertEqual([expected_error], errors)

        # ---

        nic_1.ipaddress = '10.0.0.8'
        errors = DhcpservicePlugin._validate_static_ips(node, combined_nodes)
        self.assertEqual([], errors)

    def test_validate_static_ipv6_ips(self):
        rng1 = DhcpMock(item_id='r1',
                        item_type_id='dhcp6-range',
                        start='2001:db8::1',
                        end='2001:db8::5')
        rng2 = DhcpMock(item_id='r2',
                        item_type_id='dhcp6-range',
                        start='2001:db8::4',
                        end='2001:db8::9')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp6-subnet',
                          network_name='storage',
                          ranges=[rng1, rng2])
        svc = DhcpMock(item_id='svc1',
                       item_type_id='dhcp6-service',
                       service_name='svc1',
                       primary='true',
                       subnets=[subnet])

        nic_1 = DhcpMock(item_id='if1',
                         item_type_id='eth',
                         network_name='storage',
                         ipv6address='2001:db8::6')
        nic_2 = DhcpMock(item_id='if2',
                         item_type_id='eth',
                         ipv6address='2001:db8::10')

        nic_3 = DhcpMock(item_id='if3',
                         item_type_id='eth',
                         ipv6address='2001:db9::1')
        nic_4 = DhcpMock(item_id='if4',
                         item_type_id='eth',
                         ipv6address='2001:db9::2')

        def node_dhcp_service_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return []
            elif 'dhcp6-service' == query_item_type:
                return [svc]

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        query=node_dhcp_service_query,
                        hostname="mn1")

        other_node = DhcpMock(item_id='n2',
                              item_type_id='node',
                              network_interfaces=[nic_1, nic_2],
                              query=lambda x :[])

        ms = DhcpMock(item_id='ms',
                      item_type_id='ms',
                      network_interfaces=[nic_3, nic_4],
                      hostname="mn1")

        items = [rng1, rng2, subnet, svc, node, nic_1, nic_2, other_node, nic_3, nic_4, ms]
        TestDhcpservicePlugin._set_state_initial(items)

        combined_nodes = [other_node] + [ms]

        errors = DhcpservicePlugin._validate_static_ips(node, combined_nodes)
        emsg = 'Static IPv6 address "2001:db8::6" lies within the dhcp6-range "%s"' % rng2.get_vpath()
        expected_error = ValidationError(item_path=nic_1.get_vpath(), error_message=emsg)
        self.assertEqual([expected_error], errors)

    def test_validate_model(self):

        (node1, node2) = self.setup_model()

        services_url = '/software/services/'
        a = self.model.create_item('dhcp-service',
                                   services_url + 's1',
                                   service_name='dhcp_svc1')

        b = self.model.create_item('dhcp-subnet',
                                   a.get_vpath() + '/subnets/s1',
                                   network_name='storage')

        c = self.model.create_item('dhcp-range',
                                   b.get_vpath() + '/ranges/r1',
                                   start='10.0.0.1',
                                   end='10.0.0.4')

        nets_url = '/infrastructure/networking/networks'

        d = self.model.create_item('network',
                                   nets_url + '/n1',
                                   name='data',
                                   subnet='11.0.0.0/24',
                                   litp_management='true')

        e = self.model.create_item('network',
                                   nets_url + '/n2',
                                   name='storage',
                                   subnet='10.0.0.0/24',
                                   litp_management='false')

        f = self.model.create_item('eth',
                                   node1.get_vpath() + '/network_interfaces/n1',
                                   macaddress='08:00:27:48:A8:B4',
                                   device_name='eth0',
                                   network_name='storage',
                                   ipaddress='10.10.10.10')

        g = self.model.create_item('eth',
                                   node2.get_vpath() + '/network_interfaces/n1',
                                   macaddress='08:00:27:65:C2:1E',
                                   device_name='eth0',
                                   network_name='storage',
                                   ipaddress='10.10.10.11')

        x = self.model.create_inherited(a.get_vpath(),
                                        node1.get_vpath() + '/services/s1')

        y = self.model.create_inherited(a.get_vpath(),
                                        node2.get_vpath() + '/services/s1',
                                        primary='false')

        for item in [a, b, c, d, e, f, g, x, y]:
            self.assertTrue(isinstance(item, ModelItem), item)

        errors = self.plugin.validate_model(self.context)
        self.assertEqual([], errors)

    def test_for_litpcds_8883(self):

        date_net1 = DhcpMock(item_id='net1',
                             item_type_id='network',
                             litp_management='false',
                             subnet='192.168.0.0/24')
        date_net1.name = 'data'

        data2_net = DhcpMock(item_id='net2',
                             item_type_id='network',
                             litp_management='false',
                             subnet='192.168.0.0/24')
        data2_net.name = 'second-data'

        mgmt_net = DhcpMock(item_id='net3',
                            item_type_id='network',
                            litp_management='true',
                            subnet='10.10.10.0/24')
        mgmt_net.name = 'mgmt'

        nic = DhcpMock(item_id='if1',
                       item_type_id='eth',
                       device_name='eth1',
                       network_name='data',
                       ipaddress='192.168.0.42',
                       ipv6address=None,
                       applied_properties={'network_name': 'data',
                                           'ipaddress': '192.168.0.42'}
                       )

        range = DhcpMock(item_id='r1',
                         item_type_id='dhcp-range',
                         start='10.0.0.1',
                         end='11.0.0.5')

        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name='data',
                          ranges=[range])

        service = DhcpMock(item_id='svc1',
                           item_type_id='dhcp-service',
                           ntpservers='',
                           domainsearch='',
                           nameservers='',
                           service_name='dhcp_serv1',
                           primary='true',
                           subnets=[subnet])

        def _mock_node_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [service]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        network_interfaces = [nic],
                        query=_mock_node_query)

        items = [mgmt_net, date_net1, data2_net, nic, range, subnet, service, node]
        TestDhcpservicePlugin._set_state_applied(items)

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [node]
            if 'network' == query_item_type and kwargs:
                return [mgmt_net]
            if 'network' == query_item_type:
                return [date_net1, data2_net]

        context = Mock(query=_mock_context_query)
        tasks = self.plugin.create_configuration(context)
        self.assertEqual([], tasks)

        # ----

        #Begin with just a NIC uodate
        nic.network_name = 'second-data'

        TestDhcpservicePlugin._set_state_updated([nic])

        tasks = self.plugin.create_configuration(context)
        self.assertEqual(1, len(tasks))

        # ----

        # Make the dhcp-{service,subnet,range} look Brand new
        # while the NIC update is still present
        TestDhcpservicePlugin._set_state_initial([range, subnet, service])

        tasks = self.plugin.create_configuration(context)
        self.assertEqual(2, len(tasks))

    def test_validate_valid_ranges_in_network_v6(self):
        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp6-range',
                          start='2001:db8::10',
                          end='2001:db8::20')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp6-subnet',
                          network_name='storage',
                          ranges=[range1])

        service = DhcpMock(item_id='svc1',
                           item_type_id='dhcp-service',
                           subnets=[subnet])

        nic = DhcpMock(item_id='if1',
                       item_type_id='eth',
                       device_name='eth1',
                       ipv6address='2001:db8::1/64',
                       network_name='storage')

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        network_interfaces = [nic],
                        query=lambda x: [service])

        TestDhcpservicePlugin._set_state_initial([range1, subnet, service, nic, node])

        errors = DhcpservicePlugin._validate_ranges_in_networks_v6(node)
        self.assertEqual([], errors)

    def test_validate_invalid_ranges_in_network_v6(self):
        range1 = DhcpMock(item_id='r1',
                          item_type_id='dhcp6-range',
                          start='2001:db8::10',
                          end='2001:db8::20')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp6-subnet',
                          network_name='storage',
                          ranges=[range1])

        service = DhcpMock(item_id='svc1',
                           item_type_id='dhcp6-service',
                           subnets=[subnet])

        nic = DhcpMock(item_id='if1',
                       item_type_id='eth',
                       device_name='eth1',
                       ipv6address='2001:aaa::1/64',
                       network_name='storage')

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname = 'mn1',
                        network_interfaces = [nic],
                        query=lambda x: [service])

        TestDhcpservicePlugin._set_state_initial([range1, subnet, service, nic, node])

        errors = DhcpservicePlugin._validate_ranges_in_networks_v6(node)
        self.assertNotEqual([], errors)

    def _create_common_litpcds_8995_items(self):
        mgmt_net = DhcpMock(item_id='net_mgmt',
                            item_type_id='network',
                            litp_management='true')
        mgmt_net.name='mgmt'

        net1 = DhcpMock(item_id='net1',
                        item_type_id='network',
                        litp_management='false',
                        subnet='10.10.10.0/24')
        net1.name='traffic1'

        net2 = DhcpMock(item_id='net2',
                        item_type_id='network',
                        litp_management='false',
                        subnet='192.10.10.0/24')
        net2.name='traffic2'

        nic1 = DhcpMock(item_id='if1',
                        item_type_id='eth',
                        network_name=net1.name,
                        macaddress='dd:ee:aa:dd:bb:ee',
                        device_name='eth1')

        nic2 = DhcpMock(item_id='if2',
                        item_type_id='eth',
                        network_name=net2.name,
                        macaddress='dd:ee:aa:dd:be:ef',
                        device_name='eth2')

        items = [mgmt_net, net1, net2, nic1, nic2]
        TestDhcpservicePlugin._set_state_applied(items)
        return items

    def test_for_litpcds_8995_dhcpv4(self):
        (mgmt_net, net1, net2, nic1, nic2) = self._create_common_litpcds_8995_items()
        nic1.ipaddress='10.10.10.1'
        nic2.ipaddress='192.10.10.1'

        range = DhcpMock(item_id='r1',
                         item_type_id='dhcp-range',
                         start='192.168.100.20',
                         end='192.168.100.30')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp-subnet',
                          network_name=net1.name,
                          ranges=[range])
        service = DhcpMock(item_id='svc1',
                           item_type_id='dhcp-service',
                           service_name='dhcp1',
                           subnets=[subnet],
                           ntpservers=None,
                           nameservers=None,
                           domainsearch=None)

        def _mock_node_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [service]
            elif 'dhcp6-service' == query_item_type:
                return []

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname='mn1',
                        network_interfaces=[nic1, nic2],
                        query=_mock_node_query)

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [node]
            elif 'network' == query_item_type:
                return [net1, net2]
            elif 'network' == query_item_type and kwargs:
                return [mgmt_net]

        context = Mock(query=_mock_context_query)

        items = [range, subnet, service, node]
        TestDhcpservicePlugin._set_state_applied(items)

        tasks = self.plugin._new_tasks(context)

        self.assertEquals([], tasks)

        # ----

        subnet.applied_properties = {'network_name': subnet.network_name}
        subnet.network_name = net2.name

        range.start = '192.168.201.20'
        range.end = '192.168.201.30'

        TestDhcpservicePlugin._set_state_updated([subnet, range])

        tasks = self.plugin._new_tasks(context)

        expected_tasks = [ConfigTask(node, service,
                                     'Update "dhcp-service" "dhcp1" on node "mn1"',
                                     'dhcpservice::config_server',
                                     self.plugin._gen_service_call_id(service),
                                     interfaces=[nic2.device_name],
                                     default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                                     max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                                     role='primary'),
                          ConfigTask(node, subnet,
                                     'Update "dhcp-subnet", update "dhcp-range" "r1" on network "traffic2" on node "mn1"',
                                     'dhcpservice::config_pool',
                                     DhcpservicePlugin._gen_hash_path(subnet),
                                     ranges=['192.168.201.20 192.168.201.30'],
                                     network='192.10.10.0',
                                     mask='255.255.255.0')
                         ]
        self.assertEquals(set(expected_tasks), set(tasks))

    def test_for_litpcds_8995_dhcpv6(self):
        (mgmt_net, net1, net2, nic1, nic2) = self._create_common_litpcds_8995_items()
        nic1.ipv6address='2001:db8::81/64'
        nic2.ipv6address='2001:db8::82/64'

        range = DhcpMock(item_id='r1',
                         item_type_id='dhcp6-range',
                         start='2001:db8::80',
                         end='2001:db8::90')
        subnet = DhcpMock(item_id='sub1',
                          item_type_id='dhcp6-subnet',
                          network_name=net1.name,
                          ranges=[range])

        service = DhcpMock(item_id='svc1',
                           item_type_id='dhcp6-service',
                           service_name='dhcp2',
                           subnets=[subnet],
                           ntpservers=None,
                           nameservers=None,
                           domainsearch=None)

        def _mock_node_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return []
            elif 'dhcp6-service' == query_item_type:
                return [service]

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname='mn1',
                        network_interfaces=[nic1, nic2],
                        query=_mock_node_query)

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [node]
            elif 'network' == query_item_type and kwargs:
                return [mgmt_net]
            elif 'network' == query_item_type:
                return [net1]


        context = Mock(query=_mock_context_query)

        items = [range, subnet, service, node]
        TestDhcpservicePlugin._set_state_applied(items)

        tasks = self.plugin._new_tasks(context)

        self.assertEquals([], tasks)

        # ----

        subnet.applied_properties = {'network_name': subnet.network_name}
        subnet.network_name = net2.name

        range.start = '2001:db8::10'
        range.end = '2001:db8::20'

        TestDhcpservicePlugin._set_state_updated([range, subnet])

        tasks = self.plugin._new_tasks(context)

        expected_tasks = [ConfigTask(node, service,
                                     'Update "dhcp6-service" "dhcp2" on node "mn1"',
                                     'dhcpservice::config_server6',
                                     self.plugin._gen_service_call_id(service),
                                     interfaces=[nic2.device_name],
                                     default_lease_time=DhcpservicePlugin.DEFAULT_LEASE_TIME,
                                     max_lease_time=DhcpservicePlugin.MAX_LEASE_TIME,
                                     role='primary'),
                         ConfigTask(node, subnet,
                                    'Update "dhcp6-subnet", update "dhcp6-range" "r1" on network "traffic2" on node "mn1"',
                                    'dhcpservice::config_pool6',
                                    DhcpservicePlugin._gen_hash_path(subnet),
                                    ranges=['2001:db8::10 2001:db8::20'],
                                    network='2001:db8::/64')
                         ]

        self.assertEquals(set(expected_tasks), set(tasks))

    def test_for_litpcds_9132(self):

        node = DhcpMock(item_id='n1',
                        item_type_id='node',
                        hostname='mn1')

        node.services.get_vpath = lambda: '/x/y/z'

        self._test_for_litpcds_9132_for_dhcpX('dhcp-service', node)
        self._test_for_litpcds_9132_for_dhcpX('dhcp6-service', node)

        # ----

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id='dhcp-service',
                        service_name='dhcp1',
                        subnets=[],
                        primary='true')

        svc2 = DhcpMock(item_id='svc2',
                        item_type_id='dhcp6-service',
                        service_name='dhcp2',
                        subnets=[],
                        primary=svc1.primary)

        def _mock_node_query (query_item_type, **kwargs):
            if 'dhcp-service' == query_item_type:
                return [svc1]
            elif 'dhcp6-service' == query_item_type:
                return [svc2]
            else:
                return []

        node.query = _mock_node_query

        TestDhcpservicePlugin._set_state_initial([svc1, svc2])  # svc2 begins 'Initial'
        TestDhcpservicePlugin._set_state_applied([node])

        errors = self.plugin._validate_node_service_count(node)
        self.assertEqual([], errors)

        # ----

        TestDhcpservicePlugin._set_state_updated([svc2])
        errors = self.plugin._validate_node_service_count(node)
        self.assertEqual([], errors)

        # ----

        TestDhcpservicePlugin._set_state_for_removal([svc2])
        errors = self.plugin._validate_node_service_count(node)
        self.assertEqual([], errors)

    def _test_for_litpcds_9132_for_dhcpX(self, svc_version, node):

        print "Testing for %s" % svc_version

        svc1 = DhcpMock(item_id='svc1',
                        item_type_id=svc_version,
                        service_name='dhcp1',
                        subnets=[],
                        primary='true')

        svc2 = DhcpMock(item_id='svc2',
                        item_type_id=svc1.item_type_id,
                        service_name='dhcp2',
                        subnets=[],
                        primary=svc1.primary)

        def _mock_node_query (query_item_type, **kwargs):
            if svc_version == query_item_type:
                return [svc1, svc2]
            else:
                return []

        node.query = _mock_node_query

        TestDhcpservicePlugin._set_state_initial([svc1, svc2])  # svc2 begins 'Initial'
        TestDhcpservicePlugin._set_state_applied([node])

        emsg = 'Node "%s" must have at most one %s' % (node.hostname, svc1.item_type_id)

        expected_errors = [ValidationError(item_path=node.services.get_vpath(),
                                           error_message=emsg)]

        errors = self.plugin._validate_node_service_count(node)
        self.assertEqual(expected_errors, errors)

        # ----

        TestDhcpservicePlugin._set_state_updated([svc2])
        errors = self.plugin._validate_node_service_count(node)
        self.assertEqual(expected_errors, errors)

        # ----

        TestDhcpservicePlugin._set_state_for_removal([svc2])
        errors = self.plugin._validate_node_service_count(node)
        self.assertEqual(expected_errors, errors)
