##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from netaddr.ip import IPAddress, IPNetwork
import hashlib

from litp.core.plugin import Plugin
from litp.core.model_item import CollectionItem
from litp.core.validators import ValidationError
from litp.core.execution_manager import ConfigTask
from litp.core.litp_logging import LitpLogger

log = LitpLogger()


class DhcpservicePlugin(Plugin):
    """
    LITP DHCP Service plugin provides support for
    the configuration of a DHCP IPv4 service and a DHCP IPv6 service
    on a pair of peer nodes or a single peer node.
    A service may reference
    one or more DHCP subnets which, in turn, may reference
    one or more DHCP subnet ranges.

    Update and remove reconfiguration actions are supported for this plugin
    (with some exceptions).
    """

    DHCP_CALL_ID = 'dhcp_config'
    DEFAULT_LEASE_TIME = 28800
    MAX_LEASE_TIME = 86400

    @staticmethod
    def _dhcp_interfaces_network_changed(node, svc):

        dhcp_networks = [s.network_name for s in
                          DhcpservicePlugin._dhcp_subnets(svc)]

        net_name_in_dhcp_networks = (lambda iface, networks: hasattr(iface,
                            'network_name') and iface.network_name
                             and iface.network_name in networks)

        net_name_changed = (lambda iface: hasattr(iface, 'network_name') and
                            iface.network_name and
                            (iface.network_name !=
                                iface.applied_properties.get('network_name')))
        changed_items = []

        for iface in node.network_interfaces:
            if iface.is_for_removal():
                if net_name_in_dhcp_networks(iface, dhcp_networks):
                    changed_items.append(iface)
            elif iface.is_updated():
                if (((iface.applied_properties.get('network_name')
                      in dhcp_networks) or
                    net_name_in_dhcp_networks(iface, dhcp_networks)) and
                    net_name_changed(iface)):
                    changed_items.append(iface)

        return changed_items

    @staticmethod
    def _get_current_dhcp_interfaces(node, svc):

        dhcp_interfaces = []

        dhcp_networks = [s.network_name for s in
                          DhcpservicePlugin._dhcp_subnets(svc)]

        for iface in node.network_interfaces:
            if not iface.is_for_removal():
                if (hasattr(iface, 'network_name') and iface.network_name
                    and iface.network_name in dhcp_networks):
                    dhcp_interfaces.append(iface)

        return dhcp_interfaces

    @staticmethod
    def _get_mgmt_ip_of_node(context, node):

        mgmt_ip_of_node = None
        mgmt_network = DhcpservicePlugin._management_network(context)

        if mgmt_network:
            for iface in node.network_interfaces:
                if hasattr(iface, 'network_name') and iface.network_name \
                and hasattr(iface, 'ipaddress') and iface.ipaddress \
                and iface.network_name == mgmt_network.name:
                    mgmt_ip_of_node = iface.ipaddress
        return mgmt_ip_of_node

    @staticmethod
    def _peer_server_is_present(service, other_service):
        #For single server case this may need to check if
        #services are not removed
        return (service.service_name == other_service.service_name
                 and service.primary != other_service.primary)

    @staticmethod
    def _get_peer_address(context, svc):

        peer_address = None

        peer_nodes = context.query('node')

        for other_node in peer_nodes:
            for other_svc in DhcpservicePlugin._dhcp_services(other_node):
                if DhcpservicePlugin._peer_server_is_present(svc, other_svc):
                    peer_address = DhcpservicePlugin._get_mgmt_ip_of_node(
                                                        context, other_node)

        return peer_address

    @staticmethod
    def _get_ipv4_network_address(context, dhcp_subnet):
        """
        Method returns an IPNetwork object
        """

        networks = DhcpservicePlugin._networks(context)

        network_subnet = DhcpservicePlugin._get_subnet_for_net_name(
                                    dhcp_subnet.network_name, networks)

        subnet = IPNetwork(network_subnet)

        return subnet

    @staticmethod
    def _get_ipv6_network_address(node, dhcp_subnet):
        """
        Method returns an IPNetwork object
        """

        subnet = None

        net_name = dhcp_subnet.network_name

        for iface in node.network_interfaces:
            if hasattr(iface, 'network_name') and iface.network_name:
                if hasattr(iface, 'ipv6address') and iface.ipv6address:
                    if iface.network_name == net_name:
                        subnet = DhcpservicePlugin._network_from_ipv6address(
                                                            iface.ipv6address)
                        return subnet

    @staticmethod
    def _get_ranges_as_list(subnet):
        ranges = []
        for rng in DhcpservicePlugin._dhcp_ranges(subnet):
            ranges.append('%s %s' % (rng.start, rng.end))
        return ranges

    @staticmethod
    def _nics_with_ips(node, fieldname='ipaddress'):
        return [nic for nic in node.network_interfaces
                if not nic.is_for_removal() and
                   hasattr(nic, fieldname) and getattr(nic, fieldname)]

    @staticmethod
    def _pool_task_call_type(subnet):
        return ('dhcpservice::config_pool'
                if subnet.item_type_id == 'dhcp-subnet'
                else 'dhcpservice::config_pool6')

    @staticmethod
    def _config_task_call_type(service):
        return ('dhcpservice::config_server'
                if service.item_type_id == 'dhcp-service'
                else 'dhcpservice::config_server6')

    @staticmethod
    def _is_service_version4(service):
        return service.item_type_id == 'dhcp-service'

    @staticmethod
    def _service_version(service):
        return ('dhcp-service'
                if DhcpservicePlugin._is_service_version4(service)
                else 'dhcp6-service')

    @staticmethod
    def _subnet_version(service):
        return ('dhcp-subnet'
                if DhcpservicePlugin._is_service_version4(service)
                else 'dhcp6-subnet')

    @staticmethod
    def _range_version(service):
        return ('dhcp-range'
                if DhcpservicePlugin._is_service_version4(service)
                else 'dhcp6-range')

    @staticmethod
    def _network_from_ipv6address(ipv6address):
        """
        Returns a netaddr.IPNetwork object instantiated from a
        network-interface model item's ipv6address property. If the prefix is
        absent from the property value, it defaults to /64
        """
        if '/' in ipv6address:
            return IPNetwork(ipv6address).cidr
        else:
            return IPNetwork(ipv6address + '/64').cidr

    @staticmethod
    def _networks(context):
        return [net for net in context.query('network')
                if not net.is_for_removal()]

    @staticmethod
    def _all_nodes(context):
        return [node for node in context.query('node')
                if not node.is_for_removal()]

    @staticmethod
    def _all_mses(context):
        return [ms for ms in context.query('ms')
                if not ms.is_for_removal()]

    @staticmethod
    def _management_networks(context):
        return [net for net in context.query('network', litp_management='true')
                if not net.is_for_removal()]

    @staticmethod
    def _management_network(context):
        networks = DhcpservicePlugin._management_networks(context)
        return networks[0] if 1 == len(networks) else None

    @staticmethod
    def _dhcp_services(scope, item_type_id='dhcp-service'):
        return [svc for svc in scope.query(item_type_id)
                if not svc.is_for_removal()]

    @staticmethod
    def _all_dhcp_services(scope):
        return DhcpservicePlugin._dhcp_services(scope, 'dhcp-service') + \
               DhcpservicePlugin._dhcp_services(scope, 'dhcp6-service')

    @staticmethod
    def _all_present_and_for_removal_services(scope):
        return scope.query('dhcp-service') + scope.query('dhcp6-service')

    @staticmethod
    def _dhcp_subnets(service):
        return [subnet for subnet in service.subnets
                if not subnet.is_for_removal()]

    @staticmethod
    def _dhcp_ranges(subnet):
        return [rng for rng in subnet.ranges
                if not rng.is_for_removal()]

    @staticmethod
    def _get_dhcp_subnet_and_version(node):
        return [(sub.network_name, sub.item_type_id) for svc in
                DhcpservicePlugin._all_dhcp_services(node)
                for sub in DhcpservicePlugin._dhcp_subnets(svc)]

    def validate_model(self, context):
        """
        - A ``dhcp-service`` or a ``dhcp6-service`` may only be \
          deployed on peer servers and not on the MS.

        - The ``service_name`` property of a ``dhcp-service`` and a \
          ``dhcp6-service`` item must be collectively unique.

        - A ``network`` named in a ``dhcp-subnet`` or a ``dhcp6-subnet`` \
          item must not be the designated "management" ``network``.

        - A ``network`` named in a ``dhcp-subnet`` or a ``dhcp6-subnet`` \
          item must be a valid ``network`` referenced by a \
          ``network-interface`` on the ``node`` where the \
          ``dhcp-service`` or ``dhcp6-service`` is located.

        - A ``network`` named in a ``dhcp-subnet`` item must have the \
          ``subnet`` property defined.

        - The ``network-interface`` associated with the ``network`` \
          referenced by a ``dhcp6-subnet`` must have an ``ipv6address`` \
          defined.

        - A ``network`` may be referenced by at most one ``dhcp-subnet`` \
          and at most one ``dhcp6-subnet``.

        - The ``dhcp-range`` ``start`` and ``end`` property values must be \
          valid ``ipaddress`` values within the associated IPv4 ``network``.

        - The ``dhcp6-range`` ``start`` and ``end`` property values must be \
          valid ``ipv6address`` values within the associated IPv6 ``network``.

        - The ``dhcp-range`` ``end`` address must \
          be greater than or equal to the ``dhcp-range`` ``start`` address.

        - The ``dhcp6-range`` ``end`` address must \
          be greater than or equal to the ``dhcp6-range`` ``start`` address.

        - For a given ``dhcp-subnet`` or ``dhcp6-subnet``, ranges must not \
          overlap.

        - A ``node`` may have at most one ``dhcp-service`` (primary \
          or non-primary) and at most one ``dhcp6-service`` (primary \
          or non-primary).

        - A named ``dhcp-service`` or ``dhcp6-service`` may appear twice \
          in the scope of a ``cluster`` (only once per ``node``) - once as \
          primary, once as non-primary.

        - A ``dhcp-service`` or ``dhcp6-service`` may appear once \
          in the scope of a ``cluster`` as a standalone service instance.

        - All static ``ipaddress``/``ipv6address`` values \
          (ie non-dhcp addresses) throughout the model must \
          not lie within any ``dhcp-range`` or ``dhcp6-range`` \
          if they have the same ``network`` referenced \
          by the ``dhcp-subnet`` or ``dhcp6-subnet``.
        """

        errors = []

        all_nodes = DhcpservicePlugin._all_nodes(context)
        all_mses = DhcpservicePlugin._all_mses(context)

        mgmt_net = DhcpservicePlugin._management_network(context)
        networks = DhcpservicePlugin._networks(context)

        errors += DhcpservicePlugin._validate_service_not_on_ms(all_mses)
        errors += DhcpservicePlugin._validate_service_names_unique(context)

        for node in all_nodes:
            if mgmt_net:
                errors += DhcpservicePlugin._validate_mgmt_net_not_used(
                                                                node, mgmt_net)

            errors += DhcpservicePlugin._validate_subnet_networks_valid(node,
                                                                      networks)
            errors += DhcpservicePlugin._validate_ranges_in_networks(node,
                                                                    networks)
            errors += DhcpservicePlugin._validate_ranges_in_networks_v6(node)
            errors += DhcpservicePlugin._validate_no_range_overlaps(node)
            errors += DhcpservicePlugin._validate_node_service_count(node)
            svc_pair_error = DhcpservicePlugin._validate_service_pairs(node,
                                                                all_nodes)
            if svc_pair_error:
                errors += svc_pair_error
            else:
                errors += DhcpservicePlugin._validate_subnet_network_unique(
                                                              node, all_nodes)
            errors += DhcpservicePlugin._validate_static_ips(node,
                                                         all_nodes + all_mses)
            errors += DhcpservicePlugin._validate_interface_has_ip_addr(node)
        return errors

    @staticmethod
    def _has_no_ip_address(iface, ip_fieldname):
        if not hasattr(iface, ip_fieldname):
            return True

        if ip_fieldname == 'ipaddress':
            return not iface.ipaddress
        elif ip_fieldname == 'ipv6address':
            return not iface.ipv6address

        return False

    @staticmethod
    def _no_ip_for_subnet(iface, subnet_versions, subnet_version,
                          ip_version, ip_fieldname):
        preamble = '._no_ip_for_subnet: '
        errors = []

        msg_template = ('A network interface that references '
                        'a network that is also referenced by '
                        'a "%s", must have an IP%s '
                        'address defined')

        if (subnet_version in subnet_versions and
            DhcpservicePlugin._has_no_ip_address(iface, ip_fieldname)):
            msg = msg_template % (subnet_version, ip_version)
            log.trace.debug(preamble + msg)
            error = ValidationError(item_path=iface.get_vpath(),
                                    error_message=msg)
            errors.append(error)

        return errors

    @staticmethod
    def _validate_interface_has_ip_addr(node):

        errors = []

        all_dhcp_subnets = DhcpservicePlugin._get_dhcp_subnet_and_version(node)

        node_ifaces = [iface for iface in node.network_interfaces
                       if hasattr(iface, 'network_name') and
                       iface.network_name and not
                       iface.is_for_removal()]

        for iface in node_ifaces:
            subnet_versions = [ver for (netname, ver) in all_dhcp_subnets
                               if netname == iface.network_name]
            errors += DhcpservicePlugin._no_ip_for_subnet(
                iface, subnet_versions, 'dhcp-subnet', 'v4', 'ipaddress')
            errors += DhcpservicePlugin._no_ip_for_subnet(
                iface, subnet_versions, 'dhcp6-subnet', 'v6', 'ipv6address')

        return errors

    @staticmethod
    def _validate_static_ips(node, all_nodes):
        errors = []

        for svc in DhcpservicePlugin._all_dhcp_services(node):
            if svc.primary == 'true':
                for subnet in DhcpservicePlugin._dhcp_subnets(svc):
                    for rng in DhcpservicePlugin._dhcp_ranges(subnet):
                        errors += \
                            DhcpservicePlugin._validate_ips_against_range(
                                     all_nodes, svc, subnet.network_name, rng)

        return errors

    @staticmethod
    def _validate_ips_against_range(nodes, service, network_name, rng):
        preamble = '._validate_ips_against_range: '
        errors = []

        if DhcpservicePlugin._is_service_version4(service):
            svc_version = 4
            ip_field_name = 'ipaddress'
        else:
            svc_version = 6
            ip_field_name = 'ipv6address'

        for node in nodes:
            for nic in DhcpservicePlugin._nics_with_ips(node, ip_field_name):
                if DhcpservicePlugin._is_service_version4(service):
                    addr = nic.ipaddress
                else:
                    addr = nic.ipv6address

                if DhcpservicePlugin._ip_in_range(addr, rng, svc_version) and \
                   nic.network_name == network_name:
                    msg = ('Static IPv%d address "%s" ' +
                           'lies within the %s "%s"') % \
                           (svc_version, addr,
                            rng.item_type_id, rng.get_vpath())

                    log.trace.debug(preamble + msg)
                    error = ValidationError(item_path=nic.get_vpath(),
                                            error_message=msg)
                    errors.append(error)
        return errors

    @staticmethod
    def _ip_in_range(ipaddr, rng, ver):
        #API prevents start and end from having / but ipaddr can
        if ver == 6 and '/' in ipaddr:
            ipaddr = ipaddr.split('/')[0]

        return IPAddress(rng.start, version=ver) <= \
               IPAddress(ipaddr, version=ver) <= \
               IPAddress(rng.end, version=ver)

    @staticmethod
    def _ranges_overlap(range1, range2):
        return IPAddress(range1.start) <= IPAddress(range2.end) and \
               IPAddress(range2.start) <= IPAddress(range1.end)

    @staticmethod
    def _validate_no_range_overlaps(node):
        preamble = '._validate_no_range_overlaps: ' + node.hostname + ': '

        errors = []
        for svc in DhcpservicePlugin._all_dhcp_services(node):
            for subnet in DhcpservicePlugin._dhcp_subnets(svc):
                ranges = DhcpservicePlugin._dhcp_ranges(subnet)
                for i, rng1 in enumerate(ranges):
                    for rng2 in ranges[i + 1:len(ranges)]:
                        if DhcpservicePlugin._ranges_overlap(rng1, rng2):
                            msg = '{0} overlaps with "{1}"'.\
                                  format(rng1.item_type_id, rng2.get_vpath())
                            log.trace.debug(preamble + msg)
                            error = ValidationError(item_path=rng1.get_vpath(),
                                                    error_message=msg)
                            errors.append(error)

        return errors

    @staticmethod
    def _service_instances(all_nodes, service_name, primary,
                           svc_version='dhcp-service'):
        return [svc
                for mn in all_nodes
                  for svc in DhcpservicePlugin._dhcp_services(mn, svc_version)
                       if svc.service_name == service_name and
                          svc.primary == primary]

    @staticmethod
    def _validate_service_pairs(node, all_nodes):
        preamble = '._validate_service_pairs: ' + node.hostname + ': '
        errors = []

        for svc_version in ['dhcp-service', 'dhcp6-service']:
            for service in DhcpservicePlugin._dhcp_services(node, svc_version):
                primary_svcs = DhcpservicePlugin._service_instances(
                        all_nodes, service.service_name, 'true', svc_version)

                non_primary_svcs = DhcpservicePlugin._service_instances(
                        all_nodes, service.service_name, 'false', svc_version)

                if len(primary_svcs) > 1 or len(non_primary_svcs) > 1:
                    msg = ('%s "%s" must be deployed exactly ' +
                           'once as primary and once as non-primary') % \
                           (svc_version, service.service_name)
                    log.trace.debug(preamble + msg)
                    error = ValidationError(item_path=service.get_vpath(),
                                            error_message=msg)
                    errors.append(error)
        return errors

    @staticmethod
    def _validate_node_service_count(node):
        preamble = '._validate_node_service_count: ' + node.hostname + ': '
        errors = []

        for svc_version in ['dhcp-service', 'dhcp6-service']:
            if len(node.query(svc_version)) > 1:
                msg = ('Node "%s" must have at most one %s' %
                       (node.hostname, svc_version))
                log.trace.debug(preamble + msg)

                error = ValidationError(item_path=node.services.get_vpath(),
                                        error_message=msg)
                errors.append(error)

        return errors

    @staticmethod
    def _address_in_network(item, network_name, network,
                            address, property_name):
        preamble = '._address_in_network: '

        if not IPAddress(address) in network:
            msg = ('"%s" address "%s" is not valid for network "%s"' %
                   (property_name, address, network_name))
            log.trace.debug(preamble + msg)
            error = ValidationError(item_path=item.get_vpath(),
                                    error_message=msg)
            return error

    @staticmethod
    def _get_subnet_for_net_name(net_name, networks):
        for net in networks:
            if net.name == net_name:
                return net.subnet

    @staticmethod
    def _validate_ranges_in_networks(node, networks):

        errors = []

        for service in DhcpservicePlugin._dhcp_services(node):
            for subnet in DhcpservicePlugin._dhcp_subnets(service):
                subnet_cidr = DhcpservicePlugin._get_subnet_for_net_name(
                                                subnet.network_name, networks)

                if subnet_cidr:
                    network = IPNetwork(subnet_cidr)
                    for rng in DhcpservicePlugin._dhcp_ranges(subnet):
                        for (prop, prop_name) in [(rng.start, 'start'),
                                                  (rng.end, 'end')]:
                            error = DhcpservicePlugin._address_in_network(rng,
                                              subnet.network_name, network,
                                              prop, prop_name)
                            if error:
                                errors.append(error)

        return errors

    @staticmethod
    def _validate_ranges_in_networks_v6(node):

        errors = []

        for service in DhcpservicePlugin._dhcp_services(node, 'dhcp6-service'):
            for subnet in DhcpservicePlugin._dhcp_subnets(service):
                network = DhcpservicePlugin._get_ipv6_network_address(node,
                                                                      subnet)

                if network:
                    for rng in DhcpservicePlugin._dhcp_ranges(subnet):
                        for (prop, prop_name) in [(rng.start, 'start'),
                                                  (rng.end, 'end')]:
                            error = DhcpservicePlugin._address_in_network(rng,
                                              subnet.network_name, network,
                                              prop, prop_name)
                            if error:
                                errors.append(error)

        return errors

    @staticmethod
    def _all_net_names(net_name, nodes, modality_boolean):
        return [(sn.network_name, sn.item_type_id)
                for mn in nodes
                  for svc in DhcpservicePlugin._all_dhcp_services(mn)
                    for sn in DhcpservicePlugin._dhcp_subnets(svc)
                      if sn.network_name == net_name and
                         svc.primary == modality_boolean]

    @staticmethod
    def _validate_subnet_network_unique(node, all_nodes):
        preamble = '._validate_subnet_network_unique: ' + node.hostname + ': '

        errors = []

        services = DhcpservicePlugin._all_dhcp_services(node)

        for svc in services:
            for subnet in DhcpservicePlugin._dhcp_subnets(svc):

                primary_nets = DhcpservicePlugin._all_net_names(
                                       subnet.network_name, all_nodes, 'true')
                non_primary_nets = DhcpservicePlugin._all_net_names(
                                       subnet.network_name, all_nodes, 'false')

                duplicates = lambda l: set([x for x in l if l.count(x) > 1])

                if duplicates(primary_nets) or duplicates(non_primary_nets):
                    msg = ('Network "%s" may be referenced by '
                           'at most one "dhcp-subnet" and at most one '
                           '"dhcp6-subnet"' %
                          (subnet.network_name))
                    log.trace.debug(preamble + msg)
                    error = ValidationError(item_path=subnet.get_vpath(),
                                            error_message=msg)
                    errors.append(error)

        return errors

    @staticmethod
    def _validate_mgmt_net_not_used(node, mgmt_net):
        preamble = '._validate_mgmt_net_not_used: ' + node.hostname + ': '

        errors = []

        for svc in DhcpservicePlugin._all_dhcp_services(node):
            for subnet in DhcpservicePlugin._dhcp_subnets(svc):
                if subnet.network_name == mgmt_net.name:
                    subnet_version = DhcpservicePlugin._subnet_version(svc)
                    msg = ('"%s" must not reference '
                           'the management network "%s"' %
                          (subnet_version, mgmt_net.name))
                    log.trace.debug(preamble + msg)
                    error = ValidationError(item_path=subnet.get_vpath(),
                                            error_message=msg)
                    errors.append(error)

        return errors

    @staticmethod
    def _validate_subnet_networks_valid(node, networks):
        preamble = '._validate_subnet_networks_valid: ' + node.hostname + ': '

        errors = []

        services = DhcpservicePlugin._all_dhcp_services(node)

        if services:
            nic_network_names = [nic.network_name
                                 for nic in node.network_interfaces
                                 if hasattr(nic, 'network_name') and
                                 nic.network_name and not
                                 nic.is_for_removal()]

            removed_nics = [nic for nic in node.network_interfaces
                            if hasattr(nic, 'network_name') and
                            nic.is_for_removal()]

            for svc in services:
                for subnet in DhcpservicePlugin._dhcp_subnets(svc):
                    if not subnet.network_name in nic_network_names:
                        subnet_version = DhcpservicePlugin._subnet_version(svc)
                        msg = 'The network "{0}" referenced by "{1}" ' \
                              'is not configured on node "{2}"'
                        msg = msg.format(subnet.network_name, subnet_version,
                                         node.hostname)
                        lost_ref = [nic for nic in removed_nics
                                    if subnet.network_name == nic.network_name]
                        if lost_ref:
                            additional_info = ' due to removal of "{0}" "{1}"'
                            additional_info = additional_info.format(
                                lost_ref[0].item_type_id,
                                lost_ref[0].get_vpath())
                            msg += additional_info
                        log.trace.debug(preamble + msg)
                        error = ValidationError(item_path=subnet.get_vpath(),
                                                error_message=msg)
                        errors.append(error)
                    else:
                        if DhcpservicePlugin._is_service_version4(svc):
                            subnet_cidr = \
                                DhcpservicePlugin._get_subnet_for_net_name(
                                                 subnet.network_name, networks)
                            if not subnet_cidr:
                                msg = ('Network "%s" does not have a '
                                       'subnet specified' %
                                       (subnet.network_name))
                                log.trace.debug(preamble + msg)
                                error = ValidationError(
                                                item_path=subnet.get_vpath(),
                                                error_message=msg)
                                errors.append(error)

        return errors

    @staticmethod
    def _validate_service_names_unique(context):
        preamble = '._validate_service_names_unique: '

        errors = []

        services = DhcpservicePlugin._all_dhcp_services(context)

        for svc in services:
            other_services = [other_svc for other_svc in services
                              if other_svc != svc and
                                 other_svc.service_name == svc.service_name]
            if other_services:
                msg = (('%s name "%s" is not unique ' +
                        'across all deployments') %
                       (svc.item_type_id, svc.service_name))
                log.trace.debug(preamble + msg)
                error = ValidationError(item_path=svc.get_vpath(),
                                        error_message=msg)
                errors.append(error)

        return errors

    @staticmethod
    def _validate_service_not_on_ms(ms_nodes):
        preamble = '._validate_service_not_on_ms: '

        errors = []

        for ms in ms_nodes:
            services = DhcpservicePlugin._all_dhcp_services(ms)
            if services:
                msg = ('DHCP services may not be deployed on the ' +
                       'Management Server "%s"') % ms.hostname
                log.trace.debug(preamble + msg)
                error = ValidationError(item_path=ms.get_vpath(),
                                        error_message=msg)
                errors.append(error)

        return errors

    def create_configuration(self, plugin_api_context):
        '''
        *An example of CLI for DHCP V4 configuration

        .. code-block:: bash
           :linenos:

            litp create \
-t dhcp-service \
-p /software/services/s1 \
-o service_name="dhcp_svc1" \
nameservers="10.10.10.10,20.20.20.20" \
domainsearch="example1.com,example2.com" \
ntpservers="0.ie.pool.ntp.org,10.44.10.44"
            litp create \
-t dhcp-subnet \
-p /software/services/s1/subnets/s1 \
-o network_name="storage_1"
            litp create \
-t dhcp-range \
-p /software/services/s1/subnets/s1/ranges/r1 \
-o start="10.0.0.1" end="10.0.0.4"
            litp create \
-t dhcp-range \
-p /software/services/s1/subnets/s1/ranges/r2 \
-o start="10.0.0.7" end="10.0.0.9"
            litp create \
-t dhcp-subnet \
-p /software/services/s1/subnets/s2 \
-o network_name="storage_2"
            litp create \
-t dhcp-range \
-p /software/services/s1/subnets/s2/ranges/r1 \
-o start="11.0.0.2" end="11.0.0.10"
            litp inherit \
-p /deployments/d1/clusters/c1/nodes/n1/services/s1 \
-s /software/services/s1
            litp inherit \
-p /deployments/d1/clusters/c1/nodes/n2/services/s1 \
-s /software/services/s1 -o primary="false"

        *An example of CLI for DHCP V6 configuration

        .. code-block:: bash
           :linenos:

            litp create \
-t dhcp6-service \
-p /software/services/s2 \
-o service_name="dhcp_svc2"
            litp create \
-t dhcp6-subnet \
-p /software/services/s2/subnets/s1 \
-o network_name="back_up1"
            litp create \
-t dhcp6-range \
-p /software/services/s2/subnets/s1/ranges/r1 \
-o start="fc01::10" end="fc01::15"
            litp inherit \
-p /deployments/d1/clusters/c1/nodes/n1/services/s2 \
-s /software/services/s2
            litp inherit \
-p /deployments/d1/clusters/c1/nodes/n2/services/s2 \
-s /software/services/s2 -o primary="false"

        *An example of XML for DHCP V4 configuration

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
            <litp:dhcp-service \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp litp-xml-schema/litp.xsd" \
id="s1">
              <primary>true</primary>
              <service_name>dhcp_svc1</service_name>
              <ntpservers>0.ie.pool.ntp.org,10.44.10.44</ntpservers>
              <nameservers>10.10.10.10,20.20.20.20</nameservers>
              <domainsearch>example1.com,example2.com</domainsearch>
                <litp:dhcp-service-subnets-collection id="subnets">
                <litp:dhcp-subnet id="s1">
                  <network_name>storage</network_name>
                  <litp:dhcp-subnet-ranges-collection id="ranges">
                    <litp:dhcp-range id="r1">
                      <end>10.10.10.7</end>
                      <start>10.10.10.1</start>
                    </litp:dhcp-range>
                  </litp:dhcp-subnet-ranges-collection>
                </litp:dhcp-subnet>
              </litp:dhcp-service-subnets-collection>
            </litp:dhcp-service>

        *An example of XML for DHCP V6 configuration

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
            <litp:dhcp6-service \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp litp-xml-schema/litp.xsd" \
id="s2">
              <primary>true</primary>
              <service_name>dhcp_svc2</service_name>
                <litp:dhcp6-service-subnets-collection id="subnets">
                <litp:dhcp6-subnet id="s1">
                  <network_name>back_up1</network_name>
                  <litp:dhcp6-subnet-ranges-collection id="ranges">
                    <litp:dhcp6-range id="r1">
                      <end>fc01::15</end>
                      <start>fc01::10</start>
                    </litp:dhcp6-range>
                  </litp:dhcp6-subnet-ranges-collection>
                </litp:dhcp6-subnet>
              </litp:dhcp6-service-subnets-collection>
            </litp:dhcp6-service>

        For more information, see "Manage DHCPv4 Service Configuration" \
and "Manage DHCPv6 Service Configuration" \
from :ref:`LITP References <litp-references>`.

        '''

        tasks = []

        initial_and_update_tasks = self._new_tasks(plugin_api_context)
        tasks.extend(initial_and_update_tasks)

        removal_tasks = self._removal_tasks(plugin_api_context)
        tasks.extend(removal_tasks)

        return tasks

    def _new_tasks(self, context):

        tasks = []

        peer_nodes = [node for node in context.query("node")
                      if not node.is_for_removal()]

        # DHCP is only configured on the peer nodes
        for node in peer_nodes:
            for svc in DhcpservicePlugin._all_dhcp_services(node):
                tasks += self._pool_tasks(context, peer_nodes, node, svc)
                tasks += self._service_tasks(context, peer_nodes, node, svc)

        return tasks

    def _pool_tasks(self, context, peer_nodes, node, svc):

        pool_tasks = []

        failover = (True
                    if self._get_peer_address(context, svc) and
                      DhcpservicePlugin._is_service_version4(svc)
                    else False)

        failover_added = DhcpservicePlugin._peer_v4_service_added(
                                                            peer_nodes, svc)

        failover_removed = DhcpservicePlugin._peer_service_removed(
                                                            peer_nodes, svc)

        for subnet in DhcpservicePlugin._dhcp_subnets(svc):
            initial_items = \
                DhcpservicePlugin._get_subnet_items_by_state(
                                                subnet, 'initial')
            updated_items = \
                DhcpservicePlugin._get_subnet_items_by_state(
                                                subnet, 'updated')

            if initial_items or updated_items or \
               failover_added or failover_removed:
                #1st - ensure primary model item is subnet
                #2nd - add in any range model items in initial state
                #3rd - add any ranges in updated state
                #Only one task needed for this operation
                model_items = [subnet] + initial_items + updated_items
                msg = DhcpservicePlugin._subnet_message(node, svc, subnet)
                kwargs = self._get_pool_args(context, subnet, node, failover)
                task = self._generate_dhcp_pool_task(msg, node, subnet,
                                                     model_items, kwargs)
                pool_tasks.append(task)

        return pool_tasks

    def _service_tasks(self, context, peer_nodes, node, service):

        tasks = []

        failover_removed = DhcpservicePlugin._peer_service_removed(
                                                    peer_nodes, service)
        subs_in_initial_state = DhcpservicePlugin.\
                            _subnets_in_initial_state(service)
        # The Server config task should be created if
        # the dhcp-service is new or new dhcp-subnets
        # were added to an existing dhcp-service.
        if service.is_initial() or service.is_updated() or \
           subs_in_initial_state or \
           DhcpservicePlugin._peer_v4_service_added(peer_nodes, service) or \
           failover_removed or \
           DhcpservicePlugin._network_changes(node, service):
            #primary model item
            items = [service]
            #add any model items of subs that are initial
            items += subs_in_initial_state
            #add any subnet model items that are updated
            #add any nic model items that have changed network
            items += DhcpservicePlugin._network_changes(node, service)

            msg = DhcpservicePlugin._server_message(peer_nodes,
                                                    node, service)

            kwargs = self._get_dhcp_config_args(peer_nodes, context, node,
                                                service, failover_removed)

            task = self._generate_dhcp_config_task(msg, node, service,
                                                   items, kwargs)
            tasks.append(task)

        return tasks

    @staticmethod
    def _subnets_in_initial_state(svc):
        subnets = DhcpservicePlugin._dhcp_subnets(svc)
        return DhcpservicePlugin._items_in_state_initial(subnets)

    @staticmethod
    def _items_in_state_initial(items):
        return [i for i in items if i.is_initial()]

    @staticmethod
    def _single_non_primary_server(peer_nodes, svc):

        if svc.primary == 'true':
            return False
        elif svc.primary == 'false':
            for other_node in peer_nodes:
                for other_svc in DhcpservicePlugin.\
                              _dhcp_services(other_node, svc.item_type_id):
                    if DhcpservicePlugin._peer_server_is_present(svc,
                                                                 other_svc):
                        return False
        return True

    @staticmethod
    def _peer_v4_service_added(peer_nodes, svc):

        if DhcpservicePlugin._is_service_version4(svc):
            for other_node in peer_nodes:
                for other_svc in DhcpservicePlugin._dhcp_services(
                                                            other_node):
                    if DhcpservicePlugin._peer_server_is_present(svc,
                                                            other_svc):
                        if other_svc.is_initial():
                            return True

    @staticmethod
    def _peer_service_removed(peer_nodes, svc):

        #In the v6 case we only want to update the remaining
        #service if it is non-primary
        if DhcpservicePlugin._is_service_version4(svc) or \
           (not DhcpservicePlugin._is_service_version4(svc) and \
            svc.primary == 'false'):
            for other_node in peer_nodes:
                for other_svc in DhcpservicePlugin.\
                        _all_present_and_for_removal_services(other_node):
                    if DhcpservicePlugin._peer_server_is_present(svc,\
                                                              other_svc):
                        if other_svc.is_for_removal():
                            return True

    @staticmethod
    def _subnet_message(node, service, subnet):
        subnet_version = DhcpservicePlugin._subnet_version(service)
        range_version = DhcpservicePlugin._range_version(service)
        if subnet.is_initial():
            msg = ('Configure "%s" and "%s" on network "%s" on node "%s"') % \
                  (subnet_version, range_version,
                   subnet.network_name, node.hostname)
        else:
            initial_ranges = DhcpservicePlugin._get_items_by_state(
                                                    subnet.ranges, 'initial')
            updated_ranges = DhcpservicePlugin._get_items_by_state(
                                                    subnet.ranges, 'updated')
            msg = 'Update "{0}"'.format(subnet_version)
            if len(updated_ranges) != 0:
                msg += ', update "{0}" {1}'.format(
                    range_version,
                    ', '.join(
                        ['"%s"' % rng.item_id for rng in updated_ranges]
                        )
                    )
            if len(initial_ranges) != 0:
                msg += ', add "{0}" {1}'.format(
                    range_version,
                    ', '.join(
                        ['"%s"' % rng.item_id for rng in initial_ranges]
                        )
                    )
            msg += ' on network "{0}" on node "{1}"'.format(
                subnet.network_name,
                node.hostname
                )
        return msg

    @staticmethod
    def _server_message(peer_nodes, node, service):

        svc_version = DhcpservicePlugin._service_version(service)

        if DhcpservicePlugin._network_changes(node, service) \
            or service.is_updated() or \
            ((DhcpservicePlugin._peer_v4_service_added(peer_nodes, service)
            or DhcpservicePlugin._peer_service_removed(
                                                     peer_nodes, service)) \
            and not service.is_initial()):
            state = 'Update'
        else:
            state = 'Configure'

        return  ('%s "%s" "%s" on node "%s"' %
                 (state, svc_version, service.service_name, node.hostname))

    @staticmethod
    def _network_changes(node, svc):
        return DhcpservicePlugin._subnet_network_name_changed(svc) + \
               DhcpservicePlugin._dhcp_interfaces_network_changed(node, svc)

    @staticmethod
    def _get_subnet_items_by_state(subnet, state):
        all_items = DhcpservicePlugin._flatten([subnet, subnet.ranges])
        return DhcpservicePlugin._get_items_by_state(all_items, state)

    @staticmethod
    def _get_items_by_state(all_items, state):
        items_in_state = []

        for item in all_items:
            if 'initial' == state and item.is_initial():
                items_in_state.append(item)
            elif 'updated' == state and item.is_updated():
                items_in_state.append(item)

        return items_in_state

    @staticmethod
    def _flatten(container):
        items = []
        for i in container:
            if isinstance(i, list) or \
               isinstance(i._model_item, CollectionItem):
                items.extend(DhcpservicePlugin._flatten(i))
            else:
                items.append(i)

        return items

    @staticmethod
    def _subnet_network_name_changed(service):

        changed_subnets = []

        for subnet in DhcpservicePlugin._dhcp_subnets(service):
            if subnet.is_updated():
                if subnet.applied_properties['network_name'] \
                           != subnet.network_name:
                    changed_subnets.append(subnet)
        return changed_subnets

    def _removal_tasks(self, context):

        tasks = []

        peer_nodes = [node for node in context.query("node")
                      if not node.is_for_removal()]

        #DHCP is only configured on the peer nodes
        for node in peer_nodes:
            for svc in DhcpservicePlugin.\
                               _all_present_and_for_removal_services(node):

                subnet_tasks = []
                # What about the removal of dhcp-range items?
                # Hmm, that can't happen with Litp inheritance

                # Hmm, maybe removal of dhcp-subnet items can't happen either!
                for sub in svc.subnets:
                    if sub.is_for_removal():
                        subnet_version = DhcpservicePlugin._subnet_version(svc)
                        msg = ('Deconfigure "%s" "%s" on node "%s"' %
                               (subnet_version, sub.item_id, node.hostname))
                        subnet_tasks.append(self._generate_subnet_removal_task(
                                                               msg, node, sub))

                if subnet_tasks:
                    tasks.extend(subnet_tasks)

                if svc.is_for_removal():
                    svc_version = DhcpservicePlugin._service_version(svc)
                    msg = ('Deconfigure "%s" "%s" on node "%s"' %
                           (svc_version, svc.service_name, node.hostname))
                    task = self._generate_dhcp_removal_task(msg, node, svc)
                    tasks.append(task)

                    if subnet_tasks:
                        for st in subnet_tasks:
                            task.requires.add(st)

        return tasks

    def _generate_dhcp_pool_task(self, msg, node, sub, items, kwargs):

        items = DhcpservicePlugin._reorder_item_list(sub, items)

        call_type = DhcpservicePlugin._pool_task_call_type(sub)

        task = ConfigTask(node, items[0], msg,
                          call_type,
                          DhcpservicePlugin._gen_hash_path(sub),
                          **kwargs)

        DhcpservicePlugin._add_model_items_to_task(task, items)

        log.trace.debug('Add %s task: "%s"' % (sub.item_type_id, task))

        return task

    @staticmethod
    def _add_model_items_to_task(task, items):
        for item in items[1:]:
            task.model_items.add(item)

    @staticmethod
    def _gen_service_call_id(svc):
        return (DhcpservicePlugin.DHCP_CALL_ID +
                '_' +
                DhcpservicePlugin._gen_hash_path(svc))

    @staticmethod
    def _gen_hash_path(item):
        return hashlib.md5(item.get_vpath()).hexdigest()

    @staticmethod
    def _reorder_item_list(primary_item, items):
        if primary_item in items:
            items = [primary_item] + \
                    [item for item in items if item != primary_item]
        return items

    def _generate_dhcp_config_task(self, msg, node, svc, items, kwargs):

        items = DhcpservicePlugin._reorder_item_list(svc, items)

        call_type = DhcpservicePlugin._config_task_call_type(svc)

        task = ConfigTask(node, items[0], msg,
                          call_type,
                          DhcpservicePlugin._gen_service_call_id(svc),
                          **kwargs)

        DhcpservicePlugin._add_model_items_to_task(task, items)

        log.trace.debug('Add %s task: "%s"' % (svc.item_type_id, task))

        return task

    def _generate_dhcp_removal_task(self, msg, node, svc):

        call_type = DhcpservicePlugin._config_task_call_type(svc)

        task = ConfigTask(node, svc, msg,
                          call_type,
                          DhcpservicePlugin._gen_service_call_id(svc),
                          ensure='absent')

        log.trace.debug('Add %s task: "%s"' % (svc.item_type_id, task))

        return task

    def _generate_subnet_removal_task(self, msg, node, subnet):
        return self._generate_dhcp_pool_task(msg, node, subnet, [subnet],
                                             {'ensure': 'absent'})

    def _get_pool_args(self, context, dhcp_subnet, node, failover=False):
        """
        Build appropriate dictionary of properties to enable
        the creation of the address pool depending on the
        defined properties of the underlying dhcp-subnet items
        and their underlying dhcp-range items.
        """

        kwargs = {}

        if dhcp_subnet.item_type_id == 'dhcp-subnet':

            subnet = (DhcpservicePlugin.
                         _get_ipv4_network_address(context, dhcp_subnet))

            kwargs['network'] = str(subnet.network)
            kwargs['mask'] = str(subnet.netmask)

            if failover:
                kwargs['failover'] = 'true'

        elif dhcp_subnet.item_type_id == 'dhcp6-subnet':
            subnet = (DhcpservicePlugin.
                             _get_ipv6_network_address(node, dhcp_subnet))

            kwargs['network'] = str(subnet)

        kwargs['ranges'] = self._get_ranges_as_list(dhcp_subnet)

        return kwargs

    def _get_dhcp_config_args(self, peer_nodes, context,
                              node, svc, failover_removed=False):
        """
        Build appropriate dictionary of properties for the DHCP task
        depending on the defined properties of the node and its underlying
        dhcp-service.
        """

        kwargs = {}

        kwargs['interfaces'] = [iface.device_name for iface in
                                self._get_current_dhcp_interfaces(node, svc)]

        if hasattr(svc, 'ntpservers') and svc.ntpservers:
            kwargs['ntpservers'] = [ntps.strip() for ntps in
                                    svc.ntpservers.split(',')]

        if hasattr(svc, 'nameservers') and svc.nameservers:
            kwargs['nameservers'] = [name.strip() for name in
                                     svc.nameservers.split(',')]

        if hasattr(svc, 'domainsearch') and svc.domainsearch:
            kwargs['domainsearch'] = [ds.strip() for ds in
                                      svc.domainsearch.split(',')]

        #If the 'primary' server is removed from a pair of services
        #instate the other server as 'primary' by writing to the model
        #primary='true' for the service in question
        if DhcpservicePlugin._single_non_primary_server(peer_nodes, svc) \
                or failover_removed:
            svc.primary = 'true'
            kwargs['role'] = 'primary'
        else:
            if svc.primary == 'false':
                kwargs['role'] = 'secondary'
            else:
                kwargs['role'] = 'primary'

        if DhcpservicePlugin._is_service_version4(svc):
            mgmt_address = self._get_mgmt_ip_of_node(context, node)
            mgmt_peer_address = self._get_peer_address(context, svc)
            if mgmt_address:
                kwargs['address'] = mgmt_address
            if mgmt_peer_address:
                kwargs['peer_address'] = mgmt_peer_address

        # Defaulted values. Not exposed yet to CLI
        kwargs['default_lease_time'] = DhcpservicePlugin.DEFAULT_LEASE_TIME
        kwargs['max_lease_time'] = DhcpservicePlugin.MAX_LEASE_TIME

        return kwargs
