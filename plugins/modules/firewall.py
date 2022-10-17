#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This module contains all of the functionality for Linode Firewalls."""

from __future__ import absolute_import, division, print_function

import copy
from typing import Optional, List, Any

import ipaddress
from ansible_collections.linode.cloud.plugins.module_utils.linode_common import LinodeModuleBase
from ansible_collections.linode.cloud.plugins.module_utils.linode_helper import \
    filter_null_values, mapping_to_dict, paginated_list_to_json, filter_null_values_recursive
from ansible_collections.linode.cloud.plugins.module_utils.linode_docs import global_authors, \
    global_requirements
import ansible_collections.linode.cloud.plugins.module_utils.doc_fragments.firewall as docs

try:
    from linode_api4 import Firewall, FirewallDevice
except ImportError:
    # handled in module_utils.linode_common
    pass

linode_firewall_addresses_spec: dict = dict(
    ipv4=dict(type='list', elements='str',
              description=[
                  'A list of IPv4 addresses or networks.',
                  'Must be in IP/mask format.'
              ]),
    ipv6=dict(type='list', elements='str',
              description=[
                  'A list of IPv4 addresses or networks.',
                  'Must be in IP/mask format.'
              ])
)

linode_firewall_rule_spec: dict = dict(
    label=dict(type='str', required=True,
               description=[
                   'The label of this rule.'
               ]),
    action=dict(type='str', required=True,
                description=[
                    'Controls whether traffic is accepted or dropped by this rule.'
                ]),
    addresses=dict(type='dict', options=linode_firewall_addresses_spec,
                   description=[
                       'Allowed IPv4 or IPv6 addresses.'
                   ]),
    description=dict(type='str',
                     description=[
                         'A description for this rule.'
                     ]),
    ports=dict(type='str',
               description=[
                   'A string representing the port or ports on which traffic will be allowed.',
                   'See U(https://www.linode.com/docs/api/networking/#firewall-create)'
               ]),
    protocol=dict(type='str',
                  description=[
                      'The type of network traffic to allow.'
                  ])
)

linode_firewall_rules_spec: dict = dict(
    inbound=dict(type='list', elements='dict', options=linode_firewall_rule_spec,
                 description=[
                     'A list of rules for inbound traffic.'
                 ]),
    inbound_policy=dict(type='str',
                        description=[
                            'The default behavior for inbound traffic.'
                        ]),
    outbound=dict(type='list', elements='dict', options=linode_firewall_rule_spec,
                  description=[
                      'A list of rules for outbound traffic.'
                  ]),
    outbound_policy=dict(type='str',
                         description=[
                             'The default behavior for outbound traffic.'
                         ]),
)

linode_firewall_device_spec: dict = dict(
    id=dict(type='int', required=True,
            description=[
                'The unique ID of the device to attach to this Firewall.'
            ]),
    type=dict(type='str', default='linode',
              description=[
                  'The type of device to be attached to this Firewall.'
              ])
)

linode_firewall_spec: dict = dict(
    label=dict(type='str',
               description=[
                    'The unique label to give this Firewall.'
                ]),
    devices=dict(type='list', elements='dict', options=linode_firewall_device_spec,
                 description=[
                     'The devices that are attached to this Firewall.'
                 ]),
    rules=dict(type='dict', options=linode_firewall_rules_spec,
               description=[
                   'The inbound and outbound access rules to apply to this Firewall.'
               ]),
    status=dict(type='str',
                description=[
                    'The status of this Firewall.'
                ]),
    state=dict(type='str',
               description='The desired state of the target.',
               choices=['present', 'absent'], required=True),
    change=dict(type='str',
                description='The rule change action to take.',
                default='all',
                choices=['all', 'delta+', 'delta-'])
)


specdoc_meta = dict(
    description=[
        'Manage Linode Firewalls.'
    ],
    requirements=global_requirements,
    author=global_authors,
    spec=linode_firewall_spec,
    examples=docs.specdoc_examples,
    return_values=dict(
        firewall=dict(
            description='The Firewall description in JSON serialized form.',
            docs_url='https://www.linode.com/docs/api/networking/#firewall-view',
            type='dict',
            sample=docs.result_firewall_samples
        ),
        devices=dict(
            description='A list of Firewall devices JSON serialized form.',
            docs_url='https://www.linode.com/docs/api/networking/#firewall-device-view',
            type='list',
            sample=docs.result_devices_samples
        )
    )
)


# Fields that can be updated on an existing Firewall
linode_firewall_mutable: List[str] = [
    'status',
    'tags'
]


class LinodeFirewall(LinodeModuleBase):
    """Module for creating and destroying Linode Firewalls"""

    def __init__(self) -> None:
        self.module_arg_spec = linode_firewall_spec

        self.results: dict = dict(
            changed=False,
            actions=[],
            firewall=None,
            devices=None
        )

        self._firewall: Optional[Firewall] = None

        super().__init__(module_arg_spec=self.module_arg_spec)

    def _get_firewall_by_label(self, label: str) -> Optional[Firewall]:
        try:
            return self.client.networking.firewalls(Firewall.label == label)[0]
        except IndexError:
            return None
        except Exception as exception:
            return self.fail(msg='failed to get firewall {0}: {1}'.format(label, exception))

    def _create_firewall(self) -> dict:
        params = self.module.params

        label = params.get('label')
        rules = filter_null_values_recursive(params['rules'])
        tags = params['tags']
        try:
            result = self.client.networking.firewall_create(label, rules=rules, tags=tags)
        except Exception as exception:
            self.fail(msg='failed to create firewall: {0}'.format(exception))

        return result

    def _create_device(self, device_id: int, device_type: str, **spec_args: Any) -> None:
        self._firewall.device_create(device_id, device_type, **spec_args)
        self.register_action('Created device {0} of type {1}'.format(
            device_id, device_type))

    def _delete_device(self, device: FirewallDevice) -> None:
        self.register_action('Deleted device {0} of type {1}'.format(
            device.entity.id, device.entity.type))
        device.delete()

    def _update_devices(self, spec_devices: list) -> None:
        # Remove devices that are not present in config
        device_map = {}

        for device in self._firewall.devices:
            device_map[device.entity.id] = device

        # Handle creating/keeping existing devices
        for device in spec_devices:
            device_entity_id = device.get('id')
            device_entity_type = device.get('type')

            if device_entity_id in device_map:
                if device_map[device_entity_id].entity.type == device_entity_type:
                    del device_map[device_entity_id]
                    continue

                # Recreate the device if the fields don't match
                self._delete_device(device_map[device_entity_id])

            self._create_device(device_entity_id, device_entity_type)

        # Delete unused devices
        for device in device_map.values():
            self._delete_device(device)

    @staticmethod
    def _normalize_addresses(rules: list) -> list:
        result = []
        for rule in rules:
            item = copy.deepcopy(rule)

            addresses = rule['addresses']

            if 'ipv6' in addresses:
                item['addresses']['ipv6'] = [str(ipaddress.IPv6Network(v))
                                             for v in addresses['ipv6']]

            if 'ipv4' in addresses:
                item['addresses']['ipv4'] = [str(ipaddress.IPv4Network(v))
                                             for v in addresses['ipv4']]

            result.append(item)

        return result

    def _change_rules(self, change: str) -> list:
        """Changes remote firewall rules relative to user-supplied new rules, and returns whether anything changed."""
        local_rules = filter_null_values_recursive(self.module.params['rules'])
        remote_rules = filter_null_values_recursive(mapping_to_dict(self._firewall.rules))

        # Normalize IP addresses for all rules
        for field in ['inbound', 'outbound']:
            local_rules[field] = self._normalize_addresses(local_rules[field]) if field in local_rules else []
            remote_rules[field] = self._normalize_addresses(remote_rules[field]) if field in remote_rules else []

        if change != "all":
            # add/delete IP addresses specified from in/out bound rules
            for field in ['inbound', 'outbound']:
                self._change_rule(remote_rules[field],local_rules[field],change)

            # When adding/deleting ips, the relevant inbound/outbound
            # rules are adjusted; and all other rules are not supplied
            # by the user. For this reson, sync the missing rules as
            # the REST API expects to fully update a
            # linode_firewall_rules spec.
            for field in ['inbound', 'inbound_policy', 'outbound', 'outbound_policy']:
                if field not in local_rules:
                    local_rules[field]=remote_rules[field]

        local_rules = filter_null_values_recursive(local_rules)
        return local_rules if local_rules != remote_rules else []

    @staticmethod
    def _get_labeled_rules(rules: list) -> dict:
        labels = {}
        for rule in rules:
            if 'label' in rule: 
                labels[rule['label']]=rule
        return labels
        
    def _change_rule(self, remote_rules: list, local_rules: list, change: str) -> None:
        # User specified to either add or del addresses in rules

        local_labeled_rules = self._get_labeled_rules(local_rules)
        remote_labeled_rules = self._get_labeled_rules(remote_rules)

        for local_label, local_rule in local_labeled_rules.items():
            if local_label not in remote_labeled_rules:
                # When the local_rule does not exist in remote_rule, it will be created.
                # For this reason, it is ok to do nothing!
                continue

            # process changes in two phases:
            # 1) adjust addresses per change delta
            # 2) sync missing fields

            # update addresses
            for ip in ['ipv4','ipv6']:
                remote_rule = remote_labeled_rules[local_label]
                remote_set = set(remote_rule['addresses'].get(ip,[]))
                local_set = set(local_rule['addresses'].get(ip,[]))
                if change=='delta+':
                    result_set = remote_set.union(local_set)
                else: # change=='delta-'
                    result_set = remote_set.difference(local_set)
                local_rule['addresses'][ip] = sorted(list(result_set))
                
            # sync missing fields in local rules from remote rules
            for field in linode_firewall_rule_spec.keys():
                if field not in local_rule:
                    local_rule[field]=remote_rule[field]

        # insert all missing labeled remote rules to local rules
        for remote_label, remote_rule in remote_labeled_rules.items():
            if remote_label not in local_labeled_rules:
                local_rules.append(remote_rule)

    def _update_firewall(self, change: str) -> None:
        """Handles all update functionality for the current Firewall"""

        # Update mutable values
        should_update = False
        params = filter_null_values(self.module.params)

        for key, new_value in params.items():
            if not hasattr(self._firewall, key):
                continue

            old_value = getattr(self._firewall, key)

            if new_value != old_value:
                if key in linode_firewall_mutable:
                    setattr(self._firewall, key, new_value)
                    self.register_action('Updated Firewall {0}: "{1}" -> "{2}"'.
                                         format(key, old_value, new_value))

                    should_update = True

        if should_update:
            self._firewall.save()

        changes = self._change_rules(change)
        if changes:
            self._firewall.update_rules(changes)
            self.register_action('Updated Firewall rules')

        # Update devices
        devices: Optional[List[Any]] = params.get('devices')
        if devices is not None:
            self._update_devices(devices)

    def _handle_present(self, change: str) -> None:
        """Updates the Firewall"""
        label = self.module.params.get('label')

        self._firewall = self._get_firewall_by_label(label)

        if self._firewall is None:
            self._firewall = self._create_firewall()
            self.register_action('Created Firewall {0}'.format(label))

        self._update_firewall(change)

        self._firewall._api_get()

        self.results['firewall'] = self._firewall._raw_json
        self.results['devices'] = paginated_list_to_json(self._firewall.devices)

    def _handle_absent(self) -> None:
        """Destroys the Firewall"""
        label = self.module.params.get('label')

        self._firewall = self._get_firewall_by_label(label)

        if self._firewall is not None:
            self.results['firewall'] = self._firewall._raw_json
            self.results['devices'] = paginated_list_to_json(self._firewall.devices)
            self.register_action('Deleted Firewall {0}'.format(label))
            self._firewall.delete()

    def exec_module(self, **kwargs: Any) -> Optional[dict]:
        """Entrypoint for Firewall module"""

        state = kwargs.get('state')

        if state == 'absent':
            self._handle_absent()
            return self.results

        change = kwargs.get('change','all')
        self._handle_present(change)
        return self.results


def main() -> None:
    """Constructs and calls the Linode Firewall module"""

    LinodeFirewall()


if __name__ == '__main__':
    main()
