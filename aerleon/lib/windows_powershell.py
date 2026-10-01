# Copyright 2026 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Windows Firewall policy generator using the PowerShell NetSecurity cmdlets.

Writes the same rules as windows_advfirewall, through New-NetFirewallRule
instead of netsh, so the output is a PowerShell script rather than a batch
file. Every rule is tagged with a per-policy group, and the script first
removes that group, so running it again replaces the policy instead of adding
a second copy of it.
"""

import os

from aerleon.lib import aclgenerator, windows
from aerleon.lib.nacaddr import IPv4, IPv6


def _Quote(value) -> str:
    """Single-quote a PowerShell string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _QuoteList(values) -> str:
    return ','.join(_Quote(v) for v in values)


class Term(windows.Term):
    """Generate one New-NetFirewallRule command per protocol of a term."""

    _PLATFORM = 'windows_powershell'

    _ACTION_TABLE = {
        'accept': 'Allow',
        'deny': 'Block',
        'reject': 'Block',
    }

    _DIRECTION_TABLE = {
        'in': 'Inbound',
        'out': 'Outbound',
    }

    # Protocols New-NetFirewallRule takes by name; anything else goes by number.
    _PROTOCOL_TABLE = {
        'tcp': 'TCP',
        'udp': 'UDP',
        'icmp': 'ICMPv4',
        'icmpv6': 'ICMPv6',
        'any': 'Any',
    }

    # Set by the generator; the group the policy's rules are created in.
    group = None

    def _HandleIcmpTypes(
        self, icmp_types: list[str], protocols: list[str]
    ) -> tuple[list[str], list[str]]:
        types = []
        if icmp_types:
            types = [str(t) for t in self.NormalizeIcmpTypes(icmp_types, protocols, self.af)]
        return types, protocols

    def _HandlePorts(
        self, src_ports: list[tuple[int, int]], dst_ports: list[tuple[int, int]]
    ) -> tuple[list[list[str]], list[list[str]]]:
        return [self._PortList(src_ports)], [self._PortList(dst_ports)]

    @staticmethod
    def _PortList(ports: list[tuple[int, int]]) -> list[str]:
        return [str(start) if start == end else f'{start}-{end}' for start, end in ports]

    def _CartesianProduct(
        self,
        src_addr: list[IPv4 | IPv6],
        dst_addr: list[IPv4 | IPv6],
        protocol: list[str],
        icmp_types: list[str],
        src_port: list[list[str]],
        dst_port: list[list[str]],
        ret_str: list[str],
    ) -> None:
        # The cmdlet takes address and port lists, so each protocol is one rule.
        direction = self.filter.lower()
        if direction == 'in':
            local_addr, remote_addr = dst_addr, src_addr
            local_port, remote_port = dst_port[0], src_port[0]
        elif direction == 'out':
            local_addr, remote_addr = src_addr, dst_addr
            local_port, remote_port = src_port[0], dst_port[0]
        else:
            raise aclgenerator.UnsupportedFilterError(
                f'Unrecognized windows_powershell direction: {self.filter}'
            )

        commands = [
            self._ComposeRule(
                direction, proto, local_addr, remote_addr, local_port, remote_port, icmp_types
            )
            for proto in protocol
        ]
        ret_str.extend(dict.fromkeys(commands))

    def _ComposeRule(
        self,
        direction: str,
        proto: str,
        local_addr: list[IPv4 | IPv6],
        remote_addr: list[IPv4 | IPv6],
        local_port: list[str],
        remote_port: list[str],
        icmp_types: list[str],
    ) -> str:
        if (local_port or remote_port) and proto not in ('tcp', 'udp'):
            raise aclgenerator.UnsupportedFilterError(
                f'Term {self.term.name}: ports may only be used with tcp or udp'
                f' in {self._PLATFORM}, not {proto}'
            )

        atoms = [f'-DisplayName {_Quote(self.term_name)}']
        if self.group:
            atoms.append(f'-Group {_Quote(self.group)}')
        atoms.append(f'-Direction {self._DIRECTION_TABLE[direction]}')
        atoms.append(f'-Protocol {self._Protocol(proto)}')
        if icmp_types:
            atoms.append(f'-IcmpType {_QuoteList(icmp_types)}')
        # An address list of only /0 prefixes is the cmdlet default, Any.
        if not all(a.prefixlen == 0 for a in local_addr):
            atoms.append(f'-LocalAddress {_QuoteList(dict.fromkeys(str(a) for a in local_addr))}')
        if not all(a.prefixlen == 0 for a in remote_addr):
            atoms.append(
                f'-RemoteAddress {_QuoteList(dict.fromkeys(str(a) for a in remote_addr))}'
            )
        if local_port:
            atoms.append(f'-LocalPort {_QuoteList(local_port)}')
        if remote_port:
            atoms.append(f'-RemotePort {_QuoteList(remote_port)}')
        atoms.append(f'-Action {self._ACTION_TABLE[self.term.action[0]]}')
        if self.term.comment:
            atoms.append(f'-Description {_Quote(" ".join(self.term.comment))}')

        return 'New-NetFirewallRule ' + ' '.join(atoms) + ' | Out-Null'

    def _Protocol(self, proto: str) -> str:
        if proto in self._PROTOCOL_TABLE:
            return self._PROTOCOL_TABLE[proto]
        if proto in self.PROTO_MAP:
            return str(self.PROTO_MAP[proto])
        return str(proto)


class WindowsPowerShell(windows.WindowsGenerator):
    """Generates a PowerShell script of NetSecurity firewall rules."""

    _PLATFORM = 'windows_powershell'
    _TERM = Term
    SUFFIX = '.ps1'
    _COMMENT_PREFIX = '#'

    _DEFAULT_ACTION_PARAM = {
        'in': 'DefaultInboundAction',
        'out': 'DefaultOutboundAction',
    }

    def _TranslatePolicy(self, pol, exp_info: int) -> None:
        super()._TranslatePolicy(pol, exp_info)
        name = os.path.splitext(os.path.basename(pol.filename or ''))[0] or 'policy'
        self.group = f'aerleon-{name}'
        for *_, terms in self.windows_policies:
            for term in terms:
                term.group = self.group
        # Once per policy, not per filter: a second filter in the same
        # direction must not remove the rules the first one just added.
        self._RENDER_PREFIX = '\n'.join(
            [
                '# Remove the rules a previous run of this policy created.',
                f'Get-NetFirewallRule -Group {_Quote(self.group)} -ErrorAction SilentlyContinue'
                ' | Remove-NetFirewallRule',
            ]
        )

    def _HandleDefaultAction(self, header, default_action: str, target: list[str]) -> None:
        direction = header.FilterName(self._PLATFORM).lower()
        param = self._DEFAULT_ACTION_PARAM.get(direction)
        if param is None:
            raise aclgenerator.UnsupportedFilterError(
                f'Unrecognized windows_powershell direction: {direction}'
            )
        value = 'Block' if default_action == 'block' else 'Allow'
        # Applies to every profile, as the generated rules do.
        target.append(f'Set-NetFirewallProfile -All -{param} {value}')
