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
"""Unittest for windows_powershell rendering module."""

from absl.testing import absltest

from aerleon.lib import naming, policy, windows_powershell
from tests.regression_utils import capture

HEADER_IN = """
header {
  comment:: "inbound test acl"
  target:: windows_powershell in
}
"""

HEADER_IN_BLOCK = """
header {
  comment:: "inbound default deny"
  target:: windows_powershell in block
}
"""

HEADER_IN_INET6 = """
header {
  target:: windows_powershell in inet6
}
"""

HEADER_OUT = """
header {
  comment:: "outbound test acl"
  target:: windows_powershell out
}
"""

HEADER_OUT_PERMIT = """
header {
  target:: windows_powershell out permit
}
"""

TERM_SSH = """
term allow-ssh {
  comment:: "it's the management network"
  source-address:: MGMT
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

TERM_DNS_OUT = """
term allow-dns {
  destination-address:: RESOLVERS
  destination-port:: DNS
  protocol:: udp
  action:: accept
}
"""

TERM_MULTIPROTO = """
term allow-rdp {
  source-address:: MGMT
  destination-port:: RDP
  protocol:: tcp udp
  action:: accept
}
"""

TERM_ICMP = """
term allow-icmp {
  protocol:: icmp
  action:: accept
}
"""

TERM_ICMP_TYPES = """
term allow-echo {
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

TERM_ICMPV6_TYPES = """
term allow-ndp {
  protocol:: icmpv6
  icmp-type:: neighbor-solicit neighbor-advertisement
  action:: accept
}
"""

TERM_MISCPROTO = """
term deny-vrrp {
  protocol:: vrrp
  action:: deny
}
"""

TERM_ANY = """
term allow-any {
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'stateless_reply',
    'name',
    'option',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
}

EXP_INFO = 2


class WindowsPowerShellTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()
        self.naming._ParseLine('MGMT = 192.0.2.0/24 2001:db8::/64', 'networks')
        self.naming._ParseLine('RESOLVERS = 198.51.100.53/32', 'networks')
        self.naming._ParseLine('SSH = 22/tcp', 'services')
        self.naming._ParseLine('DNS = 53/udp', 'services')
        self.naming._ParseLine('RDP = 3389/tcp 3389/udp', 'services')

    def _Render(self, text, filename='host1.pol'):
        acl = windows_powershell.WindowsPowerShell(
            policy.ParsePolicy(text, self.naming, filename=filename), EXP_INFO
        )
        return str(acl)

    def _Rules(self, text):
        return [
            line
            for line in self._Render(text).splitlines()
            if line.startswith('New-NetFirewallRule')
        ]

    @capture.stdout
    def testPolicy(self):
        print(
            self._Render(
                HEADER_IN_BLOCK
                + TERM_ICMP
                + TERM_ICMPV6_TYPES
                + TERM_SSH
                + TERM_MULTIPROTO
                + TERM_MISCPROTO
                + HEADER_OUT
                + TERM_DNS_OUT
                + TERM_ANY
            )
        )

    def testInboundAddressesAreRemote(self):
        rules = self._Rules(HEADER_IN + TERM_SSH)
        self.assertEqual(len(rules), 1, rules)
        self.assertIn("-Direction Inbound -Protocol TCP", rules[0])
        self.assertIn("-RemoteAddress '192.0.2.0/24','2001:db8::/64' -LocalPort '22'", rules[0])

    def testOutboundAddressesAreRemote(self):
        rules = self._Rules(HEADER_OUT + TERM_DNS_OUT)
        self.assertIn("-RemoteAddress '198.51.100.53/32' -RemotePort '53'", rules[0])
        self.assertNotIn('-LocalAddress', rules[0])

    def testOneRulePerProtocol(self):
        rules = self._Rules(HEADER_IN + TERM_MULTIPROTO)
        self.assertEqual(len(rules), 2, rules)
        self.assertIn('-Protocol TCP', rules[0])
        self.assertIn('-Protocol UDP', rules[1])

    def testAnyAddressIsOmitted(self):
        rules = self._Rules(HEADER_OUT + TERM_ANY)
        self.assertNotIn('Address', rules[0])
        self.assertIn('-Protocol Any', rules[0])

    def testIcmpTypes(self):
        rules = self._Rules(HEADER_IN + TERM_ICMP_TYPES)
        self.assertIn("-Protocol ICMPv4 -IcmpType '0','8'", rules[0])

    def testIcmpv6TypesUnderMixed(self):
        rules = self._Rules(HEADER_IN + TERM_ICMPV6_TYPES)
        self.assertIn("-Protocol ICMPv6 -IcmpType '135','136'", rules[0])

    def testInet6DropsIcmp(self):
        rules = self._Rules(HEADER_IN_INET6 + TERM_ICMP + TERM_ICMPV6_TYPES)
        self.assertEqual(len(rules), 1, rules)
        self.assertIn('ICMPv6', rules[0])

    def testMiscProtocolByNumber(self):
        rules = self._Rules(HEADER_IN + TERM_MISCPROTO)
        self.assertIn('-Protocol 112 -Action Block', rules[0])

    def testDescriptionQuoting(self):
        rules = self._Rules(HEADER_IN + TERM_SSH)
        self.assertIn("-Description 'it''s the management network'", rules[0])

    def testDefaultActions(self):
        text = self._Render(HEADER_IN_BLOCK + TERM_SSH + HEADER_OUT_PERMIT + TERM_ANY)
        self.assertIn('Set-NetFirewallProfile -All -DefaultInboundAction Block', text)
        self.assertIn('Set-NetFirewallProfile -All -DefaultOutboundAction Allow', text)

    def testGroupFromFilename(self):
        text = self._Render(HEADER_IN + TERM_SSH, filename='policies/pol/web-01.example.com.yaml')
        self.assertIn("-Group 'aerleon-web-01.example.com'", text)

    def testGroupClearedOncePerPolicy(self):
        """Two filters in one direction must not clear each other's rules."""
        lines = self._Render(
            HEADER_IN + TERM_SSH + HEADER_IN_INET6 + TERM_ICMPV6_TYPES
        ).splitlines()
        removes = [i for i, line in enumerate(lines) if 'Remove-NetFirewallRule' in line]
        rules = [i for i, line in enumerate(lines) if line.startswith('New-NetFirewallRule')]
        self.assertEqual(len(removes), 1, lines)
        self.assertLess(removes[0], rules[0])

    def testNoBatchCommentLeader(self):
        """':' is not a comment in PowerShell (#495)."""
        text = self._Render(HEADER_IN + TERM_SSH)
        self.assertFalse([line for line in text.splitlines() if line.startswith(':')], text)

    def testBuildTokens(self):
        acl = windows_powershell.WindowsPowerShell(
            policy.ParsePolicy(HEADER_IN + TERM_SSH, self.naming), EXP_INFO
        )
        st, _ = acl._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)


if __name__ == '__main__':
    absltest.main()
