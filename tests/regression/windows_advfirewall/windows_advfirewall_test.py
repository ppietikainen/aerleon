# Copyright 2016 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
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
"""Unittest for windows_advfirewall rendering module."""

import datetime
from unittest import mock

from absl.testing import absltest

from aerleon.lib import aclgenerator, naming, policy, windows, windows_advfirewall
from tests.regression_utils import capture

GOOD_HEADER_OUT = """
header {
  comment:: "this is an out test acl"
  target:: windows_advfirewall out inet
}
"""

GOOD_HEADER_IN = """
header {
  comment:: "this is an in test acl"
  target:: windows_advfirewall in inet
}
"""

GOOD_SIMPLE = """
term good-simple {
  protocol:: tcp
  action:: accept
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "this is a mixed test acl"
  target:: windows_advfirewall in mixed
}
"""

MIXED_NO_ADDRESSES = """
term mixed-any {
  protocol:: tcp
  destination-port:: HTTPS
  action:: accept
}
"""

MIXED_DUAL_STACK = """
term mixed-dual {
  destination-address:: DUAL_NET
  protocol:: tcp
  destination-port:: HTTPS
  action:: accept
}
"""

MIXED_V4_ONLY = """
term mixed-v4 {
  destination-address:: V4_NET
  protocol:: tcp
  action:: accept
}
"""

GOOD_SIMPLE_WARNING = """
term good-simple-warning {
  protocol:: tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_ICMP = """
term good-term-icmp {
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_ANYPROTO = """
term good-term-anyproto {
  source-address:: FOO
  destination-address:: FOO
  action:: accept
}
"""

GOOD_TERM_MISCPROTO = """
term good-term-miscproto {
  protocol:: vrrp
  action:: accept
}
"""

# Edge case: protocol value for hopopt is 0
GOOD_TERM_HOPOPT = """
term good-term-hopopt {
  protocol:: hopopt
  action:: accept
}
"""

GOOD_TERM_ICMP_TYPES = """
term good-term-icmp-types {
  protocol:: icmp
  icmp-type:: echo-reply unreachable time-exceeded
  action:: deny
}
"""

GOOD_TERM_ICMPV6 = """
term good-term-icmpv6 {
  protocol:: icmpv6
  action:: accept
}
"""

BAD_TERM_ICMP = """
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

BAD_TERM_ACTION = """
term bad-term-action {
  protocol:: icmp
  action:: undefined
}
"""

GOOD_TERM_TCP = """
term good-term-tcp {
  comment:: "Test term 1"
  destination-address:: PROD_NETWRK
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_LOG = """
term good-term-log {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""

EXPIRED_TERM = """
term expired_test {
  expiration:: 2000-1-1
  action:: deny
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

NEXT_TERM = """
term next {
  action:: next
}
"""

NEXT_LOG_TERM = """
term next-log {
  logging:: true
  action:: next
}
"""

EXCEPTION_POLICY = """
header {
  comment:: "Header comment"
  target:: windows_advfirewall out inet
}

term accept-corpdns {
  comment:: "accept-corpdns comment1"
  comment:: "accept-corpdns comment2"
  destination-address:: CORP_ANYCAST_DNS
  destination-port:: DNS
  protocol:: udp
  action:: accept
}

term deny-to-google {
  comment:: "deny-to-google comment"
  destination-address:: INTERNAL
  action:: deny
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

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request',
        'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request',
        'information-reply',
        'mobile-prefix-advertisement',
        'mobile-prefix-solicitation',
        'multicast-listener-done',
        'multicast-listener-query',
        'multicast-listener-report',
        'multicast-router-advertisement',
        'multicast-router-solicitation',
        'multicast-router-termination',
        'neighbor-advertisement',
        'neighbor-solicit',
        'packet-too-big',
        'parameter-problem',
        'redirect',
        'redirect-message',
        'router-advertisement',
        'router-renumbering',
        'router-solicit',
        'router-solicitation',
        'source-quench',
        'time-exceeded',
        'timestamp-reply',
        'timestamp-request',
        'unreachable',
        'version-2-multicast-listener-report',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class WindowsAdvFirewallTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()

    def assertTrue(self, strings, result, term):
        for string in strings:
            fullstring = f'netsh advfirewall firewall add rule {string}'
            super().assertIn(
                fullstring,
                result,
                f'did not find "{fullstring}" for {term}\nGot:\n{result}',
            )

    @capture.stdout
    def testTcp(self):
        self.naming._ParseLine('PROD_NETWRK = 10.0.0.0/8', 'networks')
        self.naming._ParseLine('SMTP = 25/tcp', 'services')

        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + GOOD_TERM_TCP, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertTrue(
            [
                'name=o_good-term-tcp enable=yes interfacetype=any dir=out localip=any'
                ' remoteip=10.0.0.0/8 remoteport=25 protocol=tcp action=allow'
            ],
            result,
            'did not find actual term for good-term-tcp',
        )
        print(result)

    @capture.stdout
    def testIcmp(self):
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + GOOD_TERM_ICMP, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertTrue(
            [
                'name=o_good-term-icmp enable=yes interfacetype=any dir=out'
                ' localip=any remoteip=any protocol=icmpv4 action=allow'
            ],
            result,
            'did not find actual term for good-term-icmp',
        )
        print(result)

    @capture.stdout
    def testIcmpTypes(self):
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + GOOD_TERM_ICMP_TYPES, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertTrue(
            [
                'name=o_good-term-icmp-types enable=yes interfacetype=any dir=out'
                ' localip=any remoteip=any protocol=icmpv4:0,any action=block',
                'name=o_good-term-icmp-types enable=yes interfacetype=any dir=out'
                ' localip=any remoteip=any protocol=icmpv4:3,any action=block',
                'name=o_good-term-icmp-types enable=yes interfacetype=any dir=out'
                ' localip=any remoteip=any protocol=icmpv4:11,any action=block',
            ],
            result,
            'did not find actual term for good-term-icmp-types',
        )
        print(result)

    def testBadIcmp(self):
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + BAD_TERM_ICMP, self.naming), EXP_INFO
        )
        self.assertRaises(aclgenerator.UnsupportedFilterError, str, acl)

    @mock.patch.object(windows.logging, 'warning')
    def testExpiredTerm(self, mock_warn):
        windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + EXPIRED_TERM, self.naming), EXP_INFO
        )

        mock_warn.assert_called_once_with(
            'WARNING: Term %s in policy %s is expired ' 'and will not be rendered.',
            'expired_test',
            'out',
        )

    @mock.patch.object(windows.logging, 'info')
    def testExpiringTerm(self, mock_info):
        exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
        windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(
                GOOD_HEADER_OUT + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'), self.naming
            ),
            EXP_INFO,
        )

        mock_info.assert_called_once_with(
            'INFO: Term %s in policy %s expires in ' 'less than two weeks.', 'is_expiring', 'out'
        )

    @capture.stdout
    def testMultiprotocol(self):
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + MULTIPLE_PROTOCOLS_TERM, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertTrue(
            [
                'name=o_multi-proto enable=yes interfacetype=any dir=out localip=any'
                ' remoteip=any protocol=tcp action=allow',
                'name=o_multi-proto enable=yes interfacetype=any dir=out localip=any'
                ' remoteip=any protocol=udp action=allow',
                'name=o_multi-proto enable=yes interfacetype=any dir=out localip=any'
                ' remoteip=any protocol=icmpv4 action=allow',
            ],
            result,
            'did not find actual term for multi-proto',
        )
        print(result)

    @capture.stdout
    def testAnyProtocol(self):
        self.naming._ParseLine('FOO = 10.0.0.0/8', 'networks')
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_OUT + GOOD_TERM_ANYPROTO, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertTrue(
            [
                'name=o_good-term-anyproto enable=yes interfacetype=any dir=out'
                ' localip=10.0.0.0/8 remoteip=10.0.0.0/8 protocol=any action=allow'
            ],
            result,
            '"any" proto',
        )
        print(result)

    @capture.stdout
    def testMiscProtocol(self):
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(
                GOOD_HEADER_OUT + GOOD_TERM_MISCPROTO + GOOD_TERM_HOPOPT, self.naming
            ),
            EXP_INFO,
        )
        result = str(acl)
        self.assertTrue(
            [
                'name=o_good-term-miscproto enable=yes interfacetype=any dir=out'
                ' localip=any remoteip=any protocol=112 action=allow',
                'name=o_good-term-hopopt enable=yes interfacetype=any dir=out'
                ' localip=any remoteip=any protocol=0 action=allow',
            ],
            result,
            'explicit miscellaneous proto',
        )
        print(result)

    def _MixedRules(self, term, netdef=None):
        if netdef:
            self.naming._ParseLine(netdef, 'networks')
        self.naming._ParseLine('HTTPS = 443/tcp', 'services')
        acl = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_MIXED + term, self.naming), EXP_INFO
        )
        return [
            line for line in str(acl).splitlines() if line.startswith('netsh advfirewall firewall')
        ]

    def testMixedAfIsAccepted(self):
        """'mixed' is a supported address family, as the header docs state."""
        rules = self._MixedRules(MIXED_NO_ADDRESSES)
        self.assertNotEqual(rules, [], 'mixed filter rendered nothing')

    def testMixedNoAddressesRendersOnce(self):
        """A term with no addresses must not render once per family.

        netsh 'any' already covers both stacks, so rendering the term on both
        passes would emit two byte-identical rules.
        """
        rules = self._MixedRules(MIXED_NO_ADDRESSES)
        self.assertEqual(len(rules), 1, f'expected one rule, got: {rules}')
        self.assertEqual(len(set(rules)), len(rules), f'duplicate rules: {rules}')

    def testMixedDualStackRendersPerFamily(self):
        """A dual-stack address renders one rule per family, each AF-pure."""
        rules = self._MixedRules(MIXED_DUAL_STACK, 'DUAL_NET = 10.0.0.0/8 2001:db8::/32')
        self.assertEqual(len(rules), 2, f'expected one rule per family, got: {rules}')
        v4 = [r for r in rules if '10.0.0.0/8' in r]
        v6 = [r for r in rules if '2001:db8::/32' in r]
        self.assertEqual(len(v4), 1, f'expected one IPv4 rule: {rules}')
        self.assertEqual(len(v6), 1, f'expected one IPv6 rule: {rules}')
        self.assertNotIn('2001:db8::/32', v4[0])
        self.assertNotIn('10.0.0.0/8', v6[0])

    def testMixedSingleFamilyAddressRendersOnce(self):
        """An address present in only one family must not emit an empty peer rule."""
        rules = self._MixedRules(MIXED_V4_ONLY, 'V4_NET = 10.0.0.0/8')
        self.assertEqual(len(rules), 1, f'expected a single IPv4 rule, got: {rules}')
        self.assertIn('10.0.0.0/8', rules[0])

    def testMixedIcmpRendersInMatchingFamilyOnly(self):
        """icmp renders only as icmpv4, icmpv6 only as icmpv6, once each."""
        icmp = self._MixedRules(GOOD_TERM_ICMP)
        self.assertEqual(len(icmp), 1, f'expected one icmpv4 rule, got: {icmp}')
        self.assertIn('protocol=icmpv4', icmp[0])

        self.setUp()
        icmpv6 = self._MixedRules(GOOD_TERM_ICMPV6)
        self.assertEqual(len(icmpv6), 1, f'expected one icmpv6 rule, got: {icmpv6}')
        self.assertIn('protocol=icmpv6', icmpv6[0])

    def testBuildTokens(self):
        pol1 = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_IN + GOOD_SIMPLE, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testBuildWarningTokens(self):
        pol1 = windows_advfirewall.WindowsAdvFirewall(
            policy.ParsePolicy(GOOD_HEADER_IN + GOOD_SIMPLE_WARNING, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
    absltest.main()
