import json
import logging
import time

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)
path_to_metadata = "/etc/sonic/build_metadata.yaml"
pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

# mandatory: database, swss, syncd, pmon
sonic_ctrs = {
    "database": {"status": True},
    "swss": {"status": True},
    "syncd": {"status": True},
    "pmon": {"status": True},
    "telemetry": {"status": True},
    "snmp": {"status": True},
    "mgmt-framework": {"status": True},
    "dhcp_relay": {"status": True},
    "lldp": {"status": True},
    "radv": {"status": True},
    "gbsyncd": {"status": True},
    "teamd": {"status": True},
    "bgp": {"status": True}
}


@pytest.fixture(scope="module", autouse=True)
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # check metadata file exist, by default all ctrs are Up
    check_file_on_dut = duthost.shell("[ -f {} ]".format(path_to_metadata), module_ignore_errors=True)
    if check_file_on_dut['rc'] == 0:
        data = duthost.shell("cat {}".format(path_to_metadata))['stdout']
        metadata = yaml.safe_load(data)
        config = metadata['Configuration']

        # update ctrs status according to metadata
        sonic_ctrs['telemetry']['status'] = True if config['INCLUDE_SYSTEM_TELEMETRY'] == 'y' else False
        sonic_ctrs['snmp']['status'] = True if config['INCLUDE_SNMP'] == 'y' else False
        sonic_ctrs['mgmt-framework']['status'] = True if config['INCLUDE_MGMT_FRAMEWORK'] == 'y' else False
        sonic_ctrs['dhcp_relay']['status'] = True if config['INCLUDE_DHCP_RELAY'] == 'y' else False
        sonic_ctrs['lldp']['status'] = True if config['INCLUDE_LLDP'] == 'y' else False
        sonic_ctrs['teamd']['status'] = True if config['INCLUDE_TEAMD'] == 'y' else False
        if config['INCLUDE_FRR_BFD'] == 'y' or config['INCLUDE_FRR_BGP'] == 'y' or config['INCLUDE_FRR_OSPF'] == 'y' \
                or config['INCLUDE_FRR_PBR'] == 'y' or config['INCLUDE_FRR_VRRP'] == 'y':
            sonic_ctrs['bgp']['status'] = True
        else:
            sonic_ctrs['bgp']['status'] = False

    logger.info("Sonic containers map: {}".format(sonic_ctrs))

    setup_info = {
        'duthost': duthost
    }

    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info


@pytest.mark.parametrize("name", sonic_ctrs.keys())
def test_container_state(setup, name):
    duthost = setup['duthost']
    expected_state = sonic_ctrs[name]["status"]
    actual_state = is_container_running(duthost, name)
    pytest_assert(actual_state == expected_state,
                  "{} actual state: {}, but expected: {}".format(name, actual_state, expected_state))


def test_bgp_smoke(setup):
    if not sonic_ctrs['bgp']['status']:
        pytest.skip("SKIP, BGP is not running")

    # setup, get init bgp conf
    duthost = setup['duthost']

    init_bgp_conf = duthost.command('vtysh -c \"show running-config bgpd no-header\"')['stdout'].split('\n')
    cmd_to_restore = ["vtysh -c \"configure terminal\"", "-c \"no router bgp\""]
    [cmd_to_restore.append("-c \"{}\"".format(init_bgp_conf[i])) for i in range(len(init_bgp_conf))]
    try:
        # remove current bgp conf
        duthost.command("vtysh -c \"configure terminal\" \
                                   -c \"no router bgp\"", module_ignore_errors=True)

        # configure bgp router and neighbor
        dut_asn = 1234
        neighbor_asn = 4321
        neighbor_ip = '1.1.1.1'
        duthost.command("vtysh -c \"configure terminal\" \
                                -c \"router bgp {dut_asn}\" \
                                -c \"neighbor PEER_V4 peer-group\" \
                                -c \"neighbor {neighbor_ip} remote-as {neighbor_asn}\" \
                                -c \"neighbor {neighbor_ip} peer-group PEER_V4\"".format(dut_asn=dut_asn,
                                                                                         neighbor_asn=neighbor_asn,
                                                                                         neighbor_ip=neighbor_ip))

        # verify that new bgp conf is really applied
        result = duthost.command('vtysh -c \"show bgp summary json\"')['stdout']
        result_json = json.loads(result)['ipv4Unicast']

        pytest_assert(result_json['as'] == dut_asn, "dut asn is not applied")
        pytest_assert(result_json['peers'][neighbor_ip]['remoteAs'] == neighbor_asn,
                      "Neighbor configuration is not applied")
    finally:
        # restore bgp configuration
        duthost.command(' '.join(cmd_to_restore))

        # wait some time to establish bgp session with neighbor if any
        time.sleep(20)

        # compare restored configuration with init
        restore_bgp_conf = duthost.command('vtysh -c \"show running-config bgpd no-header\"')['stdout'].split('\n')
        pytest_assert(init_bgp_conf == restore_bgp_conf, "bgp configuration is not same as init bgp configuration")


def is_container_running(duthost, name):
    # can't use community method from sonic.py, error:
    # UnicodeEncodeError: 'ascii' codec can't encode character u'\u2026' in position 183: ordinal not in range(128)
    state = duthost.shell("docker ps -f name=%s --format \{\{.Status\}\}" % name)['stdout_lines']
    if len(state) > 0:
        return True
    else:
        return False
