import logging

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


def is_container_running(duthost, name):
    # can't use community method from sonic.py, error:
    # UnicodeEncodeError: 'ascii' codec can't encode character u'\u2026' in position 183: ordinal not in range(128)
    state = duthost.shell("docker ps -f name=%s --format \{\{.Status\}\}" % name)['stdout_lines']
    if len(state) > 0:
        return True
    else:
        return False
