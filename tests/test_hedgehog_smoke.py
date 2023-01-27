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
# bgp container is for FRR routing stack (just named bgp, actually bgp is in FRR)
sonic_ctrs = {
    "database":         {"status": True, "build_flag": "INCLUDE_DATABASE"},
    "swss":             {"status": True, "build_flag": "INCLUDE_SWSS"},
    "syncd":            {"status": True, "build_flag": "INCLUDE_SYNCD"},
    "pmon":             {"status": True, "build_flag": "INCLUDE_PMON"},
    "telemetry":        {"status": True, "build_flag": "INCLUDE_SYSTEM_TELEMETRY"},
    "snmp":             {"status": True, "build_flag": "INCLUDE_SNMP"},
    "mgmt-framework":   {"status": True, "build_flag": "INCLUDE_MGMT_FRAMEWORK"},
    "dhcp_relay":       {"status": True, "build_flag": "INCLUDE_DHCP_RELAY"},
    "lldp":             {"status": True, "build_flag": "INCLUDE_LLDP"},
    "radv":             {"status": True, "build_flag": "INCLUDE_ROUTER_ADVERTISER"},
    # "gbsyncd":          {"status": True, "build_fladflag": None}, # this container is only on VS image
    "teamd":            {"status": True, "build_flag": "INCLUDE_TEAMD"},
    "bgp":              {"status": True, "build_flag": "INCLUDE_ROUTING_STACK"}
}


@pytest.fixture(scope="module", autouse=True)
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    setup_info = {'duthost': duthost}
    # check metadata file exist, by default all ctrs are Up
    check_file_on_dut = duthost.shell("[ -f {} ]".format(path_to_metadata), module_ignore_errors=True)
    if check_file_on_dut['rc'] == 0:
        data = duthost.shell("cat {}".format(path_to_metadata))['stdout']
        metadata = yaml.safe_load(data)

        config = metadata['Configuration']
        setup_info['config'] = config
    else:
        setup_info['config'] = False

    # update actual container status
    for container in sonic_ctrs.keys():
        sonic_ctrs[container]['Status'] = is_container_running(duthost, container)

    logger.info("Sonic containers map: {}".format(sonic_ctrs))
    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info


@pytest.mark.parametrize("name", sonic_ctrs.keys())
def test_container_state(setup, name):
    config = setup['config']
    if config is False:
        pytest.skip("SKIP: no build_metadata.yaml file. Cannot check expected state.")

    expected_state = True if config[sonic_ctrs[name]['build_flag']] == "y" else False
    actual_state = sonic_ctrs[name]['status']
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


def test_bfd_smoke(setup):
    duthost = setup['duthost']
    config = setup['config']
    is_bfdd_proc = is_process_running(duthost, "bfdd")

    # check container and process
    if sonic_ctrs['bgp']['status'] and not config:
        pytest.skip("SKIP: no build_metadata.yaml; it can be a community image, bfdd is not running by default.")
    elif not sonic_ctrs['bgp']['status']:
        pytest_assert(not is_bfdd_proc, "There is running bfdd process, but shouldn't be.")
    elif sonic_ctrs['bgp']['status'] and config and config['INCLUDE_FRR_BFD'] == 'n':
        pytest_assert(not is_bfdd_proc, "There is running bfdd process, but shouldn't be.")
    elif sonic_ctrs['bgp']['status'] and config and config['INCLUDE_FRR_BFD'] == 'y':
        bfd_profile = "test_profile"
        receive_interval = 111
        peer_ip = "1.1.1.1"
        try:
            # verify bfdd process
            pytest_assert(is_bfdd_proc, "There is no running bfdd process, but should be.")

            # configure test profile and peer
            duthost.command("vtysh -c \"configure terminal\" \
                                    -c \"bfd\" \
                                    -c \"profile {bfd_profile}\" \
                                    -c \"receive-interval {receive_interval}\" \
                                    -c \"no shutdown\" \
                                    -c \"exit\" \
                                    -c \"peer {peer_ip}\" \
                                    -c \"profile {bfd_profile}\"".format(bfd_profile=bfd_profile,
                                                                         receive_interval=receive_interval,
                                                                         peer_ip=peer_ip))

            # verify bfd config is really applied
            result = duthost.command("vtysh -c \"show bfd peer {} json\"".format(peer_ip))['stdout']
            result_json = json.loads(result)
            pytest_assert(result_json['peer'] == peer_ip, "Peer: '{}' is missed".format(peer_ip))
            pytest_assert(result_json['receive-interval'] == receive_interval,
                          "Receive-interval is not the same as in profile")
        finally:
            # cleanup: remove test bfd profile
            duthost.command("vtysh -c \"configure terminal\" \
                                    -c \"bfd\" \
                                    -c \"no peer {peer_ip}\" \
                                    -c \"no profile {bfd_profile}\"".format(bfd_profile=bfd_profile, peer_ip=peer_ip))


def is_container_running(duthost, name):
    # can't use community method from sonic.py, error:
    # UnicodeEncodeError: 'ascii' codec can't encode character u'\u2026' in position 183: ordinal not in range(128)
    state = duthost.shell("docker ps -f name=%s --format \{\{.Status\}\}" % name)['stdout_lines']
    if len(state) > 0:
        return True
    else:
        return False


def is_process_running(duthost, process):
    result = duthost.shell("pidof {}".format(process), module_ignore_errors=True)['rc']
    if result == 0:
        return True
    else:
        return False
