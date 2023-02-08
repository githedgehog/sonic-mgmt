import json
import logging
import re
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
        sonic_ctrs[container]['status'] = is_container_running(duthost, container)

    logger.info("Sonic containers map: {}".format(sonic_ctrs))
    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info


@pytest.mark.parametrize("name", sonic_ctrs.keys())
def test_container_state(setup, name):
    """Verify container state according to build_metadata.yaml file on a DUT
        e.i: INCLUDE_SNMP: n -> container is not running
        INCLUDE_SNMP: y -> container is running.
        In case, no build_metadata.yaml, then all containers are running"""

    config = setup['config']
    if config is False:
        pytest.skip("SKIP: no build_metadata.yaml file. Cannot check expected state.")

    expected_state = True if config[sonic_ctrs[name]['build_flag']] == "y" else False
    actual_state = sonic_ctrs[name]['status']
    pytest_assert(actual_state == expected_state,
                  "{} actual state: {}, but expected: {}".format(name, actual_state, expected_state))


def test_bgp_smoke(setup):
    """Verify that 'bgdp' process is running according to INCLUDE_FRR_BGP (build_metadata.yaml).
        If so, make basic BGP configuration and verify that configuration is applied"""

    # setup, get init bgp conf
    duthost = setup['duthost']
    config = setup['config']
    is_bgpd_proc = is_process_running(duthost, "bgpd")

    # check process
    if config and config['INCLUDE_FRR_BGP'] == 'n':
        pytest_assert(not is_bgpd_proc, "There is running 'bgpd' process, but shouldn't be.")
    # note: bgp is running in community by default ('not config' means community)
    elif not config or (config and config['INCLUDE_FRR_BGP'] == 'y'):
        # setup: get init bgp conf, prepare command for restore init config
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
    """Verify that 'bfdd' process is running according to INCLUDE_FRR_BFD (build_metadata.yaml).
        If so, make basic BFD configuration and verify that configuration is applied"""

    duthost = setup['duthost']
    config = setup['config']
    is_bfdd_proc = is_process_running(duthost, "bfdd")

    # check process
    if not config:
        pytest.skip("SKIP: no build_metadata.yaml; it can be a community image, bfdd is not running by default.")
    elif not sonic_ctrs['bgp']['status']:
        pytest_assert(not is_bfdd_proc, "There is running bfdd process, but shouldn't be.")
    elif config and config['INCLUDE_FRR_BFD'] == 'n':
        pytest_assert(not is_bfdd_proc, "There is running bfdd process, but shouldn't be.")
    elif config and config['INCLUDE_FRR_BFD'] == 'y':
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


def test_vrrp_smoke(setup):
    """Verify that 'vrrpd' process is running according to INCLUDE_FRR_VRRP (build_metadata.yaml).
        If so, make basic VRRP configuration and verify that configuration is applied"""

    duthost = setup['duthost']
    config = setup['config']
    is_vrrpd_proc = is_process_running(duthost, "vrrpd")

    # check process
    if not config:
        pytest.skip("SKIP: no build_metadata.yaml; it can be a community image, 'vrrpd' is not running by default.")
    elif config and config['INCLUDE_FRR_VRRP'] == 'n':
        pytest_assert(not is_vrrpd_proc, "There is running 'vrrpd' process, but shouldn't be.")
    elif config and config['INCLUDE_FRR_VRRP'] == 'y':
        interface = "lo"
        vrid = 111
        version = 2
        priority = 22
        try:
            # verify vrrp process
            pytest_assert(is_vrrpd_proc, "There is no running vrrpd process, but should be.")

            # configure vrrp version/priority for interface
            duthost.command("vtysh -c \"configure terminal\" \
                                    -c \"interface {interface}\" \
                                    -c \"vrrp {vrid} version {version}\" \
                                    -c \"vrrp {vrid} priority {priority}\"".format(interface=interface, vrid=vrid,
                                                                                   version=version, priority=priority))

            # verify vrrp config is applied
            result = duthost.command("vtysh -c \"show vrrp json\"")['stdout']
            result_json = json.loads(result)[0]  # json inside array
            pytest_assert(result_json['vrid'] == vrid,
                          "VRID is not matched, expected: '{}', actual: '{}'".format(vrid, result_json['vrid']))
            pytest_assert(result_json['version'] == version,
                          "VRRP version is not matched, expected: '{}', actual: '{}'".format(version,
                                                                                             result_json['version']))
            pytest_assert(result_json['interface'] == interface,
                          "Interface is not matched, expected: '{}', actual: '{}'".format(interface,
                                                                                          result_json['interface']))
        finally:
            # cleanup: remove test bfd profile
            duthost.command("vtysh -c \"configure terminal\" \
                                                -c \"interface {interface}\" \
                                                -c \"no vrrp {vrid} priority {priority}\" \
                                                -c \"no vrrp {vrid} version {version}\"".format(interface=interface,
                                                                                                vrid=vrid,
                                                                                                version=version,
                                                                                                priority=priority))


def test_syslog_smoke(setup):
    """Verify that 'rsyslogd' process is running according to INCLUDE_SYSLOG (build_metadata.yaml).
        If so, make basic syslog configuration and verify that configuration is applied"""

    # setup, get init bgp conf
    duthost = setup['duthost']
    config = setup['config']
    is_rsyslogd_proc = is_process_running(duthost, "rsyslogd")

    # check process
    if config and config['INCLUDE_SYSLOG'] == 'n':
        pytest_assert(not is_rsyslogd_proc, "There is running 'rsyslogd' process, but shouldn't be.")
    # note: syslog is running in community by default ('not config' means community)
    elif not config or (config and config['INCLUDE_SYSLOG'] == 'y'):
        # setup
        fake_syslog_server_ip = "1.1.1.1"
        try:
            # verify rsyslogd process
            pytest_assert(is_rsyslogd_proc, "There is no running 'rsyslogd' process, but should be.")
            # add fake syslog ip server verify it is added
            duthost.shell("sudo config syslog add {}".format(fake_syslog_server_ip), module_ignore_errors=True)
            syslog_servers = duthost.shell("show runningconfiguration syslog", module_ignore_errors=True)
            all_ips = re.findall(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', syslog_servers['stdout'])
            pytest_assert(fake_syslog_server_ip in all_ips,
                          "Syslog server ip is not applied, available ips: {}".format(all_ips))
        finally:
            # cleanup:
            duthost.shell("sudo config syslog del {}".format(fake_syslog_server_ip), module_ignore_errors=True)


def test_database_smoke(setup):
    """Verify that 'database' container state according to INCLUDE_DATABASE (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart).
        Check that config_db exist in redis."""

    duthost = setup['duthost']
    config = setup['config']
    container = "database"

    check_container_sanity_helper(config, container)

    check_container_restarts_helper(duthost, container)

    # "-n 4" means read from 4th redis namespace (CONFIG_DB)
    shell_check_config_db = "redis-cli -n 4 KEYS \"*\""
    res_check_config_db = duthost.shell(shell_check_config_db, module_ignore_errors=True)
    pytest_assert(res_check_config_db['failed'] == False, "Error while reading redis DB.")

    logger.info("config DB have {} records.".format(len(res_check_config_db['stdout_lines'])))


def test_syncd_smoke(setup):
    """Verify that 'syncd' container state according to INCLUDE_SYNCD (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart).
        Verify that 'syncd' process is running."""

    duthost = setup['duthost']
    config = setup['config']
    container = "syncd"

    check_container_sanity_helper(config, container)

    check_container_restarts_helper(duthost, container)

    pytest_assert(is_process_running(duthost, "syncd"), "There is no running syncd process.")


def test_swss_smoke(setup):
    """Verify that 'swss' container state according to INCLUDE_SWSS (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart).
        Verify that 'orchagent' process is running."""

    duthost = setup['duthost']
    config = setup['config']
    container = "swss"

    check_container_sanity_helper(config, container)

    check_container_restarts_helper(duthost, container)

    pytest_assert(is_process_running(duthost, "orchagent"), "There is no running orchagent process.")


def test_pmon_smoke(setup):
    """Verify that 'pmon' container state according to INCLUDE_PMON (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart)."""

    duthost = setup['duthost']
    config = setup['config']
    container = "pmon"

    check_container_sanity_helper(config, container)

    check_container_restarts_helper(duthost, container)


def get_uptime(duthost, hours = False, minutes = False, seconds = False, smooth = 0):
    '''
    hours/minutes/seconds - set to True which format you need. Default format is seconds.
    smooth - add to result (e.g. uptime is 1h, smooth == 3 -> res == 4)
    '''

    divider = 1
    if hours:
        divider = 3600
    elif minutes:
        divider = 60

    shell_uptime = "cat /proc/uptime | awk '{{print int($1/{} + {})}}'".format(divider, smooth)
    result = duthost.shell(shell_uptime)

    return result


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


def check_container_sanity_helper(config, container):
    if config and config[sonic_ctrs[container]['build_flag']] == "n" and \
            sonic_ctrs[container]['status'] == False:
        pytest.skip("SKIP. {} container is disabled on build.".format(container))
    if config and config[sonic_ctrs[container]['build_flag']] == "n":
        pytest_assert(sonic_ctrs[container]['status'] == False, \
            "There is running {} container, but shouldn't be.".format(container))
    if config and config[sonic_ctrs[container]['build_flag']] == "y":
        pytest_assert(sonic_ctrs[container]['status'] == True, \
            "There is no running {} container, but should be.".format(container))

    pytest_assert(sonic_ctrs['database']['status'], "{} container is not running.".format(container))


def check_container_restarts_helper(duthost, container):
    events_file = container + "_events"
    uptime = get_uptime(duthost, hours=True, smooth=1)['stdout']

    shell_get_events = "docker events --since {}h --filter container={} --filter event=restart > {} &"\
        .format(uptime, container, events_file)
    shell_read_events_file = "[ -e {} ] && cat {}".format(events_file, events_file)
    shell_clear_events_file = "[ -e {} ] && rm -f {}".format(events_file, events_file)

    res_get_events = duthost.shell(shell_get_events, module_ignore_errors=True)
    pytest_assert(res_get_events['failed'] == False, "Error while calling docker events.")

    res_read_events_file = duthost.shell(shell_read_events_file, module_ignore_errors=True)
    pytest_assert(res_read_events_file['failed'] == False, "Error while reading event file.")

    restart_count = len(res_read_events_file['stdout_lines'])
    pytest_assert(restart_count < 1, "Container have {} restarts".format(restart_count))

    # cleanup
    duthost.shell(shell_clear_events_file, module_ignore_errors=True)
