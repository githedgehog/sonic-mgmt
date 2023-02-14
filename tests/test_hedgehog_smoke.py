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
    service = "database.service"
    shell_check_config_db = "redis-cli -n 4 KEYS \"*\""

    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    # Check if nat service is active
    pytest_assert(check_service_alive(duthost, service), "database service {} isn't active".format(service))

    # "-n 4" means read from 4th redis namespace (CONFIG_DB)
    res_check_config_db = run_shell_helper(duthost, shell_check_config_db, "Error while reading redis DB.", do_assert=True)

    logger.info("config DB have {} records.".format(len(res_check_config_db['stdout_lines'])))


def test_syncd_smoke(setup):
    """Verify that 'syncd' container state according to INCLUDE_SYNCD (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart).
        Verify that 'syncd' process is running."""

    duthost = setup['duthost']
    config = setup['config']
    container = "syncd"
    service = "syncd.service"

    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    pytest_assert(is_process_running(duthost, "syncd"), "There is no running syncd process.")

    # Check if nat service is active
    pytest_assert(check_service_alive(duthost, service), "syncd service {} isn't active".format(service))


def test_swss_smoke(setup):
    """Verify that 'swss' container state according to INCLUDE_SWSS (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart).
        Verify that 'orchagent' process is running."""

    duthost = setup['duthost']
    config = setup['config']
    container = "swss"
    service = "swss.service"

    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    pytest_assert(is_process_running(duthost, "orchagent"), "There is no running orchagent process.")

    # Check if nat service is active
    pytest_assert(check_service_alive(duthost, service), "swss service {} isn't active".format(service))


def test_pmon_smoke(setup):
    """Verify that 'pmon' container state according to INCLUDE_PMON (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart)."""

    duthost = setup['duthost']
    config = setup['config']
    container = "pmon"
    service = "pmon.service"

    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    # Check if nat service is active
    pytest_assert(check_service_alive(duthost, service), "pmon service {} isn't active".format(service))


def test_nat_smoke(setup):
    """Verify that 'nat' feature is running according to INCLUDE_NAT (build_metadata.yaml).
        If so, make basic NAT configuration and verify that configuration is applied"""
    duthost = setup['duthost']
    config = setup['config']
    build_flag = "INCLUDE_NAT"
    service = "nat.service"
    shell_show_nat = "show nat"
    shell_show_nat_state = shell_show_nat + " config globalvalues | grep \"Admin Mode\" | awk '{print $4}'"
    shell_conf_nat = "sudo config nat"
    shell_conf_nat_feature = shell_conf_nat + " feature"


    if config and config[build_flag] == "n":
        pytest.skip("SKIP. NAT feature is disabled on build.")

    # Skip this step. Currently nat.setvice doesn't work
    # Check if nat service is active
    # pytest_assert(check_service_alive(duthost, service), "NAT service {} isn't active".format(service))

    # Check CLI available
    run_shell_helper(duthost, shell_show_nat, "CLI \"{}\" command error".format(shell_show_nat), do_assert=True)
    run_shell_helper(duthost, shell_conf_nat, "CLI \"{}\" command error".format(shell_conf_nat), do_assert=True)

    # Get NAT state
    res_show_nat_state = run_shell_helper(duthost, shell_show_nat_state, "Fail while getting NAT state", do_assert=True)
    original_nat_state = res_show_nat_state['stdout']
    new_nat_state = "enable" if original_nat_state == "disabled" else "disable"

    try:
        # Change NAT state and check it
        run_shell_helper(duthost, shell_conf_nat_feature + " " + new_nat_state)
        res_show_nat_state = run_shell_helper(duthost, shell_show_nat_state, "CLI \"{}\" command error".format(shell_show_nat_state), do_assert=True)
        pytest_assert(new_nat_state == res_show_nat_state['stdout'], "Error while changing NAT feature state")
    finally:
        # cleanup
        run_shell_helper(duthost, shell_conf_nat_feature + " " + original_nat_state,
                        "Cleanup: error while NAT state ({}) to the original ({})".format(new_nat_state, original_nat_state), do_assert=True)


def test_radius_smoke(setup):
    """Verify that 'radius' feature is running according to INCLUDE_RADIUS (build_metadata.yaml).
        If so, make basic RADIUS configuration and verify that configuration is applied"""
    duthost = setup['duthost']
    config = setup['config']
    build_flag = "INCLUDE_RADIUS"
    deb_packets = ["libnss-radius", "libpam-radius-auth"]
    shell_show_radius = "show radius"
    shell_show_radius_server = shell_show_radius + " | grep \"RADIUS_SERVER\" | awk '{print $3}'"
    fake_server_ip = "1.1.1.1"
    shell_conf_radius = "sudo config radius"
    shell_conf_radius_add = shell_conf_radius + " add " + fake_server_ip
    shell_conf_radius_del = shell_conf_radius + " delete " + fake_server_ip

    if config and config[build_flag] == "n":
        pytest.skip("SKIP. Radius feature is disabled on build.")

    # Check if deb packets installed
    check_installed_package_helper(duthost, deb_packets)

    # Check CLI available
    run_shell_helper(duthost, shell_show_radius, "CLI \"{}\" command error".format(shell_show_radius), do_assert=True)
    run_shell_helper(duthost, shell_conf_radius, "CLI \"{}\" command error".format(shell_conf_radius), do_assert=True)

    # Check there is no radius server with fake IP
    res_show_radius_server = run_shell_helper(duthost, shell_show_radius_server)
    for line in res_show_radius_server['stdout_lines']:
        pytest_assert(line != fake_server_ip, "Radius server with IP {} already exists")

    try:
        # Add fake Radius server
        run_shell_helper(duthost, shell_conf_radius_add)
        res_show_radius_server = run_shell_helper(duthost, shell_show_radius_server)
        pytest_assert(fake_server_ip in res_show_radius_server['stdout_lines'], "Radius server {} doesn't added".format(fake_server_ip))
    finally:
        # Cleanup
        run_shell_helper(duthost, shell_conf_radius_del, "Cleanup: error with deletion of fake RADIUS server ({})".format(fake_server_ip), do_assert=True)


def test_ntp_smoke(setup):
    """Verify that 'ntp' feature is running according to INCLUDE_NTP (build_metadata.yaml).
        If so, make basic NTP feature checks and verify"""
    duthost = setup['duthost']
    config = setup['config']
    build_flag = "INCLUDE_NTP"
    is_ntpd_proc = is_process_running(duthost, "ntpd")
    deb_packets = ["ntp", "ntpstat"]
    service = "ntp.service"
    shell_show_ntp = "show ntp"
    shell_conf_ntp = "sudo config ntp"

    if config and config[build_flag] == "n":
        pytest_assert(not is_ntpd_proc, "There is running 'ntpd' process, but shouldn't be.")
        pytest.skip("SKIP. NTP is disabled on build.")

    pytest_assert(is_ntpd_proc, "There is no running 'ntpd' process, but should be.")

    # Check if deb packets installed
    check_installed_package_helper(duthost, deb_packets)

    # Check if systemd service is active
    pytest_assert(check_service_alive(duthost, service), "Systemd service {} isn't active".format(service))

    # Check CLI available
    res_show_ntp = run_shell_helper(duthost, shell_show_ntp)
    # This is workaround for 'show ntp' because ntpstat inside may return 1 (cli error == 2)
    pytest_assert(res_show_ntp['rc'] < 2, "CLI \"{}\" command error".format(shell_show_ntp))
    run_shell_helper(duthost, shell_conf_ntp, "CLI \"{}\" command error".format(shell_conf_ntp), do_assert=True)


def test_snmp_smoke(setup):
    """Verify that 'cnmp' container is running according to INCLUDE_SNMP (build_metadata.yaml).
        If so, make basic SNMP configuration and verify that configuration is applied"""
    duthost = setup['duthost']
    config = setup['config']
    container = "snmp"
    is_snmpd_proc = is_process_running(duthost, "snmpd")
    service = "snmp.service"
    shell_show_snmp = ["show snmpagentaddress", "show snmptrap"]
    shell_conf_snmp = "sudo config snmp"
    snmp_test_user = "SNMPSmokeTestUser"
    shell_conf_snmp_user_add = shell_conf_snmp + " user add " + snmp_test_user + " noAuthNoPriv RO"
    shell_conf_snmp_user_del = shell_conf_snmp + " user del " + snmp_test_user

    # Check metadata
    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    pytest_assert(is_snmpd_proc, "There is no running 'snmpd' process, but should be.")

    # Check if systemd service is active
    pytest_assert(check_service_alive(duthost, service), "Systemd service {} isn't active".format(service))

    # Check CLI available
    for shell_show in shell_show_snmp:
        run_shell_helper(duthost, shell_show, "CLI \"{}\" command error".format(shell_show), do_assert=True)
    run_shell_helper(duthost, shell_conf_snmp, "CLI \"{}\" command error".format(shell_conf_snmp), do_assert=True)

    try:
        # Add SNMP user
        run_shell_helper(duthost, shell_conf_snmp_user_add, "CLI \"{}\" command error".format(shell_conf_snmp_user_add), do_assert=True)

        # Check systemd service again bcs is restards after user add
        pytest_assert(check_service_alive(duthost, service), "Systemd service {} isn't active".format(service))

        # Check user added to the DB
        res_redis_snmp_user = run_shell_helper(duthost, "redis-cli -n 4 KEYS \"SNMP_USER|{}\"".format(snmp_test_user))
        pytest_assert(res_redis_snmp_user['stdout_lines'] > 0, "User doesn't exist in redis-db")
    finally:
        # Cleanup
        run_shell_helper(duthost, shell_conf_snmp_user_del, "Cleanup: error with deletion SNMP user ({})".format(snmp_test_user), do_assert=True)


def test_lldp_smoke(setup):
    """Verify that 'LLDP' container is running according to INCLUDE_LLDP (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart).
        Verify that 'lldpd' process is running."""
    duthost = setup['duthost']
    config = setup['config']
    container = "lldp"
    is_lldpd_proc = is_process_running(duthost, "lldpd")
    service = "lldp.service"
    shell_show_lldp = ["show lldp neighbors", "show lldp table"]

    # check metadata
    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    pytest_assert(is_lldpd_proc, "There is no running 'lldpd' process, but should be.")

    # Check if systemd service is active
    pytest_assert(check_service_alive(duthost, service), "Systemd service {} isn't active".format(service))

    # Check CLI available
    for shell_show in shell_show_lldp:
        run_shell_helper(duthost, shell_show, "CLI \"{}\" command error".format(shell_show), do_assert=True)


def test_mgmt_framework_smoke(setup):
    """Verify that 'mgmt framework' container is running according to INCLUDE_MGMT_FRAMEWORK (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart)."""
    duthost = setup['duthost']
    config = setup['config']
    container = "mgmt-framework"
    service = "mgmt-framework.service"

    # Check metadata
    check_container_sanity_helper(config, container)
    check_container_restarts_helper(duthost, container)

    # Check if systemd service is active
    pytest_assert(check_service_alive(duthost, service), "Systemd service {} isn't active".format(service))

    # Error: FATAL: root cannot launch CLI
    # TODO: resolve root error
    # test "sonic-cli"
    # run_shell_helper(duthost, "sonic-cli", "sonic-cli returned error", do_assert=True)


def test_restapi_smoke(setup):
    """Verify that 'RESTAPI' container is running according to INCLUDE_RESTAPI (build_metadata.yaml).
        Check 'docker events' and make sure that container is stable (no restart)."""
    duthost = setup['duthost']
    config = setup['config']
    build_flag = "INCLUDE_RESTAPI"
    container = "restapi"
    service = "restapi.service"
    status = is_container_running(duthost, "restapi")

    # Check metadata with container
    if config and config[build_flag] == "n" and status == False:
        pytest.skip("SKIP. {} container is disabled on build.".format(container))
    if config and config[build_flag] == "n":
        pytest_assert(status == False, "There is running {} container, but shouldn't be.".format(container))
    if config and config[build_flag] == "y":
        pytest_assert(status == True, "There is no running {} container, but should be.".format(container))

    pytest_assert(status, "{} container is not running.".format(container))

    # Check if systemd service is active
    pytest_assert(check_service_alive(duthost, service), "Systemd service {} isn't active".format(service))


def check_installed_package_helper(duthost, package_list=None):
    shell_check_package = "apt list --installed "

    if not package_list:
        logger.warning("Package list is none or empty")
        return

    for package in package_list:
        res_check_package = run_shell_helper(duthost, shell_check_package + package)
        pytest_assert(len(res_check_package['stdout_lines']) > 1, "No installed {} package".format(package))


def check_service_alive(duthost, service):
    alive = False
    shell_check_service = "sudo systemctl is-active " + service

    res_check_service = run_shell_helper(duthost, shell_check_service)
    if res_check_service['stdout'] == "active":
        alive = True

    return alive


def run_shell_helper(duthost, shell_command, fail_msg = "", do_assert = False):
    res_shell_command = duthost.shell(shell_command, module_ignore_errors=True)
    success = res_shell_command['failed']

    if success == False:
        logger.debug("Shell command {} failed:\n{}".format(shell_command, res_shell_command['stderr']))

    if do_assert:
        pytest_assert(success == False, fail_msg)

    return res_shell_command


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
    build_flag = sonic_ctrs[container]['build_flag']
    status = sonic_ctrs[container]['status']

    if config and config[build_flag] == "n" and status == False:
        pytest.skip("SKIP. {} container is disabled on build.".format(container))
    if config and config[build_flag] == "n":
        pytest_assert(status == False, "There is running {} container, but shouldn't be.".format(container))
    if config and config[build_flag] == "y":
        pytest_assert(status == True, "There is no running {} container, but should be.".format(container))

    pytest_assert(status, "{} container is not running.".format(container))


def check_container_restarts_helper(duthost, container):
    events_file = container + "_events"
    uptime = get_uptime(duthost, hours=True, smooth=1)['stdout']

    shell_get_events = "docker events --since {}h --filter container={} --filter event=restart > {} &"\
        .format(uptime, container, events_file)
    shell_read_events_file = "[ -e {} ] && cat {}".format(events_file, events_file)
    shell_clear_events_file = "[ -e {} ] && rm -f {}".format(events_file, events_file)

    try:
        run_shell_helper(duthost, shell_get_events, "Error while calling docker events.", do_assert=True)

        res_read_events_file = run_shell_helper(duthost, shell_read_events_file, "Error while reading event file.", do_assert=True)

        restart_count = len(res_read_events_file['stdout_lines'])
        pytest_assert(restart_count < 1, "Container have {} restarts".format(restart_count))
    finally:
        # cleanup
        duthost.shell(shell_clear_events_file, module_ignore_errors=True)
