import argparse
import subprocess
import sys

import paramiko
import yaml

FULL_REPORT_DIR_PATH = ""


def read_yaml(path):
    with open(path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def run_cmd_on_dut(testbed_data, cmd):
    result = False
    dut_ip = testbed_data["testbed"]["dut_ip"]
    username = testbed_data["testbed"]["username"]
    password = testbed_data["testbed"]["password"]

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(dut_ip, username=username, password=password, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        if stdout.channel.recv_exit_status() == 0:
            result = stdout.read().decode('utf-8')
    except paramiko.AuthenticationException:
        print("SSH connect failed. Make sure use the expected password according to the SONiC image.")
        raise
    finally:
        ssh.close()

    return result


def read_metadata(testbed_data):
    metadata = False
    path_to_metadata = "/etc/sonic/build_metadata.yaml"
    cmd = "cat {}".format(path_to_metadata)
    metadata_plain = run_cmd_on_dut(testbed_data, cmd)
    if metadata_plain:
        metadata = yaml.safe_load(metadata_plain)

    return metadata


def read_sonic_version(testbed_data):
    # NOTE: sonic_version.yml is available in community image
    path_to_sonic_version = "/etc/sonic/sonic_version.yml"

    cmd = "cat {}".format(path_to_sonic_version)
    sonic_ver_plain = run_cmd_on_dut(testbed_data, cmd)
    sonic_ver = yaml.safe_load(sonic_ver_plain)

    return sonic_ver


def generate_test_list(testbed_data, metadata):
    test_dictionary = dict(testbed_data["pytest_param"]["tests"])
    tests_to_run = []
    # remove tests in case feature is disabled
    # by default all available test are going to be run, otherwise explicitly delete
    if metadata:
        metadata_config = metadata['configuration']
        if metadata_config['INCLUDE_SNMP'] == 'n':
            test_dictionary.pop('snmp', None)
            test_dictionary.pop('cacl', None)
        if metadata_config['INCLUDE_NTP'] == 'n':
            test_dictionary.pop('ntp', None)

    # generate list of tests to run
    for key, value in test_dictionary.items():
        for test_name in value:
            if key == 'root_dir':
                tests_to_run.append(f"./{test_name}")
            else:
                tests_to_run.append(f"./{key}/{test_name}")

    return tests_to_run


def generate_launch_name(metadata, sonic_ver):
    # required format: <channel>-<hedgehog_version>-<platform>-<git_version>-<test_type>-<build_id>
    launch_name = ""
    sonic_mgmt_commit_id = run_cmd("git rev-parse --short HEAD", False).stdout.strip()
    # todo(adovhan) 'sonic_mgmt_name': need to understand where test is running(sonic-mgmt/keysight)
    sonic_mgmt_name = "sonic-mgmt.{}".format(sonic_mgmt_commit_id)
    if metadata:
        launch_name += "{}".format(metadata['channel'])
        # launch_name += "-{}".format(metadata['hedgehog_version'])
        launch_name += "-{}".format(metadata['spec']['platform'])
        launch_name += "-{}".format(metadata['version']['SONiC_Software_Version'])
        launch_name += "-{}".format(sonic_mgmt_name)
        launch_name += "-{}".format(metadata['id'])
    else:
        launch_name += "{}".format(sonic_ver['release'])
        launch_name += "-{}".format(sonic_ver['asic_type'])
        launch_name += "-{}".format(sonic_ver['build_version'])
        launch_name += "-{}".format(sonic_mgmt_name)
        launch_name += "-community"

    return launch_name


def generate_launch_tags(testbed, metadata, ci_build_number):
    tags = []
    if metadata:
        tags.append("build-{}".format(metadata['id']))
        tags.append("usecase-{}".format(metadata['spec']['usecase']))

    # todo(adovhan) 'sonic_mgmt_name': need to understand where test is running(sonic-mgmt/keysight)
    sonic_mgmt_commit_id = run_cmd("git rev-parse --short HEAD", False).stdout.strip()
    tags.append("sonic-mgmt-{}".format(sonic_mgmt_commit_id))

    topo = ''.join([x for x in testbed['testbed']['topo'].split(',') if x != 'any'])  # t0,any => t0
    tags.append("topology-{}".format(topo))
    tags.append(testbed['name'])

    if ci_build_number != 'manual':
        tags.append("jenkins-{}".format(ci_build_number))
    else:
        tags.append(ci_build_number)

    return tags


def build_run_test_cmd(testbed_data, test_list, report_dir_name):
    testbed = testbed_data["testbed"]
    pytest_param = testbed_data["pytest_param"]
    global FULL_REPORT_DIR_PATH
    FULL_REPORT_DIR_PATH = "{}/{}".format(testbed["report_base_dir"], report_dir_name)
    allure_dir_option = " --alluredir {} ".format(FULL_REPORT_DIR_PATH)
    extra_param = " ".join(pytest_param["extra"]) + allure_dir_option

    cmd = "./run_tests.sh -n {} -d {} -t {} -u -O ".format(testbed["conf_name"],
                                                           testbed["host_pattern"],
                                                           testbed["topo"])
    cmd += " ".join(pytest_param["common"])
    cmd += " -c '{}' ".format(" ".join(test_list))
    cmd += " -e '{}' ".format(extra_param)

    return cmd


def run_cmd(cmd, print_only):
    if print_only:
        print(cmd)
    else:
        return subprocess.run(cmd, shell=True, universal_newlines=True, stdout=subprocess.PIPE)


def build_allurectl_cmd(testbed_data, metadata, sonic_version, ci_build_number, token):
    launch_name = generate_launch_name(metadata, sonic_version)
    launch_tags = generate_launch_tags(testbed_data, metadata, ci_build_number)
    data = testbed_data["testops"]
    cmd = "/opt/allurectl upload "
    cmd += "--endpoint {} ".format(data['endpoint'])
    cmd += "--token {} ".format(token)
    cmd += "--project-id {} ".format(data['project_id'])
    cmd += "--launch-name {} ".format(launch_name)
    cmd += ' '.join([" --launch-tags {} ".format(x) for x in launch_tags if x])

    cmd += FULL_REPORT_DIR_PATH

    return cmd


def main(argv):
    example_text = '''Example:
    ./hedgehog_test_runner.py --testbed hedgehog/env/vsTestbed-01-t0.yaml --report_dir_name vs_test --print True 
    --allurectl_token <token> '''
    parser = argparse.ArgumentParser(epilog=example_text)
    parser.add_argument("--testbed", help="testbed config file", required=True)
    parser.add_argument("--report_dir_name", help="report directory name", required=True)
    parser.add_argument("--allurectl_token", help="token for allurectl", required=True)
    parser.add_argument("--ci_build_number", help="CI build number, in case it is running by CI, "
                                                  "otherwise this parameter can be skipped",
                        default="manual", required=False)
    parser.add_argument("--print", help="print pytest cmd only", default=False, required=False, type=bool,
                        choices=[True, False])
    args = parser.parse_args()
    is_print_only = args.print

    testbed = read_yaml(args.testbed)
    metadata = read_metadata(testbed)
    sonic_ver = read_sonic_version(testbed)

    # generate cmd to run test
    tests_to_run = generate_test_list(testbed, metadata)
    test_run_cmd = build_run_test_cmd(testbed, tests_to_run, args.report_dir_name)

    # run tests
    run_cmd(test_run_cmd, is_print_only)

    # upload result into testops via `allurectl`
    allurectl_upload_cmd = build_allurectl_cmd(testbed, metadata, sonic_ver, args.ci_build_number, args.allurectl_token)
    run_cmd(allurectl_upload_cmd, is_print_only)


if __name__ == "__main__":
    main(sys.argv[1:])
