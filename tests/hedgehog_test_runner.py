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


def read_metadata(testbed_data):
    metadata = False
    dut_ip = testbed_data["testbed"]["dut_ip"]
    username = testbed_data["testbed"]["username"]
    password = testbed_data["testbed"]["password"]
    path_to_metadata = "/etc/sonic/build_metadata.yaml"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(dut_ip, username=username, password=password, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("cat {}".format(path_to_metadata))
        if stdout.channel.recv_exit_status() == 0:
            metadata = yaml.safe_load(stdout.read().decode('utf-8'))
    except paramiko.AuthenticationException:
        print("SSH connect failed. Make sure use the expected password according to the SONiC image.")
        raise
    finally:
        ssh.close()

    return metadata


def generate_test_list(testbed_data, metadata):
    test_dictionary = dict(testbed_data["pytest_param"]["tests"])
    tests_to_run = []
    # remove tests in case feature is disabled
    # by default all available test are going to be run, otherwise explicitly delete
    if metadata:
        metadata_config = metadata['Configuration']
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
        subprocess.run(cmd, shell=True, universal_newlines=True)


def build_allurectl_cmd(testbed_data, metadata, launch_name, token):
    data = testbed_data["testops"]
    cmd = "/opt/allurectl upload "
    cmd += "--endpoint {} ".format(data['endpoint'])
    cmd += "--token {} ".format(token)
    cmd += "--project-id {} ".format(data['project_id'])
    cmd += "--launch-name {} ".format(launch_name)
    testbed_name = testbed_data["name"]
    if metadata:
        # setup_name = metadata["spec"]["usecase"]
        # launch_tag = f"{testbed_name}_{setup_name}"  # => vsTestbed-01-t0_<setup_name>
        launch_tag = f"{testbed_name}_default-img"
        cmd += "--launch-tags {} ".format(launch_tag)
    else:
        cmd += "--launch-tags {}_outside_img ".format(testbed_name)

    cmd += FULL_REPORT_DIR_PATH

    return cmd


def main(argv):
    example_text = '''Example:
    ./hedgehog_test_runner.py --testbed hedgehog/env/vsTestbed-01-t0.yaml --report_dir_name vs_test --print True 
    --launch_name [73]202205_dev.173-0e4b738fd --allurectl_token <token> '''
    parser = argparse.ArgumentParser(epilog=example_text)
    parser.add_argument("--testbed", help="testbed config file", required=True)
    parser.add_argument("--report_dir_name", help="report directory name", required=True)
    parser.add_argument("--launch_name", help="launch_name [test build]<version>.<build>-<commit_id>", required=True)
    parser.add_argument("--allurectl_token", help="token for allurectl", required=True)
    parser.add_argument("--print", help="print pytest cmd only", default=False, required=False, type=bool,
                        choices=[True, False])
    args = parser.parse_args()
    is_print_only = args.print

    testbed = read_yaml(args.testbed)
    metadata = read_metadata(testbed)

    # run tests
    tests_to_run = generate_test_list(testbed, metadata)
    test_run_cmd = build_run_test_cmd(testbed, tests_to_run, args.report_dir_name)
    run_cmd(test_run_cmd, is_print_only)

    # uplaod result into testops via `allurectl`
    allurectl_upload_cmd = build_allurectl_cmd(testbed, metadata, args.launch_name, args.allurectl_token)
    run_cmd(allurectl_upload_cmd, is_print_only)


if __name__ == "__main__":
    main(sys.argv[1:])
