import getopt
import subprocess
import sys

import paramiko
import yaml

# structure of yaml
# "vms-kvm-t0":
#   "acl":
#     - "test_stress_acl.py"
# "01-t0": - not implemented yet
PATH_TO_AVAILABLE_TESTS = "hedgehog_test_list.yaml"
PATH_TO_BUILD_METADATA = "/etc/sonic/build_metadata.yaml"
PATH_TO_CREDS = "../ansible/group_vars/lab/secrets.yml"
DUT_IP = "10.250.0.101"  # todo: keep all conf in testbed.csv and get topo and ip from this file
ALLOWED_TOPO = ['vms-kvm-t0']  # todo in future '01-t0', '01-t1', '01-ptf'

# will be defined below
CMD_TO_RUN = ""
TESTS_TO_RUN = []
TOPO = None
REPORT_DIR = None
AVAILABLE_TESTS = None
METADATA = None


def read_yaml(path):
    with open(path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def read_metadata(path):
    global METADATA
    creds = read_yaml(PATH_TO_CREDS)
    ssh_username = creds['sonicadmin_user']
    ssh_password = creds['sonicadmin_password']

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(DUT_IP, username=ssh_username, password=ssh_password, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("cat {}".format(path))
        if stdout.channel.recv_exit_status() == 0:
            METADATA = yaml.safe_load(stdout.read().decode('utf-8'))
    except paramiko.AuthenticationException:
        print("SSH connect failed. Make sure use the expected password according to the SONiC image.")
        raise
    finally:
        ssh.close()


def generate_test_list():
    # todo create enum for INCLUDE_* flags and use them here and in hedgehog_smoke_test
    test_dictionary = dict(AVAILABLE_TESTS[TOPO].items())
    # remove tests in case feature is disabled
    # by default all available test are going to be run, otherwise explicitly delete
    if METADATA:
        metadata_config = METADATA['Configuration']
        if metadata_config['INCLUDE_SNMP'] == 'n':
            test_dictionary.pop('snmp', None)
            test_dictionary.pop('cacl', None)
        if metadata_config['INCLUDE_NTP'] == 'n':
            test_dictionary.pop('ntp', None)

    # generate list of tests to run
    for key, value in test_dictionary.items():
        for test_name in value:
            if key == 'root_dir':
                TESTS_TO_RUN.append(f"./{test_name}")
            else:
                TESTS_TO_RUN.append(f"./{key}/{test_name}")


def build_cmd_to_run():
    global CMD_TO_RUN
    CMD_TO_RUN = f"export ANSIBLE_CONFIG=../ansible; export ANSIBLE_LIBRARY=../ansible; pytest --inventory ../ansible/veos_vtb --host-pattern vlab-01 --testbed {TOPO} --testbed_file vtestbed.yaml --log-cli-level warning --log-file-level debug --showlocals --assert plain --show-capture no -rav --allow_recover --topology t0,any --module-path ../ansible/library --skip_sanity"
    test_list = " ".join(TESTS_TO_RUN)
    CMD_TO_RUN += f" {test_list}"
    CMD_TO_RUN += f" --alluredir {REPORT_DIR}"


def run_test():
    global CMD_TO_RUN
    print(CMD_TO_RUN)
    subprocess.run(CMD_TO_RUN, shell=True, universal_newlines=True)


def main(argv):
    global AVAILABLE_TESTS
    help_msg = "./hedgehog_test_runner.py -t <topo: [{}]> -r <path to report dir>".format('|'.join(ALLOWED_TOPO))
    found_t, found_r = False, False
    try:
        opts, args = getopt.getopt(argv, "ht:r:", ["topo=", "report_dir="])
    except getopt.GetoptError:
        print('Error: unexpected option(s)')
        print(help_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(help_msg)
            sys.exit()
        elif opt in ("-t", "--topo"):
            global TOPO
            TOPO = arg.lower()
            found_t = True
            if TOPO not in ALLOWED_TOPO:
                print(f"Topo: {TOPO}")
                print('Error: incorrect topo')
                print(help_msg)
                sys.exit(2)
        elif opt in ("-r", "--report_dir"):
            global REPORT_DIR
            REPORT_DIR = arg
            found_r = True
    if not found_t or not found_r:
        print("'--topo' or --'report_dir' is not passed")
        print(help_msg)
        sys.exit(2)
    read_metadata(PATH_TO_BUILD_METADATA)
    AVAILABLE_TESTS = read_yaml(PATH_TO_AVAILABLE_TESTS)
    generate_test_list()
    build_cmd_to_run()
    run_test()
    print(f"TOPO: {TOPO}")
    print(f"REPORT_DIR: {REPORT_DIR}")


if __name__ == "__main__":
    main(sys.argv[1:])
