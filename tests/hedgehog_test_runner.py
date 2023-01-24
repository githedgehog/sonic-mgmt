import getopt
import subprocess
import sys

import yaml

# structure of yaml
# "vms-kvm-t0":
#   "acl":
#     - "test_stress_acl.py"
# "01-t0": - not implemented yet
PATH_TO_YAML = "hedgehog_test_list.yaml"
CMD_TO_RUN = ""
TESTS_TO_RUN = []

# will be defined below
TOPO = None
REPORT_DIR = None
DATA = None
ALLOWED_TOPO = ['vms-kvm-t0']  # todo in future '01-t0', '01-t1', '01-ptf'


def read_yaml(path):
    with open(path, "r") as stream:
        try:
            global DATA
            DATA = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def generate_test_list():
    for key, value in DATA[TOPO].items():
        for test_name in value:
            if key == 'root_dir':
                TESTS_TO_RUN.append(f"./{test_name}")
            else:
                TESTS_TO_RUN.append(f"./{key}/{test_name}")


def build_cmd_to_run():
    global CMD_TO_RUN
    CMD_TO_RUN = f"export ANSIBLE_CONFIG=../ansible; export ANSIBLE_LIBRARY=../ansible; pytest --inventory ../ansible/veos_vtb --host-pattern vlab-01 --testbed {TOPO} --testbed_file vtestbed.yaml --log-cli-level warning --log-file-level debug --showlocals --assert plain --show-capture no -rav --allow_recover --topology vs,any --module-path ../ansible/library --skip_sanity"
    test_list = " ".join(TESTS_TO_RUN)
    CMD_TO_RUN += f" {test_list}"
    CMD_TO_RUN += f" --alluredir {REPORT_DIR}"


def run_test():
    global CMD_TO_RUN
    print(CMD_TO_RUN)
    subprocess.run(CMD_TO_RUN, shell=True, universal_newlines=True)


def main(argv):
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
    read_yaml(PATH_TO_YAML)
    generate_test_list()
    build_cmd_to_run()
    run_test()
    print(f"TOPO: {TOPO}")
    print(f"REPORT_DIR: {REPORT_DIR}")


if __name__ == "__main__":
    main(sys.argv[1:])
