import sys
import argparse
import yaml
import json

from os.path import exists
from pathlib import Path


def read_yaml(path):
    with open(path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def read_json(path):
    with open(path, "r") as stream:
        try:
            return json.load(stream)
        except json.JSONDecodeError as exc:
            print(exc.msg)


def add_layers(report_dir_path, test_to_layer_map, unmapped_test_path=None):
    file_exists = exists(report_dir_path)
    if not file_exists:
        print("Error: Directory with Allure report doesn't exist.")
        return -1

    file_exists = exists(test_to_layer_map)
    if not file_exists:
        print("Error: File with  <test> to <layer> mapping doesn't exist")
        return -1

    unmapped_tests = []
    tests_to_grup_map = read_yaml(test_to_layer_map)

    # iterate over files with test results in the Allure directory
    files = Path(report_dir_path).glob('*result.json')
    for file in files:
        test_info = read_json(file)
        layer_label = {"name" : "layer"}

        # Find layer label for test in test_to_group.yaml file
        # If test doesn't find, layer label will be set to "Default" value
        if test_info["fullName"] in tests_to_grup_map:
            layer_label["value"] = tests_to_grup_map[test_info["fullName"]]
        else:
            layer_label["value"] ="Default"
            unmapped_tests.append(test_info["fullName"])

        test_info["labels"].append(layer_label)

        #rewrite updated JSON
        with open(file, "w") as outfile:
            json.dump(test_info, outfile)

    #write list with unmapped tests to file
    if unmapped_test_path:
        with open(unmapped_test_path, 'w') as outfile:
            outfile.write('\n'.join(unmapped_tests))


def main(argv):
    example_text = '''Example:
    ./add_layer_to_allure.py --report_dir_path allure_results --test_to_layer_map ./mapping_test_to_group.yaml
    --unmapped_test_path ./unmapped_tests.txt '''
    parser = argparse.ArgumentParser(epilog=example_text)
    parser.add_argument("--report_dir_path", help="report directory path", required=True)
    parser.add_argument("--test_to_layer_map", help="path to file with <test> to <layer> mapping", required=True)
    parser.add_argument("--unmapped_test_path", help="path to file with unmapped test", required=False)
    args = parser.parse_args()

    add_layers(args.report_dir_path, args.test_to_layer_map, args.unmapped_test_path)


if __name__ == "__main__":
    main(sys.argv[1:])
