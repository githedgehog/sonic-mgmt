import argparse
import os
import shutil
import sys
import uuid
import yaml

import boto3
import requests

METADATA_FILENAME = "build_metadata.yaml"


def read_yaml(path):
    with open(path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def rename_directory(path_with_target, build_id):
    # mv old_name -> new_name_uuid4
    parent_dir = os.path.dirname(path_with_target)
    dir_to_rename = os.path.basename(path_with_target)
    new_dir_name = build_id
    os.chdir(parent_dir)
    os.rename(dir_to_rename, new_dir_name)
    return new_dir_name


def create_metadata_symlink(path):
    # find build_metadata.yaml file
    os.chdir(path)
    metadata_path = ""
    current_dir = "."
    for root, dirs, files in os.walk(current_dir):
        if METADATA_FILENAME in files:
            metadata_path = os.path.join(root, METADATA_FILENAME)
            break

    # create symlink, to avoid copying
    if metadata_path != "":
        os.symlink(metadata_path, METADATA_FILENAME)
    else:
        print("ERROR: no 'build_metadata.yaml' file inside '{}'.".format(path))
        exit(1)


def create_and_move_dir(parent_dir, dir_to_move):
    # mv foo -> sonic/foo
    root_dir = 'sonic'
    os.chdir(parent_dir)
    os.mkdir(root_dir)
    shutil.move(dir_to_move, root_dir)
    return root_dir


def gen_file_path_to_publish(parent_dir, dirname):
    os.chdir(parent_dir)
    files_to_publish = []  # [ 'sonic/uuid4/file_1', 'sonic/uuid4/file_2', ...]
    for root, dirs, files in os.walk(dirname):
        for file in files:
            s3_path = os.path.join(root, file)
            files_to_publish.append(s3_path)
    print(files_to_publish)
    return files_to_publish


def publish_file(parent_dir, files, access_key, secret_key, account_id, bucket_name):
    os.chdir(parent_dir)
    s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                             endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com")

    for file in files:
        with open(file, "rb") as f:
            s3_client.upload_fileobj(f, bucket_name, f.name)


def notify_factory_api(uuid4):
    # TODO: Add request to Factory API when it will be ready
    # res = requests.get(f"https://factory.githedgehog.com/api/webhook/build/{uuid4}")
    # res = requests.get(f"https://api.factory.stage.x.githedgehog.com/api/webhook/build/{uuid4}")
    # assert res.status_code == 200
    pass


def main(argv):
    example_text = '''Example:
    ./publish_img_artifacts.py --path_to_artifact_dir <path>/target --aws_access_key xxx --aws_secret_key xxx
        --account_id xxx --bucket_name hedgehog-downloads'''
    parser = argparse.ArgumentParser(epilog=example_text)
    parser.add_argument("--path_to_artifact_dir", help="Full path to artifacts", required=True)
    parser.add_argument("--aws_access_key", help="Access Key ID", required=True)
    parser.add_argument("--aws_secret_key", help="Secret Access Key", required=True)
    parser.add_argument("--account_id", help="Account ID", required=True)
    parser.add_argument("--bucket_name", help="Bucket name", required=True)

    args = parser.parse_args()

    path_with_target = args.path_to_artifact_dir
    parent_dir = os.path.dirname(path_with_target)

    # create symlink for build_metadata
    create_metadata_symlink(path_with_target)

    # read build metadata
    metadata = read_yaml(METADATA_FILENAME)

    # rename target -> to uuid4
    new_target_dir_name = rename_directory(path_with_target, metadata['id'])

    # create dir structure according requirements sonic/<uuid4/
    root_dir = create_and_move_dir(parent_dir, new_target_dir_name)

    # generate list of paths to publish
    files_to_publish = gen_file_path_to_publish(parent_dir, root_dir)

    # publish artifacts
    publish_file(parent_dir, files_to_publish, args.aws_access_key, args.aws_secret_key, args.account_id, args.bucket_name)

    # notify
    notify_factory_api(new_target_dir_name)


if __name__ == "__main__":
    main(sys.argv[1:])
