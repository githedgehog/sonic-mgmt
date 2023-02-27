import argparse
import os
import shutil
import sys
import uuid

import boto3
import requests

BUCKET_NAME = "test" #todo, change in code


def rename_directory(path_with_target):
    # mv old_name -> new_name_uuid4
    parent_dir = os.path.dirname(path_with_target)
    dir_to_rename = os.path.basename(path_with_target)
    new_dir_name = str(uuid.uuid4())
    os.chdir(parent_dir)
    os.rename(dir_to_rename, new_dir_name)
    return new_dir_name


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


def publish_file(parent_dir, files, access_key, secret_key):
    os.chdir(parent_dir)
    s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)

    for file in files:
        with open(file, "rb") as f:
            s3_client.upload_fileobj(f, "BUCKET_NAME", "OBJECT_NAME")


def notify_factory_api(uuid4):
    # res = requests.get("https://factory.githedgehog.com/api/webhook/build/".format(uuid4))
    # assert res.status_code == 200
    pass


def main(argv):
    example_text = '''Example:
    ./publish_img_artifacts.py --path_to_artifact_dir <path>/target --aws_access_key xxx --aws_secret_key xxx'''
    parser = argparse.ArgumentParser(epilog=example_text)
    parser.add_argument("--path_to_artifact_dir", help="path to artifacts", required=True)
    parser.add_argument("--aws_access_key", help="access key", required=True)
    parser.add_argument("--aws_secret_key", help="secret key", required=True)

    args = parser.parse_args()

    path_with_target = args.path_to_artifact_dir
    parent_dir = os.path.dirname(args.path_to_artifact_dir)

    # rename target -> to uuid4
    new_target_dir_name = rename_directory(path_with_target)

    # create dir structure according requirements sonic/<uuid4/
    root_dir = create_and_move_dir(parent_dir, new_target_dir_name)

    # generate list of paths to publish
    files_to_publish = gen_file_path_to_publish(parent_dir, root_dir)

    # publish artifacts
    publish_file(parent_dir, files_to_publish, args.aws_access_key, args.aws_secret_key)

    # notify
    notify_factory_api(new_target_dir_name)


if __name__ == "__main__":
    main(sys.argv[1:])
