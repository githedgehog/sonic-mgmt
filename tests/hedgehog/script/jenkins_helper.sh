#!/bin/bash

BRANCH=''
SERVER=''
TESTBED=''
REPORT_DIR=''
SONIC_IMG=''
ALLURE_TOKEN=''

OPTIND=1
while getopts ':b:s:t:r:i:a:n:' flag; do
  case "${flag}" in
    b) BRANCH="${OPTARG}" ;;
    s) SERVER="${OPTARG}" ;;
    t) TESTBED="${OPTARG}" ;;
    r) REPORT_DIR="${OPTARG}" ;;
    i) SONIC_IMG="${OPTARG}" ;;
    a) ALLURE_TOKEN="${OPTARG}" ;;
    n) CI_BUILD_NUMBER="${OPTARG}" ;;
  esac
done

SONIC_MGMT_WD="/home/hedgehog/sonic-mgmt"
SSH_OPTIONS="-o ServerAliveInterval=30 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
UNMAPPED_TESTS_FILE_NAME="unmapped_tests.txt"

MGMT_CONTAINER=`ssh -q $SSH_OPTIONS $SERVER "docker ps -f ancestor=docker-sonic-mgmt-hedgehog:master --format {{.Names}}"`
REPORT_PREFIX=`ssh -q $SSH_OPTIONS $SERVER "cat $SONIC_MGMT_WD/tests/$TESTBED | yq .testbed.report_base_dir"`
DUT_IP=`ssh -q $SSH_OPTIONS $SERVER "cat $SONIC_MGMT_WD/tests/$TESTBED | yq .testbed.dut_ip"`
REPORT_DIR="$(date +%Y%m%d)-$REPORT_DIR-b$CI_BUILD_NUMBER"


redeployEnv() {
    if [ ! -f "$SONIC_IMG" ]; then
        echo "$SONIC_IMG does not exist."
        exit 1
    fi

    echo "Deploy topology"
    ssh $SSH_OPTIONS $SERVER "cd $SONIC_MGMT_WD && git stash; git fetch; git checkout $BRANCH; git pull"
    ssh $SSH_OPTIONS $SERVER "cd $SONIC_MGMT_WD/ansible && ./hedgehog_deployment_script.sh"

    DUT_USER=`ssh -q $SSH_OPTIONS $SERVER "cat $SONIC_MGMT_WD/ansible/group_vars/lab/secrets.yml | yq .sonicadmin_user"`
    DUT_PASS=`ssh -q $SSH_OPTIONS $SERVER "cat $SONIC_MGMT_WD/ansible/group_vars/lab/secrets.yml | yq .sonicadmin_password"`

    echo "Copy SONiC image to DUT"
    sshpass -p $DUT_PASS scp $SSH_OPTIONS -o "ProxyCommand ssh $SSH_OPTIONS $SERVER -W %h:%p" $SONIC_IMG $DUT_USER@$DUT_IP:/home/admin/

    echo "Install SONiC image"
    sshpass -p $DUT_PASS ssh $SSH_OPTIONS -o "ProxyCommand ssh $SSH_OPTIONS $SERVER -W %h:%p" $DUT_USER@$DUT_IP "sudo sonic-installer install -y /home/admin/$SONIC_IMG"

    echo "Reboot DUT to apply changes"
    sshpass -p $DUT_PASS ssh $SSH_OPTIONS -o "ProxyCommand ssh $SSH_OPTIONS $SERVER -W %h:%p" $DUT_USER@$DUT_IP "sudo reboot"

    echo "Apply hedgehog user patch"
    ssh $SSH_OPTIONS $SERVER "cd $SONIC_MGMT_WD && git apply test_hedgehog_user.patch"
}

runTests() {
    DUT_USER=`ssh -q $SSH_OPTIONS $SERVER "cat $SONIC_MGMT_WD/ansible/group_vars/lab/secrets.yml | yq .sonicadmin_user"`
    DUT_PASS=`ssh -q $SSH_OPTIONS $SERVER "cat $SONIC_MGMT_WD/ansible/group_vars/lab/secrets.yml | yq .sonicadmin_password"`

    echo "Run test cases"
    ssh $SSH_OPTIONS $SERVER "docker exec -t $MGMT_CONTAINER bash -c \"cd /data/sonic-mgmt/tests && python3.8 hedgehog_test_runner.py \
                --testbed $TESTBED --report_dir_name $REPORT_DIR --ci_build_number $CI_BUILD_NUMBER --allurectl_token $ALLURE_TOKEN \" "
}

copyArtifacts() {
    echo "Copy allure and pytest reports"
    prefix=${REPORT_PREFIX#"/data/sonic-mgmt/"}
    mkdir -p reports
    scp -r $SSH_OPTIONS $SERVER:$SONIC_MGMT_WD/$prefix/$REPORT_DIR reports/
    scp -r $SSH_OPTIONS $SERVER:$SONIC_MGMT_WD/tests/report.html reports/
    mv reports/$REPORT_DIR/$UNMAPPED_TESTS_FILE_NAME reports/
}
