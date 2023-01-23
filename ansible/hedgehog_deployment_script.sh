#!/bin/bash

#todo use docker filter with regex
#MGMT_CONTAINER=`docker ps -f ancestor=docker-sonic-mgmt-hedgehog:master --format {{.Names}}`

MGMT_CONTAINER=`docker ps | awk '/docker-sonic-mgmt/ { print $NF }'`
CURRENT_TOPO_CONTAINER=`docker ps | awk '/sonicdev-microsoft.azurecr.io/ { print $NF }'`
SONIC_MGMT_REPO="sonic-mgmt_dev_202205"

pre_check () {
  echo "Pre check"
  if [ -z "$MGMT_CONTAINER" ]; then
    echo "No sonic-mgmt container is running. Exit 1."
    exit 1
  else
    echo "The sonit-mgmt container is running: $MGMT_CONTAINER"
  fi
}

remove_topo () {
  # todo adopt for diff kind of topos 01-t0, 01-t1, vs
  if [ -z "$CURRENT_TOPO_CONTAINER" ]; then
    echo "No topo is running. Skip removing topo step."
  else
    echo "TOPO is detected: $CURRENT_TOPO_CONTAINER"
    echo "Going to remove current topo"
    docker exec -i "$MGMT_CONTAINER" bash -c "cd /data/$SONIC_MGMT_REPO/ansible && ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k veos remove-topo vms-kvm-t0 password.txt"
fi
}

deploy_topo () {
  echo "Deploy topo"
  docker exec -i "$MGMT_CONTAINER" bash -c "cd /data/$SONIC_MGMT_REPO/ansible && ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb add-topo vms-kvm-t0 password.txt"
  docker exec -i "$MGMT_CONTAINER" bash -c "cd /data/$SONIC_MGMT_REPO/ansible && ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-t0 veos_vtb password.txt"
}

post_check () {
  echo "Verify env"
  docker exec -i "$MGMT_CONTAINER" bash -c "cd /data/$SONIC_MGMT_REPO/tests && export ANSIBLE_CONFIG=../ansible; export ANSIBLE_LIBRARY=../ansible; pytest --inventory ../ansible/veos_vtb --host-pattern vlab-01 --testbed vms-kvm-t0 --testbed_file vtestbed.yaml --log-cli-level warning --log-file-level debug --showlocals --assert plain --show-capture no -rav --allow_recover --topology vs,any --module-path ../ansible/library --skip_sanity ./bgp/test_bgp_fact.py"

  if [ $? -eq 0 ]; then
    echo "Topo is deployed successfully."
  else
    echo "Something went wrong"
  fi
}

pre_check
remove_topo
deploy_topo
post_check
