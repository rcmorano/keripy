#!/bin/bash

CONFIG_DIR=${WITROOTS_CONFIG_DIR:-$PWD}
BACKER_CONFIG_FILE=${BACKER_CONFIG_FILE:-$CONFIG_DIR/keri/cf/backer.json}
WITROOT_CONFIG_FILE=${WITROOT_CONFIG_FILE:-$CONFIG_DIR/witroot-config.json}

mkdir -p $CONFIG_DIR/keri/cf
echo '{
    "witroot": {
      "dt": "2022-01-20T12:57:59.823350+00:00",
      "curls": ["tcp://127.0.0.1:5665/", "http://127.0.0.1:5666/"]
    },
    "dt": "2022-01-20T12:57:59.823350+00:00",
    "iurls": [
    ]
  }
  ' > $BACKER_CONFIG_FILE
echo '{
    "transferable": false,
    "wits": [],
    "icount": 1,
    "ncount": 1,
    "isith": "1",
    "nsith": "1"
  }' > $WITROOT_CONFIG_FILE


kli init --name witroot --nopasscode --config-dir ${CONFIG_DIR} --config-file ${BACKER_CONFIG_FILE}

kli incept --name witroot --alias witroot --config ${CONFIG_DIR} --file ${WITROOT_CONFIG_FILE}

kli backer start --name witroot --alias witroot -H 5666 -T 5665 --ledger cardano