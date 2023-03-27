#!/bin/bash

BACKER_CONFIG_FILE=${BACKER_CONFIG_FILE:-witroot-config.json}
WITROOTS_CONFIG_DIR=${WITROOTS_CONFIG_DIR:-~/.keri/roots}

kli init --name witroot --nopasscode --config-dir ${WITROOTS_CONFIG_DIR} --config-file witroot

kli incept --name witroot --alias witroot --config ${WITROOTS_CONFIG_DIR} --file ${BACKER_CONFIG_FILE}

kli backer start --name witroot --alias witroot -H 5666 -T 5665 --ledger cardano
