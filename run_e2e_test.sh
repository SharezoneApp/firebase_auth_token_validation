#!/bin/bash

# Must be ". script" so that vars are exported to this shell
. ./load_env_into_bash.sh

cd firebase_authentication_token_validator
dart test e2e_test