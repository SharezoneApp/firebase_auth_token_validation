#!/bin/bash
set -e

# On CI-Pipeline env-vars are pre-exported via Github secrets not via .env file.
if [-f ".env"]; then
    # Must be ". script" so that vars are exported to this shell
    . ./load_env_into_bash.sh
fi

cd firebase_authentication_token_validator
dart pub get
dart test e2e_test