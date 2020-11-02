#!/bin/bash

# Must be ". script" so that vars are exported to this shell
. ./load_env_into_bash.sh

cd firebase/functions
if firebase functions:config:set fbase.api_key=$FIREBASE_API_TOKEN; then
    echo "Set cf successfully"
    firebase deploy --only functions
else
    echo "Could not set cf config"
fi