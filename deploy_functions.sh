#!/bin/bash
set -e

# Must be ". script" so that vars are exported to this shell
. ./load_env_into_bash.sh

cd firebase/functions
firebase functions:config:set fbase.api_key=$FIREBASE_API_TOKEN --project $FIREBASE_PROJECT_ID
firebase deploy --only functions --project $FIREBASE_PROJECT_ID
