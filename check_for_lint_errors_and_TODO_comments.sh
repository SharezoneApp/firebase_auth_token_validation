#!/bin/bash
set -e

# To make pub global work
export PATH="$PATH":"$HOME/.pub-cache/bin"
pub global activate tuneup
# TODOs should be Tickets - not TODO comments.
tuneup check ./firebase_auth_token_validation --fail-on-todos