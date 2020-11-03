#!/bin/bash
set -e

pub global activate tuneup
# TODOs should be Tickets - not TODO comments.
tuneup check ./firebase_auth_token_validation --fail-on-todos