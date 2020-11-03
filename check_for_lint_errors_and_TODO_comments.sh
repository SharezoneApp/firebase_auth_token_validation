#!/bin/bash
set -e

pub global activate tuneup
tuneup check ./firebase_auth_token_validation --fail-on-todos