#!/bin/bash
set -e
source ./.venv/bin/activate
gunicorn app:app