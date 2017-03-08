#!/bin/bash
until ./bike-listener; do
    echo "Listener 'bike-listener' crashed with exit code $?.  Respawning.." >&2
    sleep 3
done