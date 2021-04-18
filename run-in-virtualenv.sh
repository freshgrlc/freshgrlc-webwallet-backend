#!/bin/sh

. bin/activate
exec bin/uwsgi --http :8080 --mount /=api:webapp

