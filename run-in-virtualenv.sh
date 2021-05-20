#!/bin/sh

. bin/activate
exec bin/uwsgi --master --http :8080 --gevent 256 --mount /=api:webapp

