#!/bin/sh
if [ -f /start ] && [ -s /ssh/key.pub ]; then
    exit 0;
else
    exit 1;
fi
