#!/usr/bin/env bash
ssh-keygen -t dsa -f test_dsa  -C "me@github" -m PEM -P "11111111"
ssh-keygen -t rsa -f test_rsa  -C "me@github" -m PEM -P "11111111"
ssh-keygen -t ecdsa -f test_ecdsa  -C "me@github" -m PEM -P "11111111"
