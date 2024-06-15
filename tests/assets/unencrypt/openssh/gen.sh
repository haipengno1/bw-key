#!/usr/bin/env bash
ssh-keygen -t dsa -f test_dsa  -C "me-unencrypt@github"
ssh-keygen -t rsa -f test_rsa  -C "me-unencrypt@github"
ssh-keygen -t ecdsa -f test_ecdsa  -C "me-unencrypt@github"
ssh-keygen -t ed25519 -f test_ed25519  -C "me-unencrypt@github"