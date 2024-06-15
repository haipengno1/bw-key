#!/usr/bin/env bash
cp ../openssh/test_dsa ./
cp ../openssh/test_rsa ./
cp ../openssh/test_ecdsa ./
ssh-keygen -P "11111111" -N "11111111" -e -p -m SSH2 -f test_dsa
ssh-keygen -P "11111111" -N "11111111" -e -p -m SSH2 -f test_rsa
ssh-keygen -P "11111111" -N "11111111" -e -p -m SSH2 -f test_ecdsa
# ed25519只支持SSH2
ssh-keygen -t ed25519 -f test_ed25519  -C "me@github" -m PEM -P "11111111"