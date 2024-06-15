#!/usr/bin/env bash
cp ../openssh/test_dsa ./
cp ../openssh/test_rsa ./
cp ../openssh/test_ecdsa ./
# 转换成openssl可以识别的格式
ssh-keygen -P "11111111" -N "11111111" -e -p -m PKCS8 -f test_dsa
ssh-keygen -P "11111111" -N "11111111" -e -p -m PKCS8 -f test_rsa
ssh-keygen -P "11111111" -N "11111111" -e -p -m PKCS8 -f test_ecdsa