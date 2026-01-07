#!/usr/bin/env bash

source .env

for f in "$LOCAL_DIR"/$PATTERN; do
  [ -e "$f" ] || continue
  (scp -i $KEY $f $HOST:/home/ec2-user/traffics)
  echo -e "\e[32mSUCCESSFUL UPLOAD:\e[0m $f"
done
