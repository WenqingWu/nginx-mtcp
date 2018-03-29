#!/bin/bash

rm -rf install-dir/
make
make install
./change.sh

