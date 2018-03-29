#!/bin/bash

rm -rf install-dir/
make
make install
./set_file_copy.sh

