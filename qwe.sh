#!/bin/bash

set -e -u

#exec python3 setup.py build_ext --inplace
#exec python3 setup.py build
rm -rf ~/.local/lib/python3.4/site-packages/htpy3*
python3 setup.py install --user
cd tests
python3 test.py
