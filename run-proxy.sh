#!/bin/bash

set -x

cargo run -p arti --release -- proxy -c ~/.arti-proxy/config/
