#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .test-build
c++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -pthread src/main.cpp -o .test-build/SandboxHost
c++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -pthread tests/core_tests.cpp -o .test-build/core-tests
.test-build/core-tests
python3 tests/integration.py .test-build/SandboxHost --workspace .test-build
