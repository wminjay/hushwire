#!/bin/bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"

"$script_directory/build-core-xcframework.sh"
xcodegen --spec "$repository_root/macos/project.yml" --project "$repository_root/macos"

echo "Generated $repository_root/macos/HushWireSystem.xcodeproj"
