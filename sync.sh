#!/usr/bin/env bash
set -euo pipefail

API_URL="https://api.github.com/repos/godotengine/godot/releases?per_page=3"

mark_lazy() {
  # Remove any existing .lazy lines to avoid duplicates, then add after each .hash
  sed -i '/\.lazy = true,$/d' build.zig.zon
  sed -i 's/\.hash = "\([^"]*\)",$/\.hash = "\1",\n            .lazy = true,/' build.zig.zon
}

echo "Fetching Godot releases from GitHub..."

releases=$(curl -s -H "Accept: application/vnd.github.v3+json" "$API_URL")

# Get existing dependencies from build.zig.zon
existing=$(grep -oE '\.godot_[a-z0-9_]+' build.zig.zon 2>/dev/null | sed 's/^\.//' | sort -u || echo "")

echo "Processing releases..."

echo "$releases" | jq -r '
  .[] |
  select(.tag_name | endswith("-stable")) |
  .tag_name as $tag |
  .assets[] |
  select(.name | test("^Godot_v.*\\.(zip)$")) |
  select(.name | test("mono|export_templates|debug_symbols|web_editor|android|godot-lib|SHA512") | not) |
  {
    name: .name,
    url: .browser_download_url,
    version: ($tag | sub("-stable$"; "")),
  } |
  # Normalize version to always have 3 components (4.5 -> 4.5.0)
  .version as $v |
  .normalized_version = (if ($v | split(".") | length) == 2 then $v + ".0" else $v end) |
  # Parse platform and arch from filename
  if .name | test("_linux\\.x86_64\\.zip$") then . + {platform: "linux", arch: "x86_64"}
  elif .name | test("_linux\\.x86_32\\.zip$") then . + {platform: "linux", arch: "x86"}
  elif .name | test("_linux\\.arm64\\.zip$") then . + {platform: "linux", arch: "aarch64"}
  elif .name | test("_linux\\.arm32\\.zip$") then . + {platform: "linux", arch: "arm"}
  elif .name | test("_macos\\.universal\\.zip$") then . + {platform: "macos", arch: "universal"}
  elif .name | test("_win64\\.exe\\.zip$") then . + {platform: "windows", arch: "x86_64"}
  elif .name | test("_win32\\.exe\\.zip$") then . + {platform: "windows", arch: "x86"}
  elif .name | test("_windows_arm64\\.exe\\.zip$") then . + {platform: "windows", arch: "aarch64"}
  # Godot 3.x patterns
  elif .name | test("_x11\\.64\\.zip$") then . + {platform: "linux", arch: "x86_64"}
  elif .name | test("_x11\\.32\\.zip$") then . + {platform: "linux", arch: "x86"}
  elif .name | test("_osx\\.universal\\.zip$") then . + {platform: "macos", arch: "universal"}
  else empty
  end |
  # Create dependency name: godot_4_5_0_linux_x86_64
  .dep_name = "godot_" + (.normalized_version | gsub("\\."; "_")) + "_" + .platform + "_" + .arch |
  "\(.dep_name) \(.url)"
' | while read -r dep_name url; do
  if echo "$existing" | grep -qx "$dep_name"; then
    echo "  Skipping $dep_name (already exists)"
  else
    echo "  Adding $dep_name..."
    if zig fetch --save="$dep_name" "$url"; then
      mark_lazy
    else
      echo "    Failed: $dep_name"
    fi
  fi
done

echo "Done!"
