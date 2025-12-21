#!/usr/bin/env bash
set -euo pipefail

# Use godot-builds repository which has ALL releases (dev, beta, rc, stable)
# Pass PAGE=N environment variable to fetch different pages (default: 1)
# Pass DUMP_ONLY=1 to re-dump headers for all existing versions without downloading
PAGE="${PAGE:-1}"
LIMIT="${LIMIT:-5}"
DUMP_ONLY="${DUMP_ONLY:-}"
API_URL="https://api.github.com/repos/godotengine/godot-builds/releases?per_page=${LIMIT}&page=${PAGE}"

mark_lazy() {
  # Remove any existing .lazy lines to avoid duplicates, then add after each .hash
  sed -i '/\.lazy = true,$/d' build.zig.zon
  sed -i 's/\.hash = "\([^"]*\)",$/\.hash = "\1",\n            .lazy = true,/' build.zig.zon
}

dump_headers() {
  local version="$1"
  local prerelease="$2"
  local force="${3:-}"
  local dir="vendor/godot_${version//./_}_${prerelease}"

  if [[ -d "$dir" && -z "$force" ]]; then
    echo "    Headers already exist for $version-$prerelease"
    return 0
  fi

  echo "    Dumping headers for $version-$prerelease..."
  mkdir -p "$dir"

  # Determine which flags to use based on version:
  # - 4.1.x and 4.2.0-dev[1-5]: --dump-extension-api (old flag)
  # - 4.2.0-dev6 to 4.5.x: --dump-extension-api-with-docs
  # - 4.6.0-dev5+: also has --dump-gdextension-interface-json
  local major="${version%%.*}"
  local minor="${version#*.}"
  minor="${minor%%.*}"
  local major_minor="${version%.*}"

  local api_flag="--dump-extension-api-with-docs"
  local has_json_interface=false

  if [[ "$major_minor" == "4.1" ]]; then
    api_flag="--dump-extension-api"
  elif [[ "$version" == "4.2.0" && "$prerelease" =~ ^dev[1-5]$ ]]; then
    api_flag="--dump-extension-api"
  fi

  # --dump-gdextension-interface-json was introduced in 4.6.0-dev5
  if [[ "$major" -gt 4 ]]; then
    has_json_interface=true
  elif [[ "$major" -eq 4 && "$minor" -gt 6 ]]; then
    has_json_interface=true
  elif [[ "$major" -eq 4 && "$minor" -eq 6 ]]; then
    # For 4.6.x, check if it's dev5+ or later prerelease type
    if [[ "$prerelease" =~ ^dev([0-9]+)$ ]]; then
      local dev_num="${BASH_REMATCH[1]}"
      if [[ "$dev_num" -ge 5 ]]; then
        has_json_interface=true
      fi
    elif [[ "$prerelease" =~ ^(beta|rc|stable) ]]; then
      # beta, rc, and stable are all after dev5
      has_json_interface=true
    fi
  fi

  if [[ "$has_json_interface" == "true" ]]; then
    zig build run -Dversion="$version-$prerelease" -- "$api_flag" --dump-gdextension-interface --dump-gdextension-interface-json --headless >/dev/null 2>&1
  else
    zig build run -Dversion="$version-$prerelease" -- "$api_flag" --dump-gdextension-interface --headless >/dev/null 2>&1
  fi

  # Move generated files to vendor directory
  local moved_files=false
  if [[ "$has_json_interface" == "true" ]]; then
    if mv extension_api.json gdextension_interface.h gdextension_interface.json "$dir/" 2>/dev/null; then
      moved_files=true
    fi
  else
    if mv extension_api.json gdextension_interface.h "$dir/" 2>/dev/null; then
      moved_files=true
    fi
  fi

  if [[ "$moved_files" == "true" ]]; then
    echo "    Headers dumped for $version-$prerelease"
  else
    echo "    Failed to dump headers for $version-$prerelease"
    rmdir "$dir" 2>/dev/null || true
    return 1
  fi
}

# DUMP_ONLY mode: re-dump headers for all existing versions in build.zig.zon
if [[ -n "$DUMP_ONLY" ]]; then
  echo "DUMP_ONLY mode: Re-dumping headers for all versions in build.zig.zon..."

  # Extract unique version+prerelease combinations from build.zig.zon
  # Dependency names look like: godot_4_1_0_stable_linux_x86_64
  grep -oE '\.godot_4_[0-9]+_[0-9]+_[a-zA-Z0-9]+_linux_x86_64' build.zig.zon | \
    sed 's/^\.godot_//' | \
    sed 's/_linux_x86_64$//' | \
    sort -u | \
  while read -r version_prerelease; do
    # Parse: 4_1_0_stable -> version=4.1.0, prerelease=stable
    # Format: major_minor_patch_prerelease
    major=$(echo "$version_prerelease" | cut -d_ -f1)
    minor=$(echo "$version_prerelease" | cut -d_ -f2)
    patch=$(echo "$version_prerelease" | cut -d_ -f3)
    prerelease=$(echo "$version_prerelease" | cut -d_ -f4-)
    version="${major}.${minor}.${patch}"

    # Only dump for 4.1+
    if [[ "$major" -gt 4 ]] || [[ "$major" -eq 4 && "$minor" -ge 1 ]]; then
      dump_headers "$version" "$prerelease" "force"
    fi
  done

  echo "Done!"
  exit 0
fi

echo "Fetching Godot releases from GitHub (godot-builds)..."

releases=$(curl -s -H "Accept: application/vnd.github.v3+json" "$API_URL")

# Get existing dependencies from build.zig.zon
existing=$(grep -oE '\.godot_[a-z0-9_]+' build.zig.zon 2>/dev/null | sed 's/^\.//' | sort -u || echo "")

echo "Processing releases..."

echo "$releases" | jq -r '
  .[] |
  .tag_name as $tag |
  # Parse version and prerelease from tag (e.g., "4.6-beta2" -> version="4.6", prerelease="beta2")
  # Format: major.minor[.patch]-prerelease
  ($tag | capture("^(?<ver>[0-9]+\\.[0-9]+(\\.[0-9]+)?)-(?<pre>.+)$")) as $parsed |
  select($parsed != null) |
  $parsed.ver as $ver |
  $parsed.pre as $pre |
  ($ver | split(".")[0] | tonumber) as $major |
  ($ver | split(".")[1] | tonumber) as $minor |
  .assets[] |
  select(.name | test("^Godot_v.*\\.(zip)$")) |
  select(.name | test("mono|export_templates|debug_symbols|web_editor|android|godot-lib|SHA512") | not) |
  {
    name: .name,
    url: .browser_download_url,
    version: $ver,
    prerelease: $pre,
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
  # Create dependency name: godot_4_6_0_beta2_linux_x86_64
  .dep_name = "godot_" + (.normalized_version | gsub("\\."; "_")) + "_" + .prerelease + "_" + .platform + "_" + .arch |
  "\(.dep_name) \(.url) \(.normalized_version) \(.prerelease)"
' | while read -r dep_name url version prerelease; do
  if echo "$existing" | grep -qx "$dep_name"; then
    echo "  Skipping $dep_name (already exists)"
  else
    echo "  Adding $dep_name..."
    if zig fetch --save="$dep_name" "$url"; then
      mark_lazy
      # Dump headers once per version (only need one platform)
      # GDExtension interface was added in 4.1, so only dump headers for 4.1+
      if [[ "$dep_name" == *_linux_x86_64 ]]; then
        major="${version%%.*}"
        minor="${version#*.}"
        minor="${minor%%.*}"
        if [[ "$major" -gt 4 ]] || [[ "$major" -eq 4 && "$minor" -ge 1 ]]; then
          dump_headers "$version" "$prerelease"
        fi
      fi
    else
      echo "    Failed: $dep_name"
    fi
  fi
done

echo "Done!"
