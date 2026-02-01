#!/usr/bin/env bash
set -euo pipefail

# Sync Godot releases from godot-builds repository to versions.zig
#
# Usage:
#   ./sync.sh                    # Fetch latest 5 releases
#   PAGE=2 ./sync.sh             # Fetch page 2
#   LIMIT=100 ./sync.sh          # Fetch 100 releases per page
#   GITHUB_TOKEN=xxx ./sync.sh   # Use token to avoid rate limiting
#   NO_CACHE=1 ./sync.sh         # Disable SHA512 caching

PAGE="${PAGE:-1}"
LIMIT="${LIMIT:-5}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
NO_CACHE="${NO_CACHE:-}"
API_URL="https://api.github.com/repos/godotengine/godot-builds/releases?per_page=${LIMIT}&page=${PAGE}"
VERSIONS_FILE="versions.zon"
CACHE_FILE="versions-cache.json"

# Initialize cache file if it doesn't exist
if [[ ! -f "$CACHE_FILE" ]]; then
  echo "{}" > "$CACHE_FILE"
fi

echo "Fetching Godot releases from GitHub (godot-builds)..."

if [[ -n "$GITHUB_TOKEN" ]]; then
  releases=$(curl -s -H "Accept: application/vnd.github.v3+json" -H "Authorization: Bearer $GITHUB_TOKEN" "$API_URL")
else
  releases=$(curl -s -H "Accept: application/vnd.github.v3+json" "$API_URL")
fi

# Check for API errors (rate limiting, etc.)
if echo "$releases" | jq -e '.message' >/dev/null 2>&1; then
  echo "Error from GitHub API: $(echo "$releases" | jq -r '.message')" >&2
  echo "Try setting GITHUB_TOKEN environment variable to avoid rate limiting." >&2
  exit 1
fi

# Get existing version names from versions.zon
existing=$(grep -oE '\.godot_[a-z0-9_]+' "$VERSIONS_FILE" 2>/dev/null | sed 's/^\.//' | sort -u || echo "")

echo "Processing releases..."

# Cache for SHA512-SUMS.txt per release tag (avoid re-fetching)
declare -A sha512_sums_cache

# Function to get SHA512 for a file from a release
get_sha512() {
  local tag="$1"
  local filename="$2"

  # Fetch SHA512-SUMS.txt if not cached
  if [[ -z "${sha512_sums_cache[$tag]:-}" ]]; then
    local sums_url="https://github.com/godotengine/godot-builds/releases/download/${tag}/SHA512-SUMS.txt"
    sha512_sums_cache[$tag]=$(curl -sL "$sums_url" 2>/dev/null || echo "")
  fi

  # Extract SHA512 for the specific file
  echo "${sha512_sums_cache[$tag]}" | grep -F "$filename" | awk '{print $1}' | head -1
}

# Function to get cached hash if SHA512 matches
get_cached_hash() {
  local filename="$1"
  local expected_sha512="$2"

  if [[ -n "$NO_CACHE" ]]; then
    return 1
  fi

  local cached_sha512
  cached_sha512=$(jq -r --arg f "$filename" '.[$f].sha512 // ""' "$CACHE_FILE")

  if [[ "$cached_sha512" == "$expected_sha512" ]]; then
    jq -r --arg f "$filename" '.[$f].zig_hash // ""' "$CACHE_FILE"
    return 0
  fi
  return 1
}

# Function to update cache
update_cache() {
  local filename="$1"
  local sha512="$2"
  local zig_hash="$3"

  local tmp_cache
  tmp_cache=$(mktemp)
  jq --arg f "$filename" --arg s "$sha512" --arg h "$zig_hash" \
    '.[$f] = {"sha512": $s, "zig_hash": $h}' "$CACHE_FILE" > "$tmp_cache"
  mv "$tmp_cache" "$CACHE_FILE"
}

# Process releases and collect new versions
new_versions=""
cache_hits=0
cache_misses=0

while read -r dep_name url tag filename; do
  if grep -qx "$dep_name" <<< "$existing"; then
    echo "  Skipping $dep_name (already exists)"
  else
    echo "  Fetching $dep_name..."

    # Get SHA512 from release checksums
    expected_sha512=$(get_sha512 "$tag" "$filename")

    # Try to get from cache
    if cached_hash=$(get_cached_hash "$filename" "$expected_sha512"); then
      hash="$cached_hash"
      echo "    Cache hit: $dep_name"
      ((cache_hits++)) || true
    else
      # Download and compute hash
      if hash=$(zig fetch "$url" 2>/dev/null); then
        update_cache "$filename" "$expected_sha512" "$hash"
        echo "    Downloaded: $dep_name"
        ((cache_misses++)) || true
      else
        echo "    Failed: $dep_name" >&2
        continue
      fi
    fi

    new_versions+="    .$dep_name = .{ .url = \"$url\", .hash = \"$hash\" },
"
    echo "    Added: $dep_name"
  fi
done < <(echo "$releases" | jq -r '
  .[] |
  .tag_name as $tag |
  # Parse version and prerelease from tag (e.g., "4.6-beta2" -> version="4.6", prerelease="beta2")
  ($tag | capture("^(?<ver>[0-9]+\\.[0-9]+(\\.[0-9]+)?)-(?<pre>.+)$")) as $parsed |
  select($parsed != null) |
  $parsed.ver as $ver |
  $parsed.pre as $pre |
  .assets[] |
  select(.name | test("^Godot_v.*\\.(zip)$")) |
  select(.name | test("mono|export_templates|debug_symbols|web_editor|android|godot-lib|SHA512") | not) |
  {
    name: .name,
    url: .browser_download_url,
    tag: $tag,
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
  "\(.dep_name) \(.url) \(.tag) \(.name)"
')

# If we have new versions, append them to versions.zon
if [[ -n "$new_versions" ]]; then
  echo "Adding new versions to $VERSIONS_FILE..."

  # Insert new versions before the closing "}"
  tmp_file=$(mktemp)

  # Remove the last line (}) and trailing empty lines
  head -n -1 "$VERSIONS_FILE" > "$tmp_file"

  # Append new versions
  echo -n "$new_versions" >> "$tmp_file"

  # Add back the closing
  echo "}" >> "$tmp_file"

  mv "$tmp_file" "$VERSIONS_FILE"

  echo "Done! New versions added to $VERSIONS_FILE"
  echo "Stats: $cache_hits cache hits, $cache_misses downloads"
else
  echo "No new versions to add."
fi
