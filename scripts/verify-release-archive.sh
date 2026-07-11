#!/bin/sh
set -eu

export LC_ALL=C

dist_dir="${1:-dist}"
project="grokbuild-proxy"
checksums="$dist_dir/checksums.txt"
artifacts="$dist_dir/artifacts.json"
require_sbom="${REQUIRE_SBOM:-0}"

expected_archives="
${project}_Linux_x86_64.tar.gz:linux:amd64:tar
${project}_Linux_arm64.tar.gz:linux:arm64:tar
${project}_Darwin_x86_64.tar.gz:darwin:amd64:tar
${project}_Darwin_arm64.tar.gz:darwin:arm64:tar
${project}_Windows_x86_64.zip:windows:amd64:zip
${project}_Windows_arm64.zip:windows:arm64:zip
"

# Keep this in lockstep with the files declared under archives.files in
# .goreleaser.yml. Archive verification intentionally checks the exact set,
# rather than a small subset of security-sensitive files.
expected_payload="
LICENSE
README.md
README_EN.md
DISCLAIMER.md
DESIGN.md
SECURITY.md
CONTRIBUTING.md
COMPATIBILITY.md
CHANGELOG.md
docs/build-and-run.md
docs/operations.md
docs/release-checklist.md
docs/release-notes-v0.1.0.md
docs/release-notes-v0.2.0.md
config.example.yaml
Dockerfile
docker-compose.yml
docker-compose.release.yml
Makefile
scripts/install.sh
scripts/install.ps1
grok2api-sso-to-grokbuild/.dockerignore
grok2api-sso-to-grokbuild/Dockerfile
grok2api-sso-to-grokbuild/README
grok2api-sso-to-grokbuild/requirements.txt
grok2api-sso-to-grokbuild/server.py
grok2api-sso-to-grokbuild/sso2auth.py
"

# Payload files are data or source unless explicitly listed here. GoReleaser
# preserves source modes, so verify them to prevent WSL/checkout mode mistakes
# from turning every document and configuration file into an executable.
expected_executable_payload="
scripts/install.sh
"

fail() {
  echo "$*" >&2
  exit 1
}

is_regular_file() {
  [ -f "$1" ] && [ ! -L "$1" ]
}

is_expected_executable() {
  for executable in $expected_executable_payload; do
    [ "$1" != "$executable" ] || return 0
  done
  return 1
}

file_mode() {
  stat -c '%a' "$1"
}

checksum_entry_count() {
  awk -v name="$1" 'substr($0, 67) == name { count++ } END { print count + 0 }' "$checksums"
}

[ "$require_sbom" = "0" ] || [ "$require_sbom" = "1" ] || \
  fail "REQUIRE_SBOM must be either 0 or 1"

is_regular_file "$checksums" || fail "checksums.txt is missing or is not a regular file"
is_regular_file "$artifacts" || fail "artifacts.json is missing or is not a regular file"
jq -e 'type == "array"' "$artifacts" >/dev/null || fail "artifacts.json must contain a JSON array"

archive_path_count="$(find "$dist_dir" -maxdepth 1 \( -name "${project}_*.tar.gz" -o -name "${project}_*.zip" \) -print | wc -l | tr -d ' ')"
[ "$archive_path_count" -eq 6 ] || fail "expected exactly 6 release archive paths, found $archive_path_count"

sbom_path_count="$(find "$dist_dir" -maxdepth 1 -name '*.sbom.json' -print | wc -l | tr -d ' ')"
if [ "$require_sbom" = "1" ]; then
  [ "$sbom_path_count" -eq 6 ] || fail "expected exactly 6 SBOM files, found $sbom_path_count"
  expected_checksum_count=12
else
  [ "$sbom_path_count" -eq 0 ] || fail "SBOM files are present but REQUIRE_SBOM=1 was not set"
  expected_checksum_count=6
fi

checksum_line_count="$(wc -l < "$checksums" | tr -d ' ')"
[ "$checksum_line_count" -eq "$expected_checksum_count" ] || \
  fail "checksums.txt must contain exactly $expected_checksum_count entries, found $checksum_line_count"

# sha256sum accepts several loose formats by default. Require the canonical
# lowercase GNU form: 64 hex characters, exactly two spaces, and a basename.
awk '
  {
    digest = substr($0, 1, 64)
    separator = substr($0, 65, 2)
    name = substr($0, 67)
    if (length($0) != 66 + length(name) ||
        length(digest) != 64 || digest !~ /^[0-9a-f]+$/ ||
        separator != "  " || name !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/) {
      exit 1
    }
  }
' "$checksums" || fail "checksums.txt has a malformed entry; canonical sha256sum format is required"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

payload_list="$tmp_dir/payload.list"
payload_json="$tmp_dir/payload.json"
printf '%s\n' "$expected_payload" | sed '/^$/d' | sort > "$payload_list"
jq -Rsc 'split("\n") | map(select(length > 0)) | sort' < "$payload_list" > "$payload_json"

printf '%s\n' "$expected_archives" | while IFS=: read -r filename os arch format; do
  [ -n "$filename" ] || continue
  archive="$dist_dir/$filename"
  is_regular_file "$archive" || fail "release archive is missing or is not a regular file: $filename"

  checksum_matches="$(checksum_entry_count "$filename")"
  [ "$checksum_matches" -eq 1 ] || \
    fail "checksums.txt must contain exactly one entry for $filename, found $checksum_matches"

  artifact_matches="$(jq --arg name "$filename" --arg os "$os" --arg arch "$arch" \
    --slurpfile payload "$payload_json" '
      [.[] | select(
        .type == "Archive" and .name == $name and .goos == $os and .goarch == $arch and
        ((.path // "") | split("/") | last) == $name and
        ((.extra.Files // []) | sort) == $payload[0]
      )] | length
    ' "$artifacts")"
  [ "$artifact_matches" -eq 1 ] || \
    fail "artifacts.json must contain one exact Archive record for $filename ($os/$arch), found $artifact_matches"

  actual_list="$tmp_dir/actual.list"
  expected_list="$tmp_dir/expected.list"
  extract_dir="$tmp_dir/extract"
  find "$extract_dir" -mindepth 1 -delete 2>/dev/null || true
  mkdir -p "$extract_dir"

  if [ "$format" = "tar" ]; then
    tar -tzf "$archive" | sed 's#^\./##' | sort > "$actual_list"
    binary="$project"
    tar -tvzf "$archive" | awk '
      substr($1, 1, 1) != "-" { bad = 1 }
      END { if (bad) exit 1 }
    ' || \
      fail "$filename must contain regular files only"
    tar -xzf "$archive" -C "$extract_dir"
  else
    unzip -Z1 "$archive" | sed 's#^\./##' | sort > "$actual_list"
    binary="${project}.exe"
    entry_count="$(wc -l < "$actual_list" | tr -d ' ')"
    zipinfo -l "$archive" | awk -v expected="$entry_count" '
      length($1) == 10 && substr($1, 1, 1) ~ /^[-dl]$/ {
        count++
        if (substr($1, 1, 1) != "-") bad = 1
      }
      END { if (count != expected || bad) exit 1 }
    ' || fail "$filename must contain regular files only"
    unzip -qq "$archive" -d "$extract_dir"
  fi

  {
    printf '%s\n' "$expected_payload"
    printf '%s\n' "$binary"
  } | sed '/^$/d' | sort > "$expected_list"
  if ! cmp -s "$expected_list" "$actual_list"; then
    diff -u "$expected_list" "$actual_list" >&2 || true
    fail "$filename does not contain the exact release payload"
  fi

  for entry in $expected_payload $binary; do
    extracted="$extract_dir/$entry"
    is_regular_file "$extracted" || fail "$filename contains a non-regular payload entry: $entry"
  done
  for entry in $expected_payload; do
    extracted="$extract_dir/$entry"
    if is_expected_executable "$entry"; then
      mode="$(file_mode "$extracted")"
      [ "$mode" = "755" ] || fail "$filename payload must have mode 755: $entry (found $mode)"
    else
      mode="$(file_mode "$extracted")"
      [ "$mode" = "644" ] || fail "$filename payload must have mode 644: $entry (found $mode)"
    fi
  done
  case "$os" in
    linux|darwin)
      mode="$(file_mode "$extract_dir/$binary")"
      [ "$mode" = "755" ] || fail "$filename Unix binary must have mode 755 (found $mode)"
      ;;
  esac

  description="$(file -b "$extract_dir/$binary")"
  case "$os:$arch:$description" in
    linux:amd64:*ELF*x86-64*) ;;
    linux:arm64:*ELF*ARM*aarch64*|linux:arm64:*ELF*AArch64*) ;;
    darwin:amd64:*Mach-O*x86_64*) ;;
    darwin:arm64:*Mach-O*arm64*) ;;
    windows:amd64:*PE32+*x86-64*) ;;
    windows:arm64:*PE32+*Aarch64*) ;;
    *) fail "$filename has an unexpected binary format: $description" ;;
  esac
done

archive_artifacts="$(jq '[.[] | select(.type == "Archive")] | length' "$artifacts")"
[ "$archive_artifacts" -eq 6 ] || fail "artifacts.json must describe exactly 6 archives, found $archive_artifacts"

if [ "$require_sbom" = "1" ]; then
  sbom_artifacts="$(jq '[.[] | select(.type == "SBOM")] | length' "$artifacts")"
  [ "$sbom_artifacts" -eq 6 ] || fail "artifacts.json must describe exactly 6 SBOMs, found $sbom_artifacts"

  printf '%s\n' "$expected_archives" | while IFS=: read -r filename _os _arch _format; do
    [ -n "$filename" ] || continue
    sbom_name="${filename}.sbom.json"
    sbom="$dist_dir/$sbom_name"
    is_regular_file "$sbom" || fail "SBOM is missing or is not a regular file: $sbom_name"
    jq -e . "$sbom" >/dev/null || fail "$sbom_name is not valid JSON"

    checksum_matches="$(checksum_entry_count "$sbom_name")"
    [ "$checksum_matches" -eq 1 ] || \
      fail "checksums.txt must contain exactly one entry for $sbom_name, found $checksum_matches"

    matches="$(jq --arg name "$sbom_name" '
      [.[] | select(
        .type == "SBOM" and .name == $name and
        ((.path // "") | split("/") | last) == $name
      )] | length
    ' "$artifacts")"
    [ "$matches" -eq 1 ] || \
      fail "artifacts.json must contain exactly one SBOM record for $sbom_name, found $matches"
  done
fi

checksum_artifacts="$(jq '
  [.[] | select(.type == "Checksum")] |
  if length == 1 and .[0].name == "checksums.txt" and
     (((.[0].path // "") | split("/") | last) == "checksums.txt")
  then 1 else 0 end
' "$artifacts")"
[ "$checksum_artifacts" -eq 1 ] || fail "artifacts.json must contain exactly one checksums.txt record"

(cd "$dist_dir" && sha256sum --strict -c checksums.txt)

sbom_summary=""
[ "$require_sbom" = "0" ] || sbom_summary=", and 6 checksummed SBOMs"
echo "verified 6 release archives, strict checksums, binary formats, exact payloads${sbom_summary} in $dist_dir"
