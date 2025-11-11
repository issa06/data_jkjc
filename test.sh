#!/bin/sh
# NetBSD experiment script: Apache -> Nginx, publish dataset, measure ALL files
# Classification by file type & size bins, per-file result folders + global CSV.
# Run as root on NetBSD minimal with pkgin configured.

set -eu

# ---------- Configurable parameters ----------
APACHE_PKG="apache24"
NGINX_PKG="nginx"

APACHE_DOCROOT="/var/www/apache"
NGINX_DOCROOT="/var/www/nginx"

APACHE_CONF="/usr/pkg/etc/httpd/httpd.conf"
NGINX_CONF="/usr/pkg/etc/nginx/nginx.conf"

RESULT_DIR="/root/exp_results"

# Baseline loads for synthetic small/large files
REQUESTS_STATIC=10000
CONCURRENCY_STATIC=100
REQUESTS_LARGE=1000
CONCURRENCY_LARGE=50

# Dataset tarball (arg1 or env)
DATA_TAR="${1:-${DATA_TAR:-/root/data.tar.gz}}"
DATA_SUBDIR="pubdata"   # under each docroot

# Bind only to loopback for lab safety
BIND_ADDR="127.0.0.1"
TARGET_HOST="$BIND_ADDR"
PORT=80

SMALL_FILE="index.html"
LARGE_FILE="blob_1m.bin"

# -------- Size bins (bytes) --------
BIN_SMALL_MAX=$((64*1024))         # <= 64 KiB
BIN_MED_MAX=$((1024*1024))         # 64 KiB - 1 MiB
BIN_LARGE_MAX=$((50*1024*1024))    # 1 MiB - 50 MiB
# >50 MiB => huge

# -------- Load profiles per bin --------
# These are *per-file* ab settings to avoid runaway runtimes
# Small text/asset
REQ_S=2000; CONC_S=100
# Medium asset
REQ_M=800;  CONC_M=50
# Large asset
REQ_L=200;  CONC_L=20
# Huge asset
REQ_H=50;   CONC_H=10

# Media (mp4/webm/mov/mkv/mp3/wav): do a range fetch and a modest ab full GET
MEDIA_RANGE_BYTES=$((100*1024))    # first 100 KiB
MEDIA_AB_REQ=100; MEDIA_AB_CONC=10

# Global limit knobs (defaults = process ALL). Set to integers to cap.
MAX_FILES_TOTAL="${MAX_FILES_TOTAL:-}"      # e.g., 2000 to cap
MAX_FILES_PER_DIR="${MAX_FILES_PER_DIR:-}"  # e.g., 200

PATH="/usr/pkg/bin:/usr/pkg/sbin:/usr/sbin:/usr/bin:$PATH"; export PATH

# ---------- Helpers ----------
log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

ensure_line_in_rcconf() { grep -q "^$1\$" /etc/rc.conf 2>/dev/null || echo "$1" >> /etc/rc.conf; }

copy_rcd_if_missing() {
  [ -f "/etc/rc.d/$1" ] || cp "/usr/pkg/share/examples/rc.d/$1" /etc/rc.d/
  chmod +x "/etc/rc.d/$1"
}

ensure_pkg() {
  if ! pkg_info -qe "$1"; then
    log "Installing package: $1"
    pkgin -y install "$1"
  else
    log "Package already installed: $1"
  fi
}

prepare_docs() {
  # Create docroot and base test files
  DOCROOT="$1"
  mkdir -p "$DOCROOT"
  umask 022
  # Small file
  cat > "$DOCROOT/$SMALL_FILE" <<'EOF'
<!doctype html>
<html><head><meta charset="utf-8"><title>Web Server Experiment</title></head>
<body><h1>It works!</h1><p>Small static page for benchmarking.</p></body></html>
EOF
  # Large file (~1 MiB)
  dd if=/dev/zero of="$DOCROOT/$LARGE_FILE" bs=1m count=1 >/dev/null 2>&1
}

tighten_perms() {
  # Least-privilege on docroots
  for d in "$APACHE_DOCROOT" "$NGINX_DOCROOT"; do
    chown -R www:www "$d"
    find "$d" -type d -exec chmod 0755 {} \;
    find "$d" -type f -exec chmod 0644 {} \;
  done
}

wait_port_ready() {
  H="$1"; P="$2"
  i=0
  while :; do
    if /usr/bin/telnet "$H" "$P" </dev/null 2>/dev/null | grep -q 'Escape character'; then
      break
    fi
    i=$((i+1)); [ $i -le 30 ] || { log "Timeout waiting for $H:$P"; exit 1; }
    sleep 1
  done
}

ab_safe() {
  command -v ab >/dev/null 2>&1 || { log "ERROR: ab not found (apache24 provides it)."; exit 1; }
  ab "$@"
}

mime_guess() {
  # Prefer "file -i" when available; fallback to extension
  f="$1"
  if command -v file >/dev/null 2>&1; then
    file -b -i "$f" 2>/dev/null | awk -F';' '{print $1}'
  else
    ext="${f##*.}"; ext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')
    case "$ext" in
      html|htm) echo "text/html" ;;
      txt|md) echo "text/plain" ;;
      jpg|jpeg) echo "image/jpeg" ;;
      png) echo "image/png" ;;
      gif) echo "image/gif" ;;
      svg) echo "image/svg+xml" ;;
      pdf) echo "application/pdf" ;;
      mp4) echo "video/mp4" ;;
      webm) echo "video/webm" ;;
      mov) echo "video/quicktime" ;;
      mkv) echo "video/x-matroska" ;;
      mp3) echo "audio/mpeg" ;;
      wav) echo "audio/wav" ;;
      *) echo "application/octet-stream" ;;
    esac
  fi
}

type_class() {
  # Map to text/image/doc/media/other by content-type or extension
  ct="$1"; p="$2"
  case "$ct" in
    text/*) echo "text" ;;
    image/*) echo "image" ;;
    audio/*|video/*) echo "media" ;;
    application/pdf) echo "doc" ;;
    *)  # fallback by extension
      ext="${p##*.}"; ext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')
      case "$ext" in
        txt|md|html|htm) echo "text" ;;
        jpg|jpeg|png|gif|svg) echo "image" ;;
        mp4|webm|mov|mkv|mp3|wav) echo "media" ;;
        pdf) echo "doc" ;;
        *) echo "other" ;;
      esac ;;
  esac
}

size_bin() {
  sz="$1"
  if [ "$sz" -le "$BIN_SMALL_MAX" ]; then echo "small"
  elif [ "$sz" -le "$BIN_MED_MAX" ]; then echo "medium"
  elif [ "$sz" -le "$BIN_LARGE_MAX" ]; then echo "large"
  else echo "huge"; fi
}

measure_one() {
  LABEL="$1"      # apache|nginx
  DOCROOT="$2"
  REL="$3"        # relative path from docroot
  TS="$4"
  OUT_DIR="$RESULT_DIR/${LABEL}-all-$TS"
  mkdir -p "$OUT_DIR"

  URL="http://$TARGET_HOST:$PORT/$REL"
  SAFE="$(echo "$REL" | tr '/ ' '__')"
  FILE_PATH="$DOCROOT/$REL"
  [ -f "$FILE_PATH" ] || return 0

  # Collect metadata
  SIZE=$(stat -f %z "$FILE_PATH" 2>/dev/null || stat -c %s "$FILE_PATH")
  CT=$(mime_guess "$FILE_PATH")
  CLASS=$(type_class "$CT" "$FILE_PATH")
  BIN=$(size_bin "$SIZE")

  # Per-file result folder
  FDIR="$OUT_DIR/files/$SAFE"; mkdir -p "$FDIR"

  # Save meta + headers
  {
    echo "rel_path,$REL"
    echo "size_bytes,$SIZE"
    echo "size_bin,$BIN"
    echo "content_type,$CT"
    echo "class,$CLASS"
    echo "url,$URL"
  } > "$FDIR/meta.csv"
  /usr/bin/curl -s -I "$URL" > "$FDIR/headers.txt" || true

  # Choose load profile
  REQ=; CONC=
  case "$BIN" in
    small)  REQ=$REQ_S; CONC=$CONC_S ;;
    medium) REQ=$REQ_M; CONC=$CONC_M ;;
    large)  REQ=$REQ_L; CONC=$CONC_L ;;
    huge)   REQ=$REQ_H; CONC=$CONC_H ;;
  esac

  # Execute measurement
  case "$CLASS" in
    text|image|doc|other)
      ab_safe -n "$REQ" -c "$CONC" "$URL" | tee "$FDIR/ab.txt" >/dev/null
      ;;
    media)
      # Range (partial) + modest full GET load
      /usr/bin/curl -s -D "$FDIR/range_headers.txt" -o /dev/null -r 0-$((MEDIA_RANGE_BYTES-1)) "$URL" || true
      ab_safe -n "$MEDIA_AB_REQ" -c "$MEDIA_AB_CONC" "$URL" | tee "$FDIR/ab.txt" >/dev/null
      ;;
  esac

  # Parse a few key metrics from ab output if present
  if [ -f "$FDIR/ab.txt" ]; then
    RPS=$(grep -E 'Requests per second:' "$FDIR/ab.txt" | awk '{print $4}')
    TPR=$(grep -E '^Time per request:' "$FDIR/ab.txt" | head -n1 | awk '{print $4}')
    XFR=$(grep -E 'Transfer rate:' "$FDIR/ab.txt" | awk '{print $3}')
  else
    RPS=""; TPR=""; XFR=""
  fi

  echo "$LABEL,$REL,$SIZE,$BIN,$CLASS,$CT,$REQ,$CONC,${RPS:-},${TPR:-},${XFR:-}" >> "$OUT_DIR/summary.csv"
}

measure_all_files() {
  LABEL="$1"
  DOCROOT="$2"
  TS="$3"
  OUT_DIR="$RESULT_DIR/${LABEL}-all-$TS"
  mkdir -p "$OUT_DIR/files"
  SUM="$OUT_DIR/summary.csv"

  # Header for global CSV
  echo "server,rel_path,size_bytes,size_bin,class,content_type,ab_reqs,ab_conc,req_per_sec,time_per_req_ms,transfer_rate_kBps" > "$SUM"

  COUNT=0
  # Walk the dataset directory; optionally cap per directory and total
  find "$DOCROOT/$DATA_SUBDIR" -type f | while read -r F; do
    REL="${F#$DOCROOT/}"

    # Per-dir cap
    if [ -n "${MAX_FILES_PER_DIR:-}" ]; then
      DIR="${REL%/*}"
      CUR=$(grep -c ",$DIR/" "$SUM" 2>/dev/null || true)
      [ "$CUR" -ge "$MAX_FILES_PER_DIR" ] && continue
    fi

    # Global cap
    if [ -n "${MAX_FILES_TOTAL:-}" ]; then
      [ "$COUNT" -ge "$MAX_FILES_TOTAL" ] && break
    fi

    measure_one "$LABEL" "$DOCROOT" "$REL" "$TS"
    COUNT=$((COUNT+1))
  done

  log "Saved ALL-files results to: $OUT_DIR (files: $COUNT)"
}

# ---------- Dataset publish ----------
publish_dataset() {
  DOCROOT="$1"
  DEST="$DOCROOT/$DATA_SUBDIR"
  mkdir -p "$DEST"
  log "Extracting dataset to $DEST ..."
  tar -xzf "$DATA_TAR" -C "$DEST"

  # Simple ind
