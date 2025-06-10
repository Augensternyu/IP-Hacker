#!/bin/bash

set -e

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RESET='\033[0m'

# Detect OS and architecture
RAW_OS=$(uname | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

echo -e "${BLUE}[INFO]${RESET} Detected operating system: $RAW_OS"
echo -e "${BLUE}[INFO]${RESET} Detected architecture: $ARCH"

# Default values
LIBC="musl"
FILE=""
TARGET_FILE="IP-Hacker"

# Detect libc if not on Windows
if [[ "$RAW_OS" != *"mingw"* && "$RAW_OS" != *"msys"* && "$RAW_OS" != *"cygwin"* ]]; then
  if ldd --version 2>&1 | grep -iq musl; then
    LIBC="musl"
  else
    LIBC="gnu"
  fi
  echo -e "${BLUE}[INFO]${RESET} Detected libc: $LIBC"
fi

# Map to release file
case "$RAW_OS" in
  linux)
    case "$ARCH" in
      x86_64) FILE="IP-Hacker-linux-x86_64-$LIBC" ;;
      i686) FILE="IP-Hacker-linux-i686-$LIBC" ;;
      s390x) FILE="IP-Hacker-linux-s390x-gnu" ;;
      aarch64) FILE="IP-Hacker-linux-aarch64-$LIBC" ;;
      armv5te) FILE="IP-Hacker-linux-armv5te-$LIBC" ;;
      armv7l)
        if grep -q 'vfp' /proc/cpuinfo 2>/dev/null; then
          FILE="IP-Hacker-linux-armv7-${LIBC}hf"
        else
          FILE="IP-Hacker-linux-armv7-$LIBC"
        fi
        ;;
      arm)
        if grep -q 'vfp' /proc/cpuinfo 2>/dev/null; then
          FILE="IP-Hacker-linux-arm-${LIBC}hf"
        else
          FILE="IP-Hacker-linux-arm-$LIBC"
        fi
        ;;
      *) echo -e "${RED}[ERROR]${RESET} Unsupported Linux architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64|amd64) FILE="IP-Hacker-macos-amd64" ;;
      arm64) FILE="IP-Hacker-macos-arm64" ;;
      *) echo -e "${RED}[ERROR]${RESET} Unsupported macOS architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  android)
    case "$ARCH" in
      aarch64) FILE="IP-Hacker-android-aarch64" ;;
      armv7l) FILE="IP-Hacker-android-armv7" ;;
      arm) FILE="IP-Hacker-android-arm" ;;
      *) echo -e "${RED}[ERROR]${RESET} Unsupported Android architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  mingw*|msys*|cygwin*)
    FILE="IP-Hacker.exe"
    TARGET_FILE="IP-Hacker.exe"
    ;;
  *)
    echo -e "${RED}[ERROR]${RESET} Unsupported OS: $RAW_OS"
    exit 1
    ;;
esac

# Download file
DOWNLOAD_URL="https://github.com/rsbench/IP-Hacker/releases/latest/download/$FILE"

echo -e "${BLUE}[INFO]${RESET} Downloading from: $DOWNLOAD_URL"

if command -v curl > /dev/null; then
  curl -sSL "$DOWNLOAD_URL" -o "$TARGET_FILE"
elif command -v wget > /dev/null; then
  wget -q "$DOWNLOAD_URL" -O "$TARGET_FILE"
else
  echo -e "${RED}[ERROR]${RESET} Neither curl nor wget is installed. Please install one to continue."
  exit 1
fi

chmod +x "$TARGET_FILE"
echo -e "${GREEN}[OK]${RESET} IP-Hacker has been installed successfully."
echo -e "${BLUE}[INFO]${RESET} Running: ./$TARGET_FILE --help"

./"$TARGET_FILE" --help
