#!/usr/bin/env bash

outputdir=${OUTPUTDIR:-"./dist"}

mkdir -p "${outputdir}"

function build() {
  output="${outputdir}/nexus-${1}-${2}"
  if [[ "${1}" == "windows" ]]; then
    output="${output}.exe"
  fi

  GOOS=$1 GOARCH=$2 go build -o "${output}"
}

function buildarm() {
  output="${outputdir}/nexus-${1}-${2}-${3}"
  if [[ "${1}" == "windows" ]]; then
    output="${output}.exe"
  fi

  GOOS=$1 GOARCH=$2 GOARM=$3 go build -o "${output}"
}

build linux amd64
build windows amd64
buildarm linux arm 7
