#!/bin/bash

set -euo pipefail

usage()
{
	echo "Usage: $0 build" >&2
	echo "       $0 prepare-review --github-output FILE" >&2
	echo "       $0 check-full" >&2
	exit 2
}

if [ $# -lt 1 ]; then
	usage
fi

command=$1
shift

case "${command}" in
build|check-full)
	[ $# -eq 0 ] || usage
	;;
prepare-review)
	if [ $# -ne 2 ] || [ "$1" != "--github-output" ]; then
		usage
	fi
	github_output=$2
	;;
*)
	usage
	;;
esac

: "${CLANG_TIDY_BUILD_DIR:?CLANG_TIDY_BUILD_DIR must be set}"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -- "${script_dir}/.." && pwd -P)
case "${CLANG_TIDY_BUILD_DIR}" in
/*)
	build_dir=${CLANG_TIDY_BUILD_DIR}
	;;
*)
	build_dir="${project_dir}/${CLANG_TIDY_BUILD_DIR}"
	;;
esac
udev_build_dir="${build_dir}-udev"
netlink_build_dir="${build_dir}-netlink"
cc=${CC:-clang-18}
cxx=${CXX:-clang++-18}
run_clang_tidy=${RUN_CLANG_TIDY:-run-clang-tidy-18}

build()
{
	cd "${project_dir}"
	./bootstrap.sh
	mkdir "${udev_build_dir}" "${netlink_build_dir}"
	(
		cd "${udev_build_dir}"
		CC="${cc}" CXX="${cxx}" "${project_dir}/configure" \
			--enable-examples-build \
			--enable-tests-build \
			--enable-udev
	)
	(
		cd "${netlink_build_dir}"
		CC="${cc}" CXX="${cxx}" "${project_dir}/configure" \
			--enable-examples-build \
			--enable-tests-build \
			--disable-udev
	)

	bear --output "${udev_build_dir}/compile_commands.json" -- \
		make -C "${udev_build_dir}" -j"$(nproc)"
	bear --output "${netlink_build_dir}/compile_commands.json" -- \
		make -C "${netlink_build_dir}" -j"$(nproc)"
	bear --append --output "${udev_build_dir}/compile_commands.json" -- \
		"${cc}" -std=c99 -D_GNU_SOURCE \
			-I"${udev_build_dir}" \
			-I"${project_dir}/libusb" \
			-c tests/fuzz/fuzz_bos_descriptor.c \
			-o "${udev_build_dir}/fuzz_bos_descriptor.o"
	bear --append --output "${udev_build_dir}/compile_commands.json" -- \
		"${cc}" -std=c99 -D_GNU_SOURCE -Wno-macro-redefined \
			-I"${udev_build_dir}" \
			-I"${project_dir}/libusb" \
			-c tests/fuzz/fuzz_descriptor_parsers.c \
			-o "${udev_build_dir}/fuzz_descriptor_parsers.o"
}

prepare_review()
{
	mkdir "${build_dir}"
	jq -s 'add | unique_by(.file)' \
		"${udev_build_dir}/compile_commands.json" \
		"${netlink_build_dir}/compile_commands.json" \
		> "${build_dir}/compile_commands.json"

	sources=$(jq -er --arg root "${project_dir}/" '
		[.[].file |
		 if startswith($root) then ltrimstr($root)
		 else error("source outside the workspace: \(.)")
		 end] |
		unique |
		if length > 0 then join(",") else empty end
	' "${build_dir}/compile_commands.json")
	# Internal headers need translation-unit context. The full scan checks them.
	printf 'include=%s,libusb/libusb.h\n' "${sources}" >> "${github_output}"
}

check_full()
{
	status=0
	"${run_clang_tidy}" \
		-p "${udev_build_dir}" \
		-j 2 \
		-config-file="${project_dir}/.clang-tidy" \
		-header-filter='^.*/(libusb|examples|tests)/.*' \
		-warnings-as-errors='*' || status=$?
	"${run_clang_tidy}" \
		-p "${netlink_build_dir}" \
		-j 2 \
		-config-file="${project_dir}/.clang-tidy" \
		-header-filter='^.*/(libusb|examples|tests)/.*' \
		-warnings-as-errors='*' || status=$?
	return "${status}"
}

case "${command}" in
build)
	build
	;;
prepare-review)
	prepare_review
	;;
check-full)
	check_full
	;;
esac
