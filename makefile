cc_local=g++
cc_x86=/toolchains/lede-sdk-17.01.2-x86-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-i386_pentium4_gcc-5.4.0_musl-1.1.16/bin/i486-openwrt-linux-c++
cc_amd64=/toolchains/lede-sdk-17.01.2-x86-64_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-5.4.0_musl-1.1.16/bin/x86_64-openwrt-linux-c++


SOURCES=main.cpp log.cpp common.cpp lib/fec.cpp lib/rs.cpp crc32/Crc32.cpp packet.cpp delay_manager.cpp fd_manager.cpp connection.cpp fec_manager.cpp misc.cpp tunnel_client.cpp tunnel_server.cpp my_ev.cpp siphash.cpp auth.cpp crypto/kdf.cpp control_proto.cpp port_range_manager.cpp test_mode.cpp test_mode_net.cpp -isystem libev
NAME=speederv2

# Vendored crypto is C, not C++. The .c files stay OUT of SOURCES (which the
# C++ driver compiles) to avoid duplicate symbols; every link target compiles
# its own C objects with -x c through that target's compiler variable.
CRYPTO_OBJS=crypto/monocypher.o crypto/wrap.o
CRYPTO_OBJS_SAN=crypto/monocypher.san.o crypto/wrap.san.o
CRYPTO_OBJS_AMD64=crypto/monocypher.amd64.o crypto/wrap.amd64.o
CRYPTO_OBJS_X86=crypto/monocypher.x86.o crypto/wrap.x86.o

# `all` stays the default goal even though the crypto object rules above appear
# before it in the file.
.DEFAULT_GOAL := all


FLAGS= -std=c++11   -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers ${OPT}

TARGETS=amd64 x86

TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/${NAME}_\1/g'` version.txt

# Per-target C objects for the vendored crypto. -x c is required because every
# compiler variable above is a C++ driver; -std=c99 (never the C++ -std=c++11)
# keeps the C translation units valid. The sanitize target builds its own
# instrumented objects so ASan/UBSan cover the vendored code too.
crypto/monocypher.o: crypto/monocypher.c crypto/monocypher.h
	${cc_local} -x c -std=c99 -Wall -Wextra -I. ${OPT} -c crypto/monocypher.c -o $@

crypto/wrap.o: crypto/wrap.c crypto/wrap.h crypto/monocypher.h
	${cc_local} -x c -std=c99 -Wall -Wextra -I. ${OPT} -c crypto/wrap.c -o $@

crypto/monocypher.san.o: crypto/monocypher.c crypto/monocypher.h
	${cc_local} -x c -std=c99 -Wall -Wextra -I. -O1 -ggdb -fsanitize=address,undefined -fno-omit-frame-pointer -c crypto/monocypher.c -o $@

crypto/wrap.san.o: crypto/wrap.c crypto/wrap.h crypto/monocypher.h
	${cc_local} -x c -std=c99 -Wall -Wextra -I. -O1 -ggdb -fsanitize=address,undefined -fno-omit-frame-pointer -c crypto/wrap.c -o $@

crypto/monocypher.amd64.o: crypto/monocypher.c crypto/monocypher.h
	${cc_amd64} -x c -std=c99 -Wall -Wextra -I. ${OPT} -c crypto/monocypher.c -o $@

crypto/wrap.amd64.o: crypto/wrap.c crypto/wrap.h crypto/monocypher.h
	${cc_amd64} -x c -std=c99 -Wall -Wextra -I. ${OPT} -c crypto/wrap.c -o $@

crypto/monocypher.x86.o: crypto/monocypher.c crypto/monocypher.h
	${cc_x86} -x c -std=c99 -Wall -Wextra -I. ${OPT} -c crypto/monocypher.c -o $@

crypto/wrap.x86.o: crypto/wrap.c crypto/wrap.h crypto/monocypher.h
	${cc_x86} -x c -std=c99 -Wall -Wextra -I. ${OPT} -c crypto/wrap.c -o $@

# targets for native (non-cross) compile
all:git_version ${CRYPTO_OBJS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${CRYPTO_OBJS} ${FLAGS} -lrt -ggdb -static -O2

#targets only for debug purpose
fast: git_version ${CRYPTO_OBJS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${CRYPTO_OBJS} ${FLAGS} -lrt -ggdb
debug: git_version ${CRYPTO_OBJS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${CRYPTO_OBJS} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG -ggdb
debug2: git_version ${CRYPTO_OBJS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${CRYPTO_OBJS} ${FLAGS} -lrt -Wformat-nonliteral -ggdb

#targets only for 'make release'

# The cross toolchains live at fixed OpenWRT SDK paths; when they are absent
# (the usual case on a native dev box) the target prints a loud SKIP rather than
# failing on a missing compiler.
HAVE_AMD64=$(shell test -x ${cc_amd64} && echo yes)
HAVE_X86=$(shell test -x ${cc_x86} && echo yes)

ifeq (${HAVE_AMD64},yes)
amd64:git_version ${CRYPTO_OBJS_AMD64}
	${cc_amd64}   -o ${NAME}_$@    -I. ${SOURCES} ${CRYPTO_OBJS_AMD64} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
else
amd64:git_version
	@echo "SKIP: amd64 cross-compiler not found at ${cc_amd64}; skipping speederv2_amd64"
endif

ifeq (${HAVE_X86},yes)
x86:git_version ${CRYPTO_OBJS_X86}
	${cc_x86}   -o ${NAME}_$@      -I. ${SOURCES} ${CRYPTO_OBJS_X86} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
else
x86:git_version          #to build this you need 'g++-multilib' installed
	@echo "SKIP: x86 cross-compiler not found at ${cc_x86}; skipping speederv2_x86"
endif


release: ${TARGETS}
	cp git_version.h version.txt
	tar -zcvf ${TAR}

test: all test-selftest
	bash tests/smoke.sh ./${NAME}

test-selftest: all
	./${NAME} --test-selftest

test-mode: all
	bash tests/smoke_test_mode.sh ./${NAME}

test-port-range: all
	bash tests/smoke_port_range.sh ./${NAME}

# Sanitizer build. Dynamic link only: no -static here (unlike `all`), because
# ASan/UBSan cannot be combined with a fully static libc on this target.
sanitize: git_version ${CRYPTO_OBJS_SAN}
	rm -f ${NAME}-sanitize
	${cc_local}   -o ${NAME}-sanitize -I. ${SOURCES} ${CRYPTO_OBJS_SAN} ${FLAGS} -lrt -ggdb -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
	./${NAME}-sanitize --test-selftest
	bash tests/smoke.sh ./${NAME}-sanitize

clean:
	rm -f ${TAR}
	rm -f ${NAME}
	rm -f ${NAME}-sanitize
	rm -f git_version.h
	rm -f crypto/*.o

git_version:
	    echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
