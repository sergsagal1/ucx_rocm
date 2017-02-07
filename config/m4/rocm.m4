#
# Check for ROCm  support
#
rocm_happy="no"

AC_ARG_WITH([rocm],
           [AS_HELP_STRING([--with-rocm=(DIR)], [Enable the use of ROCm (default is autodetect).])],
           [], [with_rocm=guess])

AS_IF([test "x$with_rocm" != "xno"],

      [AS_IF([test "x$with_rocm" == "x" || test "x$with_rocm" == "xguess" || test "x$with_rocm" == "xyes"],
             [
              AC_MSG_NOTICE([ROCm HSA path was not specified. Guessing ...])
              with_rocm=/opt/rocm
              ],
              [:])
      AC_CHECK_HEADER([$with_rocm/hsa/include/hsa_ext_amd.h],
                       [
                        AC_SUBST(ROCM_CPPFLAGS, "-I$with_rocm/hsa/include -I$with_rocm/libhsakmt/include/libhsakmt -DHAVE_ROCM=1")
                        AC_SUBST(ROCM_CFLAGS, "-I$with_rocm/hsa/include -I$with_rocm/libhsakmt/include/libhsakmt -DHAVE_ROCM=1")
                        AC_SUBST(ROCM_LDFLAGS, "-lhsa-runtime64 -L$with_rocm/hsa/lib")
                        CFLAGS="$CFLAGS $ROCM_CFLAGS"
                        CPPFLAGS="$CPPFLAGS $ROCM_CPPFLAGS"
                        LDFLAGS="$LDFLAGS $ROCM_LDFLAGS"
                        AC_DEFINE([HAVE_ROCM], [1], [Enable the use of ROCM])
                        transports="${transports},rocm"
                        rocm_happy="yes"],
                       [AC_MSG_WARN([ROCM not found])
                        AC_DEFINE([HAVE_ROCM], [0], [Disable the use of ROCM])])],
      [AC_MSG_WARN([ROCM was explicitly disabled])
      AC_DEFINE([HAVE_ROCM], [0], [Disable the use of ROCM])]
)


AM_CONDITIONAL([HAVE_ROCM], [test "x$rocm_happy" != xno])

