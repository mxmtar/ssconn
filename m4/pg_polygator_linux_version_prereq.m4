#
# check polygator-linux version
#
# PG_POLYGATOR_LINUX_VERSION_PREREQ([version])

AC_DEFUN([PG_POLYGATOR_LINUX_VERSION_PREREQ],
[

AC_MSG_CHECKING([for polygator-linux version >= $1])

POLYGATOR_LINUX_VERSION=""

[ARG_GREP_FILTER='^[0-9]\{1,\}\(\.[0-9]\{1,\}\)\{1,\}.*$']
[ARG_SED_FILTER='{s:^\([0-9]\{1,\}\(\.[0-9]\{1,\}\)\{1,\}\).*$:\1:}']

[FILE_GREP_FILTER='^[[:space:]]*#define[[:space:]]*POLYGATOR_LINUX_VERSION[[:space:]]*"[0-9]\{1,\}\(\.[0-9]\{1,\}\)\{1,\}.*"[[:space:]]*$']
[FILE_SED_FILTER='{s:^[[:space:]]*#define[[:space:]]*POLYGATOR_LINUX_VERSION[[:space:]]*"\([0-9]\{1,\}\(\.[0-9]\{1,\}\)\{1,\}\).*"[[:space:]]*$:\1:}']

if test -f "$lt_sysroot/usr/include/polygator/version.h" ; then
	REQ_POLYGATOR_LINUX_VERSION_INPUT=$1
	[REQ_POLYGATOR_LINUX_VERSION=`echo ${REQ_POLYGATOR_LINUX_VERSION_INPUT} | ${GREP} -e ${ARG_GREP_FILTER} | ${SED} -e ${ARG_SED_FILTER}`]
	if test -z "$REQ_POLYGATOR_LINUX_VERSION"; then
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT(bad version string \"$1\")
		exit 1
	fi
	[REQ_POLYGATOR_LINUX_VERSION_PARTS=(`echo ${REQ_POLYGATOR_LINUX_VERSION} | ${SED} -e 'y:\.: :'`)]
	[REQ_POLYGATOR_LINUX_VERSION_MAJOR=`printf %d ${REQ_POLYGATOR_LINUX_VERSION_PARTS[0]}`]
	[REQ_POLYGATOR_LINUX_VERSION_MINOR=`printf %d ${REQ_POLYGATOR_LINUX_VERSION_PARTS[1]}`]
	[REQ_POLYGATOR_LINUX_VERSION_PATCH=`printf %d ${REQ_POLYGATOR_LINUX_VERSION_PARTS[2]}`]

	[TST_POLYGATOR_LINUX_VERSION=`cat $lt_sysroot/usr/include/polygator/version.h | ${GREP} -e ${FILE_GREP_FILTER} | ${SED} -e ${FILE_SED_FILTER}`]
	if test -z "$TST_POLYGATOR_LINUX_VERSION"; then
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT([Cannot find POLYGATOR_LINUX_VERSION in polygator/version.h header to retrieve polygator-linux version!])
		exit 1
	fi
	POLYGATOR_LINUX_VERSION=TST_POLYGATOR_LINUX_VERSION

	if test -z "$TST_POLYGATOR_LINUX_VERSION"; then
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT(bad version string \"$TST_POLYGATOR_LINUX_VERSION\")
		exit 1
	fi
	[TST_POLYGATOR_LINUX_VERSION_PARTS=(`echo ${TST_POLYGATOR_LINUX_VERSION} | ${SED} -e 'y:\.: :'`)]
	[TST_POLYGATOR_LINUX_VERSION_MAJOR=`printf %d ${TST_POLYGATOR_LINUX_VERSION_PARTS[0]}`]
	[TST_POLYGATOR_LINUX_VERSION_MINOR=`printf %d ${TST_POLYGATOR_LINUX_VERSION_PARTS[1]}`]
	[TST_POLYGATOR_LINUX_VERSION_PATCH=`printf %d ${TST_POLYGATOR_LINUX_VERSION_PARTS[2]}`]

	if test $TST_POLYGATOR_LINUX_VERSION_MAJOR -ge $REQ_POLYGATOR_LINUX_VERSION_MAJOR &&
		test $TST_POLYGATOR_LINUX_VERSION_MINOR -ge $REQ_POLYGATOR_LINUX_VERSION_MINOR &&
		test $TST_POLYGATOR_LINUX_VERSION_PATCH -ge $REQ_POLYGATOR_LINUX_VERSION_PATCH ; then
		AC_SUBST(POLYGATOR_LINUX_VERSION)
		AC_MSG_RESULT($TST_POLYGATOR_LINUX_VERSION)
	else
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT(polygator-linux version \"$TST_POLYGATOR_LINUX_VERSION\" is early then required \"$REQ_POLYGATOR_LINUX_VERSION\")
		exit 1
	fi
else
	AC_MSG_RESULT(fail)
	AC_MSG_RESULT(polygator/version.h not found")
	exit 1
fi

])
