/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "_string.h"

#ifdef WANT_WIDE
#define Wstrncmp wcsncmp
#else
libc_hidden_proto(strncmp)
#define Wstrncmp strncmp
#endif

int Wstrncmp(register const Wchar *s1, register const Wchar *s2, size_t n)
{
#ifdef WANT_WIDE
	printf("test1 out");
	while (n && (*((Wuchar *)s1) == *((Wuchar *)s2)))
	{
		printf("test1");
		if (!*s1++)
		{
			return 0;
		}
		++s2;
		--n;
	}
	printf("test1 out2");
	return (n == 0) ? 0 : ((*((Wuchar *)s1) < *((Wuchar *)s2)) ? -1 : 1);
#else
	int r = 0;

	// printf("test2 out");
	while (n-- && ((r = ((int)(*((unsigned char *)s1))) - *((unsigned char *)s2++)) == 0) && *s1++)
	{
		// printf("test2");
	}
	// printf("test2 out2");
	return r;
#endif
}
#ifndef WANT_WIDE
libc_hidden_weak(strncmp)
#endif
