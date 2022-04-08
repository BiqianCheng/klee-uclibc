/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
#define __FORCE_GLIBC
#include <stdio.h>
#include <features.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include "../klee/include/klee/klee.h"

#ifdef L_accept
int __libc_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	return 0;
}
#endif

#ifdef L_bind
int bind(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
{
	return syscall(__NR_bind, sockfd, myaddr, addrlen);
}
#endif

#ifdef L_connect
int __libc_connect(int sockfd, const struct sockaddr *saddr, socklen_t addrlen)
{
	return 0;
}
#endif

#ifdef L_getpeername
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *paddrlen)
{
	return 0;
}
#endif

#ifdef L_getsockname
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *paddrlen)
{
	return 0;
}
#endif

#ifdef L_getsockopt
int getsockopt(int fd, int level, int optname, __ptr_t optval,
			   socklen_t *optlen)
{
	return 0;
}
#endif

#ifdef L_listen
int listen(int sockfd, int backlog)
{
	return 0;
}
#endif

#ifdef L_recv
ssize_t __libc_recv(int sockfd, __ptr_t buffer, size_t len, int flags)
{
	return 0;
}
#endif

#ifdef L_recvfrom
ssize_t recvfrom(int sockfd, __ptr_t buffer, size_t len, int flags,
				 struct sockaddr *to, socklen_t *tolen)
{
	klee_make_symbolic(&buffer, sizeof(*buffer), "buffer");

	return syscall(__NR_recvfrom, sockfd, buffer, len, flags, to, tolen);
}
#endif

#ifdef L_recvmsg
ssize_t __libc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return 0;
}
#endif

#ifdef L_send
ssize_t __libc_send(int sockfd, const void *buffer, size_t len, int flags)
{
	return 0;
}

#endif

#ifdef L_sendmsg
ssize_t __libc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	return 0;
}

#endif

#ifdef L_sendto
ssize_t sendto(int sockfd, const void *buffer, size_t len, int flags,
			   const struct sockaddr *to, socklen_t tolen)
{
	return syscall(__NR_sendto, sockfd, buffer, len, flags, to, tolen);
}
#endif

#ifdef L_setsockopt
int setsockopt(int fd, int level, int optname, const void *optval,
			   socklen_t optlen)
{
	return 0;
}
#endif

#ifdef L_shutdown
int shutdown(int sockfd, int how)
{
	return 0;
}

#endif

#ifdef L_socket
int socket(int family, int type, int protocol)
{
	return syscall(__NR_socket, family, type, protocol);
}
#endif

#ifdef L_socketpair
int socketpair(int family, int type, int protocol, int sockvec[2])
{
	return 0;
}
#endif
