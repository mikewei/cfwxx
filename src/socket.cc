#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include "socket.h"

CFW_NS_BEGIN

Socket::Socket(int sock)
{
	set_sock(sock);
}

Socket::Socket(int domain, int type, int proto)
{
	int r = ::socket(domain, type, proto);
	if (r < 0)
		throw std::system_error(errno, std::system_category());
	set_sock(r);
}

Socket::Socket(Socket&& other)
{
	set_sock(other.sock());
	other.set_sock(-1);
}

Socket::~Socket()
{
	if (sock() >= 0)
		Close();
}

bool Socket::Close()
{
	if (sock() >= 0) {
		int r = ::close(sock());
		set_sock(-1);
		return r == 0;
	} else {
		return false;
	}
}

int Socket::Send(const uint8_t* buf, size_t len, int flags)
{
	return ::send(sock(), buf, len, flags);
}

int Socket::Recv(uint8_t* buf, size_t len, int flags)
{
	return ::recv(sock(), buf, len, flags);
}

bool Socket::Bind(const SockAddr& addr)
{
	int r = ::bind(sock(), addr.ptr(), addr.len());
	return r == 0;
}

bool Socket::Connect(const SockAddr& addr)
{
	int r = ::connect(sock(), addr.ptr(), addr.len());
	return r == 0;
}

bool Socket::IsNonBlocking()
{
	int flags = ::fcntl(sock(), F_GETFL, 0);
	if (flags < 0)
		return false;
	return (flags | O_NONBLOCK);
}

bool Socket::SetNonBlocking(bool nb)
{
	int flags = ::fcntl(sock(), F_GETFL, 0);
	if (flags < 0)
		return false;
	return (0 == ::fcntl(sock(), F_SETFL, flags | O_NONBLOCK));
}

bool Socket::GetPeerAddr(SockAddr* addr)
{
	sockaddr* saddr = addr->ptr();
	socklen_t salen = addr->len();
	int r = ::getpeername(sock(), saddr, &salen);
	return r == 0;
}

bool Socket::GetSockAddr(SockAddr* addr)
{
	sockaddr* saddr = addr->ptr();
	socklen_t salen = addr->len();
	int r = ::getsockname(sock(), saddr, &salen);
	return r == 0;
}

bool Socket::IsReuseAddr()
{
	int flag;
	return (GetOpt(SO_REUSEADDR, &flag) && flag);
}

bool Socket::SetReuseAddr(bool on)
{
	return SetOpt(SO_REUSEADDR, static_cast<int>(on));
}

bool TcpSocket::SendN(const uint8_t* buf, size_t n)
{
	int r;
	for (size_t i = 0; i < n; i += r) {
		r = Send(buf + i, n - i);
		if (r <= 0) 
			return false;
	}
	return true;
}

bool TcpSocket::RecvN(uint8_t* buf, size_t n)
{
	int r;
	for (size_t i = 0; i < n; i += r) {
		r = Recv(buf + i, n - i);
		if (r <= 0)
			return false;
	}
	return true;
}


TcpServerSocket::TcpServerSocket()
{
	SetReuseAddr();
}

TcpServerSocket::TcpServerSocket(const SockAddr& bind)
	: TcpServerSocket()
{
	if (!Bind(bind)) {
		throw std::system_error(errno, std::system_category());
	}
}

bool TcpServerSocket::Listen(int backlog)
{
	int r = ::listen(sock(), backlog);
	return r == 0;
}

TcpSocket TcpServerSocket::Accept(SockAddr* addr)
{
	sockaddr* saddr = nullptr;
	socklen_t salen = 0;
	if (addr) {
		saddr = addr->ptr();
		salen = addr->len();
	}
	int sk = ::accept(sock(), saddr, &salen);
	if (sk < 0)
		return TcpSocket(-1);
	return TcpSocket(sk);
}

CFW_NS_END
