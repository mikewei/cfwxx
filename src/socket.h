#pragma once

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string>
#include <chrono>
#include "cfw.h"

CFW_NS_BEGIN

class SockAddr
{
public:
	virtual ~SockAddr() = default;
	virtual sockaddr* ptr() const = 0;
	virtual socklen_t len() const = 0;
	virtual std::string to_str() const = 0;
};

class SockAddrIn : public SockAddr
{
public:
	SockAddrIn() = default;
	SockAddrIn(const sockaddr_in& sa) : sa_(sa) {}
	SockAddrIn(const char* ip, uint16_t port) {
		sa_.sin_family = AF_INET;
		sa_.sin_addr.s_addr = inet_addr(ip);
		sa_.sin_port = htons(port);
	}
	SockAddrIn(uint32_t ip, uint16_t port) {
		sa_.sin_family = AF_INET;
		sa_.sin_addr.s_addr = htonl(ip);
		sa_.sin_port = htons(port);
	}
	SockAddrIn(const std::string& ip, uint16_t port)
		: SockAddrIn(ip.c_str(), port) {}
	SockAddrIn(uint16_t port) : SockAddrIn("0.0.0.0", port) {}
	virtual sockaddr* ptr() const override {
		return (sockaddr*)&sa_;
	}
	virtual socklen_t len() const override {
		return sizeof(sa_);
	}
	virtual std::string to_str() const override {
		char str[32];
		uint32_t ip = this->ip();
		int r = snprintf(str, sizeof(str), "%u.%u.%u.%u:%u",
				static_cast<unsigned>((ip >> 24) & 0xff),
				static_cast<unsigned>((ip >> 16) & 0xff),
				static_cast<unsigned>((ip >> 8) & 0xff),
				static_cast<unsigned>(ip & 0xff),
				static_cast<unsigned>(port()));
		if (r < 0 || static_cast<size_t>(r) >= sizeof(str))
			return std::string();
		return std::string(str, r);
	}
	uint32_t ip() const {
		return ntohl(sa_.sin_addr.s_addr);
	}
	uint16_t port() const {
		return ntohs(sa_.sin_port);
	}
private:
	sockaddr_in sa_;
};

// class SockAddrIn6 ...

class Socket
{
public:
	Socket(int sock);
	Socket(int domain, int type, int proto = 0);
	Socket(Socket&&);
	Socket(const Socket&) = delete;
	Socket& operator=(const Socket&) = delete;
	virtual ~Socket();

	bool Close();
	bool Bind(const SockAddr& addr);
	bool Connect(const SockAddr& addr);
	int Send(const uint8_t* buf, size_t len, int flags = MSG_NOSIGNAL);
	int Send(const char* buf, size_t len, int flags = MSG_NOSIGNAL) {
		return Send(reinterpret_cast<const uint8_t*>(buf), len, flags);
	}
	int Recv(uint8_t* buf, size_t len, int flags = 0);
	int Recv(char* buf, size_t len, int flags = 0) {
		return Recv(reinterpret_cast<uint8_t*>(buf), len, flags);
	}
	int SendTo(const uint8_t* buf, size_t len, const SockAddr& addr, int flags = 0);
	int SendTo(const char* buf, size_t len, const SockAddr& addr, int flags = 0) {
		return SendTo(reinterpret_cast<const uint8_t*>(buf), len, addr, flags);
	}
	int RecvFrom(uint8_t* buf, size_t len, SockAddr* addr = nullptr, int flags = 0);
	int RecvFrom(char* buf, size_t len, SockAddr* addr = nullptr, int flags = 0) {
		return RecvFrom(reinterpret_cast<uint8_t*>(buf), len, addr, flags);
	}

	bool IsNonBlocking();
	bool SetNonBlocking(bool nb = true);
	bool GetPeerAddr(SockAddr* addr);
	bool GetSockAddr(SockAddr* addr);
	template <class T> bool GetSockOpt(int level, int opt, T* val, size_t* len = nullptr);
	template <class T> bool SetSockOpt(int level, int opt, const T& val, size_t len = sizeof(T));
	template <class T> bool GetOpt(int opt, T* val, size_t* len = nullptr);
	template <class T> bool SetOpt(int opt, const T& val, size_t len = sizeof(T));
	template <class R, class P> bool GetRecvTimeout(std::chrono::duration<R,P>* dur);
	template <class R, class P> bool SetRecvTimeout(std::chrono::duration<R,P> dur);
	template <class R, class P> bool GetSendTimeout(std::chrono::duration<R,P>* dur);
	template <class R, class P> bool SetSendTimeout(std::chrono::duration<R,P> dur);
	bool IsReuseAddr();
	bool SetReuseAddr(bool on = true);

	operator bool() const {
		return sock() >= 0;
	}

protected:
	int sock() const {
		return sock_;
	}
	void set_sock(int sk) {
		sock_ = sk;
	}
private:
	int sock_ = -1;
};

template <class T>
bool Socket::GetSockOpt(int level, int opt, T* val, size_t* len)
{
	socklen_t optlen = len ? static_cast<socklen_t>(*len) : sizeof(T);
	int r = ::getsockopt(sock(), level, opt, 
			reinterpret_cast<void*>(val), &optlen);
	if (len)
		*len = static_cast<size_t>(optlen);
	return r == 0;
}

template <class T>
bool Socket::SetSockOpt(int level, int opt, const T& val, size_t len)
{
	int r = ::setsockopt(sock(), level, opt, 
			reinterpret_cast<const void*>(&val), static_cast<socklen_t>(len));
	return r == 0;
}

template <class T>
bool Socket::GetOpt(int opt, T* val, size_t* len)
{
	return GetSockOpt(SOL_SOCKET, opt, val, len);
}

template <class T>
bool Socket::SetOpt(int opt, const T& val, size_t len)
{
	return SetSockOpt(SOL_SOCKET, opt, val, len);
}

template <class R, class P>
bool Socket::GetRecvTimeout(std::chrono::duration<R,P>* dur)
{
	using namespace std::chrono;
	timeval tv;
	if (!GetOpt(SO_RCVTIMEO, &tv))
		return false;
	uint64_t usecs = static_cast<uint64_t>(tv.tv_sec) * 1000000 + tv.tv_usec;
	*dur = duration_cast<duration<R,P>>(microseconds(usecs));
	return true;
}

template <class R, class P>
bool Socket::SetRecvTimeout(std::chrono::duration<R,P> dur)
{
	using namespace std::chrono;
	seconds secs = duration_cast<seconds>(dur);
	microseconds usecs = dur - secs;
	timeval tv = {secs.count(), usecs.count()};
	return SetOpt(SO_RCVTIMEO, tv);
}

template <class R, class P>
bool Socket::GetSendTimeout(std::chrono::duration<R,P>* dur)
{
	using namespace std::chrono;
	timeval tv;
	if (!GetOpt(SO_SNDTIMEO, &tv))
		return false;
	uint64_t usecs = static_cast<uint64_t>(tv.tv_sec) * 1000000 + tv.tv_usec;
	*dur = duration_cast<duration<R,P>>(microseconds(usecs));
	return true;
}

template <class R, class P>
bool Socket::SetSendTimeout(std::chrono::duration<R,P> dur)
{
	using namespace std::chrono;
	seconds secs = duration_cast<seconds>(dur);
	microseconds usecs = dur - secs;
	timeval tv = {secs.count(), usecs.count()};
	return SetOpt(SO_SNDTIMEO, tv);
}


class TcpSocket : public Socket
{
public:
	TcpSocket() : Socket(AF_INET, SOCK_STREAM, 0) {}
	TcpSocket(int sock) : Socket(sock) {}
	bool SendN(const uint8_t* buf, size_t n);
	bool SendN(const char* buf, size_t n) {
		return SendN(reinterpret_cast<const uint8_t*>(buf), n);
	}
	bool RecvN(uint8_t* buf, size_t n);
	bool RecvN(char* buf, size_t n) {
		return RecvN(reinterpret_cast<uint8_t*>(buf), n);
	}
	template <class T> bool SendValue(const T& ptr);
	template <class T> bool SendValue(const std::basic_string<T>& ptr);
	template <class T> bool RecvValue(T* ptr);
};

template <class T>
bool TcpSocket::SendValue(const T& val)
{
	return SendN(reinterpret_cast<const uint8_t*>(&val), sizeof(T));
}

template <class T>
bool TcpSocket::SendValue(const std::basic_string<T>& val)
{
	return SendN(reinterpret_cast<const uint8_t*>(val.data()), 
			val.length() * sizeof(T));
}

template <class T>
bool TcpSocket::RecvValue(T* ptr)
{
	return RecvN(reinterpret_cast<uint8_t*>(ptr), sizeof(T));
}


class TcpServerSocket : public TcpSocket
{
public:
	TcpServerSocket();
	TcpServerSocket(const SockAddr& bind);
	bool Listen(int backlog = 16);
	TcpSocket Accept(SockAddr* addr = nullptr);
};

CFW_NS_END
