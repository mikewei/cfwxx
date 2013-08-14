#include <time.h>
#include <thread>
#include <cstring>
#include <glog/logging.h>
#include "socket.h"
#include "cfw_crypt.h"

CFW_NS_BEGIN

uint64_t MakeKey(const SockAddrIn& addr)
{
	return ((static_cast<uint64_t>(addr.ip()) << 32)
		+ (static_cast<uint64_t>(addr.port()) << 16)
		+ (static_cast<uint64_t>(::time(nullptr)) & 0xffff));
}

bool SendPkg(TcpSocket& sk, Crypt& crypt, const Pkg& pkg)
{
	PkgBuffer buf;
	size_t off = 0;
	size_t data_len = pkg.data.size();
	*reinterpret_cast<uint64_t*>(&buf[off]) = pkg.key; off += sizeof(uint64_t);
	*reinterpret_cast<uint8_t*>(&buf[off]) = static_cast<uint8_t>(pkg.cmd); off += sizeof(uint8_t);
	*reinterpret_cast<uint32_t*>(&buf[off]) = static_cast<uint32_t>(data_len); off += sizeof(uint32_t);
	CHECK(off + data_len <= sizeof(buf)) << "SendPkg buf overflow!";
	std::memcpy(&buf[off], pkg.data.data(), data_len); off += data_len;
	crypt.EncBuffer(buf.data(), off);
	return sk.SendN(buf.data(), off);
}

int RecvPkg(TcpSocket& sk, Crypt& crypt, Pkg* pkg, std::chrono::milliseconds msecs)
{
	Buffer buf;
	uint32_t len;

	// todo: sk.WaitReadable(msecs);
	// but now use naive code here
	int r;
	r = sk.Recv(buf.data(), 1, MSG_PEEK|MSG_DONTWAIT);
	if (r < 0 && errno == EAGAIN) {
		std::this_thread::sleep_for(msecs);
		r = sk.Recv(buf.data(), 1, MSG_PEEK|MSG_DONTWAIT);
	}
	if (r < 0 && errno == EAGAIN)
		return 1;
	else if (r <= 0)
		return -1;
	
	if (!sk.RecvValue(&pkg->key)) return -1;
	crypt.DecBuffer(reinterpret_cast<uint8_t*>(&pkg->key), sizeof(pkg->key));
	if (!sk.RecvValue(&pkg->cmd)) return -1;
	crypt.DecBuffer(reinterpret_cast<uint8_t*>(&pkg->cmd), sizeof(pkg->cmd));
	if (!sk.RecvValue(&len)) return -1;
	crypt.DecBuffer(reinterpret_cast<uint8_t*>(&len), sizeof(len));
	if (!sk.RecvN(buf.data(), len)) return -1;
	crypt.DecBuffer(buf.data(), len);
	pkg->data.assign(buf.data(), len);
	return 0;
}

CFW_NS_END
