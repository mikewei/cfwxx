#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <array>

#define CFW_NS_BEGIN namespace cfw {
#define CFW_NS_END }

CFW_NS_BEGIN

using Bytes = std::basic_string<uint8_t>;
using Buffer = std::array<uint8_t, 4096>;
using PkgBuffer = std::array<uint8_t, 8192>;
using Key = uint64_t;

enum class Cmd : uint8_t
{
	kConn = 1,
	kData = 2,
	kClose = 3
};

struct Pkg 
{
	Pkg() = default;
	Pkg(Key k, Cmd c) : key(k), cmd(c) {}
	Pkg(Key k, Cmd c, const uint8_t* buf, size_t len) 
		: key(k), cmd(c), data(buf, len) {}

	Key key;
	Cmd cmd;
	Bytes data;
};

#if 0
#pragma pack(1)
struct PkgHead
{
	Key key; 
	Cmd cmd;
	uint32_t data_len;
};
#pragma pack()
#endif

class SockAddrIn;
class TcpSocket;
class Crypt;

uint64_t MakeKey(const SockAddrIn& addr);
bool SendPkg(TcpSocket& sk, Crypt& crypt, const Pkg& pkg);
//ret 0:ok 1:timeout -1:error
int RecvPkg(TcpSocket& sk, Crypt& crypt, Pkg* pkg, std::chrono::milliseconds msecs);

CFW_NS_END
