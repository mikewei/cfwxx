#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include <queue>
#include <array>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include "socket.h"
#include "cfw_channel.h"
#include "cfw_crypt.h"

using namespace cfw;

DEFINE_string(server, "127.0.0.1", "server IP");
DEFINE_uint64(server_port, 12322, "bind server port");

static Channel<Pkg> g_channel;

class ClientDataIo
{
public:
	ClientDataIo(Key k) : key_(k) {}
	ClientDataIo(const ClientDataIo&) = delete;
	ClientDataIo& operator=(const ClientDataIo&) = delete;
	// block read
	bool ReadN(uint8_t* buf, size_t len) {
		size_t wpos = 0;
		while (wpos < len) {
			while (!pkg_ || read_pos_ >= pkg_->data.size()) {
				int r = ReadPkg();
				if (r > 0)
					std::this_thread::sleep_for(std::chrono::milliseconds(50));
				else if (r < 0)
					return false;
			}
			size_t need = len - wpos;
		   	size_t left = pkg_->data.length() - read_pos_;
			size_t copy_len = (need <= left ? need : left);
			std::memcpy(buf + wpos, pkg_->data.data() + read_pos_, copy_len);
			wpos += copy_len;
			read_pos_ += copy_len;
		}
		return true;
	}
	template <class T>
	bool ReadValue(T* val) {
		return ReadN(reinterpret_cast<uint8_t*>(val), sizeof(T));
	}
	// non-block read
	// ret 0:OK 1:EMPTY -1:ERROR
	int ReadData(Bytes* buf) {
		if (!pkg_ || read_pos_ >= pkg_->data.size()) {
			int r = ReadPkg();
			if (r != 0) return r;
		}
		if (read_pos_ == 0) {
			*buf = pkg_->data;
		} else {
			buf->assign(pkg_->data, read_pos_, Bytes::npos);
		}
		pkg_.reset();
		read_pos_ = 0;
		return 0;
	}
	void WriteN(const uint8_t* buf, size_t len) {
		g_channel.Push(0, std::make_shared<Pkg>(key_, Cmd::kData, buf, len));
   	}
	void WriteClose() {
		g_channel.Push(0, std::make_shared<Pkg>(key_, Cmd::kClose));
	}
	Key key() const {
		return key_;
	}
protected:
	int ReadPkg() {
		auto pkg = g_channel.Pop(key_);
		if (!pkg)
			return 1;
		else if (pkg->cmd != Cmd::kData) {
			if (pkg->cmd == Cmd::kClose)
				LOG(INFO) << "thread:" << key() << " channel recv kClose!";
			else
				LOG(ERROR) << "thread:" << key()
					<< " channel recv bad cmd:" << static_cast<unsigned>(pkg->cmd);
			return -1;
		}
		pkg_ = std::move(pkg);
		read_pos_ = 0;
		return 0;
	}
private:
	Key key_;
	std::shared_ptr<Pkg> pkg_;
	size_t read_pos_;
};

static bool ProcHandshake(ClientDataIo* io)
{
	uint8_t ver, meth_count;
	if (!io->ReadValue(&ver)) return false;
	LOG(INFO) << "thread:" << io->key()
		<< " handshake req ver:" << static_cast<unsigned>(ver);
	if (!io->ReadValue(&meth_count)) return false;
	LOG(INFO) << "thread:" << io->key()
		<< " handshake req method count:" << static_cast<unsigned>(meth_count);
	for (uint8_t i = 0; i < meth_count; ++i) {
		uint8_t meth;
		if (!io->ReadValue(&meth)) return false;
		LOG(INFO) << "thread:" << io->key()
			<< " handshake req method:" << static_cast<unsigned>(meth);
	}
	Buffer buf;
	buf[0] = ver;
	buf[1] = 0;
	io->WriteN(buf.data(), 2);
	return true;
}

static bool ResolveIp(const char* url, uint32_t* net_order_ip)
{
	char buf[1024];
	struct hostent entry, *result;
	int error;
	int r = ::gethostbyname_r(url, &entry, buf, sizeof(buf), &result, &error);
	if (r) {
		LOG(ERROR) << "gethostbyname ret:" << r << " h_errno:" << error;
		return false;
	} else if (!result) {
		LOG(ERROR) << "gethostbyname resolve nothing";
		return false;
	}
	struct in_addr* ia = reinterpret_cast<struct in_addr*>(entry.h_addr_list[0]);
	*net_order_ip = ia->s_addr;
	return true;
}

static bool SendCommandResp(ClientDataIo* io, uint8_t reply, const SockAddrIn* bind = nullptr)
{
	Buffer rsp_buf;
	rsp_buf[0] = 5;
	rsp_buf[1] = reply;
	rsp_buf[2] = 0;
	rsp_buf[3] = 1;
	if (bind) {
		*reinterpret_cast<uint32_t*>(&rsp_buf[4]) = bind->ip();
		*reinterpret_cast<uint16_t*>(&rsp_buf[8]) = bind->port();
	} else {
		std::memset(&rsp_buf[4], 0, 6);
	}
	LOG(INFO) << "thread:" << io->key()
		<< " SendCommandResp {reply:" << static_cast<unsigned>(reply)
		<< " bind:" << (bind ? bind->to_str() : "0") << "}";
	io->WriteN(rsp_buf.data(), 10);
	return true;
}

static bool ProcCommand(ClientDataIo* io, std::shared_ptr<TcpSocket>* sk)
{
	uint8_t ver, cmd, rsv, atyp;
	uint32_t net_order_ip;
	uint16_t net_order_port;

	if ((!io->ReadValue(&ver)) ||
			(!io->ReadValue(&cmd)) ||
			(!io->ReadValue(&rsv)) ||
			(!io->ReadValue(&atyp))) {
		LOG(ERROR) << "thread:" << io->key() << " proc command read error";
		return false;
	}
	LOG(INFO) << "thread:" << io->key()
		<< " proc command ver:" << static_cast<unsigned>(ver)
		<< " cmd:" << static_cast<unsigned>(cmd)
		<< " rsv:" << static_cast<unsigned>(rsv)
		<< " atyp:" << static_cast<unsigned>(atyp);
	if (cmd != 1) {
		LOG(ERROR) << "thread:" << io->key() << " proc command unsurport cmd";
		SendCommandResp(io, 1);
		return false;
	} else if (rsv != 0) {
		LOG(ERROR) << "thread:" << io->key() << " proc command bad rsv:" << rsv;
		return false;
	}

	if (atyp == 1) { // ip (v4)
		if (!io->ReadValue(&net_order_ip)) {
			LOG(ERROR) << "thread:" << io->key() << " proc command read ip error";
			return false;
		}
	} else if (atyp == 3) { // url
		uint8_t len;
		char url[257];
		if ((!io->ReadValue(&len)) ||
				(!io->ReadN(reinterpret_cast<uint8_t*>(url), len))) {
			LOG(ERROR) << "thread:" << io->key() << " proc command read url error";
			return false;
		}
		url[len] = 0;
		LOG(INFO) << "thread:" << io->key() << " request url: " << url;
		if (!ResolveIp(url, &net_order_ip)) {
			LOG(ERROR) << "thread:" << io->key() << "resolve ip error";
			SendCommandResp(io, 1);
			return false;
		}
	} else {
		LOG(ERROR) << "thread:" << io->key() << " proc command unsurport atyp";
		SendCommandResp(io, 1);
		return false;
	}

	if (!io->ReadValue(&net_order_port)) {
		LOG(ERROR) << "thread:" << io->key() << " proc command read port error";
		return false;
	}

	SockAddrIn req_addr{ntohl(net_order_ip), ntohs(net_order_port)};
	LOG(INFO) << "thread:" << io->key() << " request connect to "<< req_addr.to_str();
	*sk = std::make_shared<TcpSocket>();
	if (!(*sk)->Connect(req_addr)) {
		LOG(ERROR) << "thread:" << io->key() << " connect remote server error";
		SendCommandResp(io, 1);
	}
	SockAddrIn bind_addr;
	PCHECK((*sk)->GetSockAddr(&bind_addr)) << "GetSockAddr";
	return SendCommandResp(io, 0, &bind_addr);
}

static void HandleClient(Key key)
{
	if (!g_channel.Own(key)) {
		LOG(FATAL) << "client key conflicts";
	}
	LOG(INFO) << "thread:" << key << " start";
	ClientDataIo io{key};

	if (!ProcHandshake(&io)) {
		LOG(ERROR) << "thread:" << key << " proc handshake error";
		return;
	}
	LOG(INFO) << "thread:" << key << " handshake ok";

	std::shared_ptr<TcpSocket> sk;
	if (!ProcCommand(&io, &sk)) {
		LOG(ERROR) << "thread:" << key << " proc command error";
		return;
	}
	LOG(INFO) << "thread:" << key << " connect command ok";

	Buffer buf;
	time_t last_active = ::time(nullptr);
	// wait 50ms for data incoming, CAN'T use RecvN
	PCHECK(sk->SetRecvTimeout(std::chrono::milliseconds(50)));
	while (true) {
		int len = sk->Recv(buf.data(), sizeof(buf));
		if (len > 0) {
			LOG(INFO) << "thread:" << key << " socket recv pkg [" << len << "]";
			io.WriteN(buf.data(), len);
			last_active = ::time(nullptr);
		} else if (len < 0 && errno == EAGAIN) {
			VLOG(1) << "thread:" << key << " socket recv timeout";
		} else {
			if (len == 0)
				LOG(INFO) << "thread:" << key << " socket closed by peer";
			else 
				PLOG(INFO) << "thread:" << key << " socket recv error";
			io.WriteClose();
			goto exit;
		}

		while (true) {
			Bytes data;
			int r = io.ReadData(&data);
			if (r < 0) {
				LOG(INFO) << "thread:" << key << " channel read failed";
				goto exit;
			} else if (r > 0) {
				VLOG(1) << "thread:" << key << " channel empty";
				break; // go on reading socket
			}
			LOG(INFO) << "thread:" << key << " channel read data [" << data.size() << "]";
			last_active = ::time(nullptr);
			if (!sk->SendValue(data)) {
				PLOG(ERROR) << "thread:" << key << " socket SendValue error";
				io.WriteClose();
				goto exit;
			}
		}

		if (last_active + 600 < ::time(nullptr)) {
			LOG(ERROR) << "thread:" << key << " is dead";
			goto exit;
		}
	};
exit:
	g_channel.Free(key);
	LOG(INFO) << "thread:" << key << " exit";
}

static void ProcessIoConnection(TcpSocket sk)
{
	LOG(INFO) << "new process start";
	SockAddrIn client_addr;
	sk.GetPeerAddr(&client_addr);
	// wait 10min for expected data
	sk.SetRecvTimeout(std::chrono::minutes(10));
	time_t last_gc = ::time(nullptr);
	Crypt enc, dec;

	while (true) {
		// get PKG from IO connection
		auto new_pkg = std::make_shared<Pkg>();
		// wait 50ms for pkg incoming
		int r = RecvPkg(sk, dec, new_pkg.get(), std::chrono::milliseconds(50));
		if (r < 0) {
			PLOG(INFO) << "io socket recv error";
			break;
		} else if (r == 0) {
			if (new_pkg->cmd == Cmd::kConn) {
				LOG(INFO) << "io socket recv kConn pkg key:" << new_pkg->key;
				// create thread if kConn command
				std::thread(HandleClient, new_pkg->key).detach();
			} else {
				LOG(INFO) << "io socket recv pkg {key:" << new_pkg->key
					<< " cmd:" << static_cast<unsigned>(new_pkg->cmd)
					<< " len:" << new_pkg->data.size() << "}";
				// forward pkg
				g_channel.Push(new_pkg->key, new_pkg);
			}
		}

		while (true) {
			auto pkg = g_channel.Pop(0);
			if (!pkg) {
				VLOG(1) << "io channel empty";
				break;
			}
			LOG(INFO) << "io channel recv pkg {key:" << pkg->key
				<< " cmd:" << static_cast<unsigned>(pkg->cmd)
				<< " len:" << pkg->data.size() << "}";
			bool ret = SendPkg(sk, enc, *pkg);
			PLOG_IF(ERROR, !ret) << "io socket send pkg error";
		}

		time_t now = ::time(nullptr);
		if (last_gc + 60 < now)
			g_channel.GarbageCleanup(120);
	}
	LOG(INFO) << "process exit";
}

int main(int argc, char* argv[])
{
	google::ParseCommandLineFlags(&argc, &argv, true);
	google::InitGoogleLogging(argv[0]);
	FLAGS_logbufsecs = 0;
	daemon(1, 1);
	signal(SIGCHLD, SIG_IGN);
	LOG(INFO) << "--- cfw_server start ---";

	TcpServerSocket ssk{SockAddrIn(FLAGS_server_port)};
	ssk.Listen();
	while (true) {
		TcpSocket csk = ssk.Accept();
		PCHECK(csk) << "accept error";
		LOG(INFO) << "accept new connection";
		if (fork() == 0) {
			ProcessIoConnection(std::move(csk));
			return 0;
		}
	}
	return 0;
}
