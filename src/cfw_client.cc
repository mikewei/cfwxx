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

DEFINE_uint64(port, 12321, "bind port");
DEFINE_string(server, "127.0.0.1", "server IP");
DEFINE_uint64(server_port, 12322, "server port");

static Channel<Pkg> g_channel;

void HandleClient(TcpSocket csk)
{
	SockAddrIn client_addr;
	csk.GetPeerAddr(&client_addr);
	auto key = MakeKey(client_addr);
	VLOG(1) << "MakeKey: " << key;
	if (!g_channel.Own(key)) {
		LOG(FATAL) << "thread:" << key << " client key conflicts";
	}
	g_channel.Push(0, std::make_shared<Pkg>(key, Cmd::kConn));
	LOG(INFO) << "thread:" << key << " start";

	Buffer buf;
	time_t last_active = ::time(nullptr);
	// wait 50ms for data incoming, CAN'T use RecvN
	PCHECK(csk.SetRecvTimeout(std::chrono::milliseconds(50)));
	while (true) {
		int len = csk.Recv(buf.data(), sizeof(buf));
		if (len > 0) {
			LOG(INFO) << "thread:" << key << " socket recv tcp pkg [" << len << "]";
			g_channel.Push(0, std::make_shared<Pkg>(key, Cmd::kData, buf.data(), len));
			last_active = ::time(nullptr);
		} else if (len < 0 && errno == EAGAIN) {
			VLOG(1) << "thread:" << key << " socket recv timeout";
		} else {
			if (len == 0) {
				LOG(INFO) << "thread:" << key << " socket closed by peer";
			} else {
				PLOG(INFO) << "thread:" << key << " socket recv error";
			}
			g_channel.Push(0, std::make_shared<Pkg>(key, Cmd::kClose));
			goto exit;
		}

		while (true) {
			auto pkg = g_channel.Pop(key);
			if (!pkg) {
				VLOG(1) << "thread:" << key << " channel empty";
				break; // go on reading socket
			}
			last_active = ::time(nullptr);
			if (pkg->cmd == Cmd::kClose) {
				LOG(INFO) << "thread:" << key << " channel cmd kClose";
				goto exit;
			} else if (pkg->cmd == Cmd::kData) {
				LOG(INFO) << "thread:" << key << " channel cmd kData";
				if(!csk.SendValue(pkg->data)) {
					PLOG(ERROR) << "thread:" << key << " socket send data error";
					g_channel.Push(0, std::make_shared<Pkg>(key, Cmd::kClose));
					goto exit;
				}
			} else {
				LOG(FATAL) << "thread:" << key << " channel cmd unexpected";
			}
		}

		if (last_active + 600 < ::time(nullptr)) {
			LOG(ERROR) << "thread:" << key << " is dead";
			goto exit;
		}
	}
exit:
	g_channel.Free(key);
	LOG(INFO) << "thread:" << key << " exit";
}

void ProcessIo(TcpSocket& sk)
{
	Crypt enc, dec;
	// wait 10min for expected data
	sk.SetRecvTimeout(std::chrono::minutes(10));
	while (true) {
		auto new_pkg = std::make_shared<Pkg>();
		// wait 50ms for pkg incoming
		int r = RecvPkg(sk, dec, new_pkg.get(), std::chrono::milliseconds(50));
		if (r < 0) {
			PLOG(INFO) << "io socket recv error";
			break;
		} else if (r == 0) {
			LOG(INFO) << "io socket recv pkg {key:" << new_pkg->key 
				<< " cmd:" << static_cast<unsigned>(new_pkg->cmd)
				<< " len:" << new_pkg->data.size() << "}";
			g_channel.Push(new_pkg->key, new_pkg);
		} else {
			VLOG(1) << "io socket recv timeout";
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
	}
}

void ChannelIoThread()
{
	LOG(INFO) << "io thread start";
	while (true) {
		TcpSocket sk;
		if (sk.Connect(SockAddrIn(FLAGS_server, FLAGS_server_port))) {
			LOG(INFO) << "io thread connected to server";
			ProcessIo(sk);
			// connection loss
			// g_channel.Broadcast(0, std::make_share<Pkg>(Cmd::kClose));
			LOG(INFO) << "io thread disconnected to server";
		} else {
			LOG(INFO) << "io thread connect server failed";
		}
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

int main(int argc, char* argv[])
{
	google::ParseCommandLineFlags(&argc, &argv, true);
	google::InitGoogleLogging(argv[0]);
	FLAGS_logbufsecs = 0;
	daemon(1, 1);
	LOG(INFO) << "--- cfw_client start ---";

	std::thread(ChannelIoThread).detach();

	time_t last_gc = ::time(nullptr);
	TcpServerSocket ssk{SockAddrIn(FLAGS_port)};
	ssk.Listen();
	while (true) {
		TcpSocket csk = ssk.Accept();
		PCHECK(csk) << "accept error";
		LOG(INFO) << "accept new connection";
		std::thread(HandleClient, std::move(csk)).detach();

		time_t now = ::time(nullptr);
		if (last_gc + 60 < now)
			g_channel.GarbageCleanup(120);
	}

	return 0;
}
