#pragma once

#include <iostream>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <functional>
#include <utility>
#include <thread>
#include <coroutine>
#include <future>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

//----------------------
class HttpsServer
{
	static const int SIZE_GET_REQ = 2048;
	struct task_asyn
	{
		struct asyn_promise
		{
			task_asyn get_return_object() { return task_asyn{}; }
			std::suspend_never initial_suspend() noexcept { return {}; }
			std::suspend_never final_suspend() noexcept { return {}; }
			void return_void() {}
			void unhandled_exception() {}
		};
		using promise_type = asyn_promise;
	};
	//-------------
	using VoidFun = std::function<void(const std::string_view, std::string&)>;
	using arr_pairs = std::vector<std::pair<std::string_view, VoidFun>>;
	arr_pairs arr_get_pairs;
	//-----------
	SSL_CTX* ssl_ctx;
	SOCKET listen_sock;
	SOCKET Create_listen_socket(const int&);
//--------
	class Client {
		VoidFun void_func;
		struct rget {
			std::string resp_header = std::string(SIZE_GET_REQ, '\0');
			std::string resp_body = std::string(SIZE_GET_REQ, '\0');
			std::string req = std::string(SIZE_GET_REQ, '\0');
			int Content_Length = 10;
			rget();
			void set_cont_len(const int&);
		};
		std::string Header_received = std::string(SIZE_GET_REQ, '\0');
		int Receive_data(SSL*);
		bool Analys_expression(const arr_pairs&);
		int Send_data(SSL*, const std::string&);
		SOCKET copy_socket;
		SSL_CTX* copy_ssl_ctx;
		arr_pairs copy_arr_pr;
		rget _get;
		//---------
		class Awaitable {
		public:		
			Awaitable(Client& cl) : client(&cl) {}
			~Awaitable() = default;
			bool await_ready() const noexcept { return false; }
			void await_suspend(std::coroutine_handle<> handle) noexcept;
			void await_resume() const noexcept {}
		private:
			Client* client;
		};
		//---------
	public:
		Awaitable ExecutAsync();
		Client(const SOCKET&, SSL_CTX*, const arr_pairs&);
		 void execution();
		};
//-------
	task_asyn Connect_waiting(const int& port);
public:
	HttpsServer(const std::string_view, const std::string_view);
	~HttpsServer();
	bool Get(const std::string_view, VoidFun);
	bool Listen(const int& port);
};