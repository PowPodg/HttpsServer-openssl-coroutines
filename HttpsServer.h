#pragma once

#include <iostream>

#include <string>
#include <functional>
#include <thread>
#include <coroutine>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else 
using SOCKET = int;
#define INVALID_SOCKET  (-1)
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
inline int WSACleanup() { return 0; }
inline int closesocket(SOCKET sock) { return close(sock); }
using ADDRINFO = struct addrinfo;
#define WSAGetLastError() (errno)
#endif


//----------------------
class HttpsServer
{
	static const int SIZE_GET_REQ = 2048;

	struct task_asyn
	{
		struct promise_type
		{
			task_asyn get_return_object() { return task_asyn{}; }
			std::suspend_never initial_suspend() noexcept { return {}; }
			std::suspend_never final_suspend() noexcept { return {}; }
			void return_void() {}
			void unhandled_exception() {}
		};
	};
	//---------------------------------------------------
	class ret_task_asyn
	{
	public:
		struct promise_type
		{
			int _result;
			ret_task_asyn get_return_object() {
				return ret_task_asyn{ std::coroutine_handle<promise_type>::from_promise(*this) };
			}
			std::suspend_never initial_suspend() noexcept { return {}; }
			std::suspend_always final_suspend() noexcept { return {}; }
			void return_value(int res) noexcept { _result = res; }
			void unhandled_exception() { std::terminate(); }
		};
		int result() { return handle_.promise()._result; }
		~ret_task_asyn() { if (handle_) handle_.destroy(); }
	private:
		ret_task_asyn(std::coroutine_handle<promise_type> handle) : handle_(handle) {}
		std::coroutine_handle<promise_type> handle_;
	};
	//-------------
	using VoidFun = std::function<void(const std::string_view&, std::string_view&)>;
	using arr_pairs = std::vector<std::pair<std::string_view, VoidFun>>;
	arr_pairs arr_get_pairs;
	//-----------
	SSL_CTX* ssl_ctx;
	SOCKET listen_sock;
	SOCKET Create_listen_socket(const int&);
	//--------
	class Client {
	private:
		std::string rest_get = "GET ";
		VoidFun void_func;
		struct rget {
			std::string resp_header = std::string(SIZE_GET_REQ, '\0');
			std::string_view resp_body;
			int Content_Length = 10;
			rget();
			void set_cont_len(const int&);
		};
		std::string Header_received = std::string(SIZE_GET_REQ, '\0');
		int Receive_data(SSL*);
		bool Analys_expression(const arr_pairs&);
		int Send_data(SSL*, const std::string_view);
		SOCKET copy_socket;
		SSL_CTX* copy_ssl_ctx;
		arr_pairs copy_arr_pr;
		rget _get;
		//---------
		class Await {
		public:
			Await(Client& cl) : client(std::addressof(cl)) {}
			bool await_ready() const noexcept { return false; }
			void await_suspend(std::coroutine_handle<>) noexcept;
			void await_resume() const noexcept {}
		private:
			Client* client = nullptr;
		};
		//-----------
		class AwaitSend {
		public:
			bool await_ready() const noexcept { return false; }
			void await_suspend(std::coroutine_handle<>) noexcept;
			int await_resume() const noexcept { return std::move(Quant_send); }
			AwaitSend(Client& cl, SSL* ssl_temp, const std::string_view resp) : client(std::addressof(cl)), _ssl_temp(ssl_temp), _resp(resp) {}
		private:
			Client* client = nullptr;
			SSL* _ssl_temp = nullptr;;
			std::string_view _resp;
			int Quant_send = 0;
		};
		//---------------------------------------------	
		void execution();
		ret_task_asyn _send_data(SSL*, const std::string_view);
	public:
		Await ExecutAsync();
		Client(const SOCKET&, SSL_CTX*, const arr_pairs&);
		int async_send_data(SSL*, const std::string_view);
		~Client() { SSL_CTX_free(copy_ssl_ctx); }
	};
	//-------
	task_asyn Connect_waiting(const int& port);
public:
	HttpsServer(const std::string_view, const std::string_view);
	~HttpsServer();
	bool Get(const std::string_view, VoidFun);
	bool Listen(const int& port);
};

#ifndef _MSC_VER
#include "HttpsServer.cpp"
#endif
