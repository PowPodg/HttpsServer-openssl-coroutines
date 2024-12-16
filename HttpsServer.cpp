#pragma once
#include "HttpsServer.h"


HttpsServer::HttpsServer(const std::string_view _cert, const std::string_view _prvt_key)
{
	listen_sock = INVALID_SOCKET;
	ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (ssl_ctx)
	{
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
		SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
		if (SSL_CTX_use_certificate_file(ssl_ctx, _cert.data(), SSL_FILETYPE_PEM) <= 0)
		{
			SSL_CTX_free(ssl_ctx);
			std::cerr << "Failed certificate file\n";
			exit(EXIT_FAILURE);
		}
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, _prvt_key.data(), SSL_FILETYPE_PEM) <= 0)
		{
			SSL_CTX_free(ssl_ctx);
			std::cerr << "Failed private key file\n";
			exit(EXIT_FAILURE);
		}
	}
	else {
		SSL_CTX_free(ssl_ctx);
		std::cerr << "Error SSL_CTX_new\n";
		exit(EXIT_FAILURE);
	}
}
//-------------------------------------------------------
HttpsServer::~HttpsServer()
{
	closesocket(listen_sock);
	SSL_CTX_free(ssl_ctx);
}
//----------------------------------------------------------
bool HttpsServer::Get(const std::string_view host, VoidFun f)
{
	arr_get_pairs.emplace_back(host, std::move(f));
	return true;
}
//---------------------------------------------------------
SOCKET HttpsServer::Create_listen_socket(const int& port)
{
	SOCKET Client_socket = INVALID_SOCKET;
	SOCKET Listen_socket = INVALID_SOCKET;

#ifdef _WIN32
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "Failed WSAStartup\n";
		return EXIT_FAILURE;
	}
#endif
	ADDRINFO* addr_inf = nullptr; ;
	ADDRINFO hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	int result = getaddrinfo(nullptr, (std::to_string(port)).c_str(), &hints, &addr_inf);

	if (result != 0) {
		std::cerr << "\ngetaddrinfo failed: " << result << "\n";
		WSACleanup();
		return EXIT_FAILURE;
	}

	Listen_socket = socket(addr_inf->ai_family, addr_inf->ai_socktype, addr_inf->ai_protocol);
	if (Listen_socket == INVALID_SOCKET) {
		std::cerr << "\nListen socket creation failed with error: " << WSAGetLastError() << "\n";
		freeaddrinfo(addr_inf);
		WSACleanup();
		return EXIT_FAILURE;
	}

	if (bind(Listen_socket, addr_inf->ai_addr, (int)addr_inf->ai_addrlen) == INVALID_SOCKET)
	{
		std::cerr << "\nBind failed with error: " << WSAGetLastError() << "\n";
		closesocket(Listen_socket);
		Listen_socket = INVALID_SOCKET;
		freeaddrinfo(addr_inf);
		WSACleanup();
		return  EXIT_FAILURE;
	}

	if (listen(Listen_socket, SOMAXCONN) == INVALID_SOCKET)
	{
		std::cerr << "\nListen failed with error: " << WSAGetLastError() << "\n";
		closesocket(Listen_socket);
		freeaddrinfo(addr_inf);
		WSACleanup();
		return EXIT_FAILURE;
	}
	return Listen_socket;
}
//-----------------------------------------------------------
HttpsServer::task_asyn HttpsServer::Connect_waiting(const int& port)
{
	listen_sock = Create_listen_socket(port);
	while (listen_sock != INVALID_SOCKET)
	{
		SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
		if (client_sock == INVALID_SOCKET) {
			std::cerr << "\nUnable to accept\n";
			closesocket(client_sock);
			continue;
		}
		Client clnt(client_sock, ssl_ctx, arr_get_pairs);
		co_await clnt.ExecutAsync();
	}
}
//-----------------------------------------------------------
bool HttpsServer::Listen(const int& port)
{
	std::jthread jth(
		[&]() {
			Connect_waiting(port);
		}
	);
	return true;
}
//--------------------------------------------------
bool HttpsServer::Client::Analys_expression(const arr_pairs& arr_get_prs)
{
	void_func = nullptr;
	if (Header_received.find(rest_get) != std::string::npos)
	{
		for (auto& p : arr_get_prs)
		{
			if (Header_received.find(std::string(rest_get + p.first.data() + " ")) != std::string::npos)
			{
				void_func = p.second;
				return true;
			}
			else continue;
		}
	}
	return true;
}
//--------------------------------------------------------------
HttpsServer::Client::rget::rget()
{
	resp_header = std::string("HTTP/1.1\r\n"
		"Version: HTTP/1.1\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"</font></h2>"
		"Content-Length: ");
}
//--------------------------------------------------------------
void HttpsServer::Client::rget::set_cont_len(const int& Cont_Length)
{
	resp_header = resp_header + std::to_string(Cont_Length) + "\r\n\r\n";
}
//----------------------------------------------------------
int HttpsServer::Client::Receive_data(SSL* ssl_temp)
{
	int rxlen = SSL_read(ssl_temp, (void*)Header_received.c_str(), SIZE_GET_REQ);
	Header_received.resize(rxlen + 1);
	if (rxlen <= 0)
	{
		if (rxlen == 0) {
			std::cerr << "\nClient closed connection\n";
		}
		else {
			std::cerr << "\nSSL_read returned %d\n", rxlen;
		}
		ERR_print_errors_fp(stderr);
	}
	return rxlen;
}
//------------------------------------------------------
int HttpsServer::Client::Send_data(SSL* ssl_temp, const std::string_view res)
{
	auto rxlen = SSL_write(ssl_temp, res.data(), (int)(res.length()));
	if (rxlen < 1)
	{
		ERR_print_errors_fp(stderr);
	}
	return rxlen;
}
//-------------------------------------------
HttpsServer::Client::Client(const SOCKET& sock, SSL_CTX* ssl_ctx, const arr_pairs& arr_pr)
{
	copy_socket = sock;
	SSL_CTX_up_ref(ssl_ctx);
	copy_ssl_ctx = ssl_ctx;
	std::copy(arr_pr.begin(), arr_pr.end(), std::back_inserter(copy_arr_pr));
}
int HttpsServer::Client::async_send_data(SSL* ssl_temp, const std::string_view resp)
{
	auto res = _send_data(ssl_temp, resp);
	return res.result();
}
//-------------------------------------------------
void HttpsServer::Client::execution()
{
	SSL* ssl_temp = SSL_new(copy_ssl_ctx);
	SSL_set_fd(ssl_temp, (int)copy_socket);

	if (SSL_accept(ssl_temp) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	else {
		auto reseiv = Receive_data(ssl_temp);
		if (reseiv) {
			Analys_expression(copy_arr_pr);
			if (void_func != nullptr)
			{
				void_func(Header_received, _get.resp_body);
				_get.set_cont_len((int)_get.resp_body.length());				
					if (async_send_data(ssl_temp, std::string(_get.resp_header + _get.resp_body.data())) < 1)
					{
						std::cerr << "\nThe page is error\n";
					}
					else
						std::cerr << "\nThe page is OK!\n";
			}
			else  std::cerr << "\nThe page is not found\n";
		}
		SSL_shutdown(ssl_temp);
		SSL_free(ssl_temp);
		closesocket(copy_socket);
		return;
	}
	SSL_shutdown(ssl_temp);
	SSL_free(ssl_temp);
	closesocket(copy_socket);
}
//-------------------------------------------------------------
HttpsServer::ret_task_asyn HttpsServer::Client::_send_data(SSL* ssl_temp, const std::string_view resp)
{
	int offset = 0, sent_bytes = 0;
	while (offset < resp.size()) {
	sent_bytes = co_await HttpsServer::Client::AwaitSend(*this, ssl_temp, resp.data()+offset);
	if(sent_bytes<1) co_return sent_bytes;
		offset += sent_bytes;
	}
	co_return sent_bytes;
}
//------------------------------------------------------------
HttpsServer::Client::Await HttpsServer::Client::ExecutAsync()
{
	return HttpsServer::Client::Await(*this);
}
//-----------------------------------------------------------------------------
void HttpsServer::Client::Await::await_suspend(std::coroutine_handle<> handle) noexcept
{
	client->execution();
	handle.resume();
}
//------------------------------------------------------
void HttpsServer::Client::AwaitSend::await_suspend(std::coroutine_handle<> handle) noexcept
{
	Quant_send = client->Send_data(_ssl_temp, _resp);
	handle.resume();
}
