#include "HttpsServer.h"
using namespace std;

int main()
{
	HttpsServer srv("cert.pem", "key.pem");

	srv.Get("/1", [](const std::string_view& req, std::string_view& resp) {
		resp = "Page 1";
		cout << req;
		});

	srv.Get("/2", [](const std::string_view& req, std::string_view& resp) {
		resp = "Page 2";
		cout << req;
		});

	srv.Listen(8120);

	return 0;
}
