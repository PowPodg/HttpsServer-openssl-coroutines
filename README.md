# HTTPS SSL Server using stackless coroutines (C++20) 

### Simplified cross-platform (Windows, Linux) http server for ssl support (openssl is used - https://github.com/openssl/openssl).

### This project shows an example of using stackless coroutines (including nested coroutines) for client connections

```cpp
HttpsServer srv("cert.pem", "key.pem");

srv.Get("/1", [](const std::string_view req, std::string_view& resp) {
	resp = "Page 1";
	cout << req;
	});

srv.Get("/2", [](const std::string_view req, std::string_view& resp) {
	resp = "Page 2";
	cout << req;
	});

srv.Listen(8120);
```