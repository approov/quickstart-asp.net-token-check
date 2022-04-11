# Unprotected Server Example

The unprotected example is the base reference to build the [Approov protected servers](/servers/hello/src/approov-protected-server/). This a very basic Hello World server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try It](#try-it)


## Why?

To be the starting building block for the [Approov protected servers](/servers/hello/src/approov-protected-server/), that will show you how to lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The ASP.Net API server is very simple and only replies to the endpoint `/` with the message:

```json
{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have installed:

* [.NET 6 SDK](https://docs.microsoft.com/en-us/dotnet/core/install/)


[TOC](#toc---table-of-contents)


## Try It

You can run this example from the `./servers/hello/src/unprotected-server` folder with:

```bash
dotnet run
```

Finally, you can test that it works with:

```text
curl -iX GET 'http://localhost:8002'
```

The response will be:

```texr
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 11 Apr 2022 18:15:47 GMT
Server: Kestrel
Transfer-Encoding: chunked

{"message":"Hello, World!"}
```

[TOC](#toc---table-of-contents)
