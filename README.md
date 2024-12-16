# httpecho

## Overview

`httpecho` is an HTTP echo server that allows you to test various HTTP request and response behaviors. It supports several query parameters to adjust the response behavior.

## Installation
```sh
grm install jsnjack/httpecho
```

## Usage

To start the HTTP echo server, use the following command:

```sh
httpecho start
```

### Query Parameters

- `sleep`: Delay the response for the specified duration. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". Example: `?sleep=5s`
- `status`: Return the response with the specified status code. Example: `?status=200`
- `size`: On top of headers, add data of specific size to the response body. Supported units are "KB", "MB", "GB". Example: `?size=200KB`
- `header`: Add additional headers to the response. Example: `?header=Content-Type:text/plain`
- `verbose`: Log the full request (headers and body) to stdout. Example: `?verbose=true`

### Example

To start the server on a specific address and port:

```sh
httpecho start --bind 127.0.0.1:8008
```

To start the server with a certificate for HTTPS:

```sh
httpecho start --bind 127.0.0.1:8008 --cert /path/to/cert.pem
```
