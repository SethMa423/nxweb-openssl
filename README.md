# NXWEB

Ultra-fast and super-lightweight web server for applications written in C.

## Home Page

Project home page: [NXWEB.ORG](http://nxweb.org)

## Rationale

Sometimes web applications need small and fast components that are best written in C.

Example: ad banner rotation engine. It gets invoked many times on every page of your site producing little HTML snippets based on predefined configuration. How would you implement it?

CGI is not an option as it gets loaded and unloaded on every request. Writing a module for your main web server such as Apache httpd or nginx gives best performance but server's API isn't very friendly (especially when dealing with shared memory, etc.). What we need is sort of servlet container for C (just like Java has).

Before writing NXWEB I evaluated a number of existing light/embeddable web servers (mongoose, microhttpd, libevent, G-WAN) each one having their own drawbacks (see notes to [benchmarks](benchmarks.md)).

## What NXWEB offers:

* good (if not best) **performance**; see [benchmarks](benchmarks.md)
* can serve thousands concurrent requests
* small memory footprint
* event-driven & multi-threaded model designed to scale
* exceptionally light code base
* **simple API**
* decent HTTP protocol handling
* keep-alive connections
* chunked requests and responses
* **SSL support** (via OpenSSl)
* **HTTP proxy** (with keep-alive connection pooling)
* **file cache** for proxied content and custom handlers' output
* cached content can be served when backend is unavailable
* non-blocking sendfile support (with configurable small file memory cache)
* cacheable **gzip** content encoding
* cacheable **image thumbnails** with watermarks (via ImageMagick)
* basic server-side includes (**SSI**)
* **templating engine** with page inheritance
* subrequests
* integrated **Python WSGI-server**
* modular design for developers
* can be run as daemon; relaunches itself on error
* open source

### Limitations:

* only tested on Linux

## Architecture

Main thread binds TCP port, accepts connections and distributes them among network threads.

*Network threads* work in non-blocking fashion (using epoll) handling HTTP protocol exchange. There should be no need in using more network threads than the number of CPU cores you have, as every thread is very efficient and can easily handle thousands of concurrent connections. Numbers of network threads is automatically configured but could be limited by `#define NXWEB_MAX_NET_THREADS` directive.

After receiving complete HTTP request network thread finds and invokes application's *URI handler*. The invocation could happen within network thread (should only be used for quick non-blocking handlers) or within worker thread (should be used for slower or blocking handlers).

*Worker threads* are organized in pool. Each thread takes new job from queue, invokes URI handler, signals network thread after handler completes the job. Number of worker threads is dynamically configured depending on the load with limits specified by #define directives.


## API

See [official website](http://nxweb.org) and [source code](https://github.com/yarosla/nxweb). `hello.c` is an example of user module. `nxweb.h` contains function and struct definitions.

## Benchmarks

See [NXWEB benchmarks here](benchmarks.md).

## Building from source

1. Download archive [from here](https://github.com/yarosla/nxweb/releases)
2. Follow INSTALL file notes

## Issues

Please report issues via [issue tracker](https://github.com/yarosla/nxweb/issues).

## Discussions & Announcements

**nxweb**
[Visit this group](http://groups.google.com/group/nxweb?hl=en)

**nxweb-ru** (in Russian)
[Visit this group](http://groups.google.com/group/nxweb-ru?hl=ru)
