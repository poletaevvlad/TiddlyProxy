# TiddlyProxy: *TiddlyWiki Authentication Proxy*

*A reverse proxy that limits access to TiddlyWiki for unauthenticated users.*

![Testing](https://github.com/poletaevvlad/TiddlyProxy/workflows/Testing/badge.svg)

TiddlyWiki node.js server supports HTTP-based authentication. This approach has
several disadvantages: username and password entry may be inconvenient on some
user agents, and the browser may close the session before it is desirable.
Also, the fact that the user must supply their password as plain text either in
the server's command-line arguments or in a text file raises some security
concerns.

TiddlyWiki supports user authentication via an external proxy. Such proxy
intercepts unauthorized requests to the server and requires the user to enter
their credentials. TiddlyProxy is such proxy written in Rust.

## Installation

To compile and install this software, clone this repository and build it using
`cargo build --release`. Note that you will need Rust and it's build tools
installed. All dependencies should be installed automatically by `cargo`.
Please refer to the [installation guide on the Rust Programming Language website](https://www.rust-lang.org/tools/install) for guidance on installing build tools.

## Usage

Before starting TiddlyProxy ensure that TiddlyWiki node.js server (or any
other server that supports the Web Server API) is up and running, is accessible
from the machine where you are about to start TiddlyProxy, and basic
authentication is disabled.

TiddlyProxy command-line utility supports several subcommands. The most
important one is `run`. To run the server issue the command with the following
syntax:

```
tiddlyproxy run --wiki_url <url> --secret <secret> --users <user's credentials>
                [--host <ip address>] [--port <port>]
```

The server requires several arguments:

### `--secret <secret>`

**Required.** A `secret` is a string of 32 randomly generated hex-encoded
bytes. This string is used to sign the access tokens and must not be made
public.

To generate the `secret` using cryptographically-secure pseudo-random number
generation algorithm issue `tiddlyproxy gensecret` command. Changing the secret
and restarting the server has an effect of invalidating any access tokens and
therefore terminating any active auth sessions.

### `--wiki_url <url>`

**Required** Hostname and port of the running TiddlyWiki web server instance.
The value must follow one of the following formats:

* `<hots>[:port]`
* `http://<host>[:port]/[path]`

### `--users <users' credentials>`

TiddlyProxy supports authentication by multiple users. Each user's
credentials are encoded in a string with the following format:

```
<username>:<salt>:<sha256(salt + ":" + password)>
```

Where `salt` is a random string no shorter than five characters, and the third
component is the hex-encoded SHA256 digest of the salted password. The usage of
salt prevents access if credentials are leaked.

To generate the credentials string issue the following command:

```
tiddlyproxy mkuser [--user <user>]
```

If you intend the wiki to be accessed by multiple users generate credentials
for all of them and pass to the server separated by a semicolon:

```finn:guksjL9:A86F8F[...]77FFEA;jake:uruNrlw:5D3335[...]B75947```

If only one person accesses the TiddlyWiki server, their username can be
omitted. In that case, the login form will contain only the password field.

### `--host` and `--port`

An IP-address (IPv4 or IPv6) and the port number respectively on which the
server will run.

## Plugin

TiddleProxy comes with a plugin that adds a logout button above the toolbar.
To install it, go to
[$:/plugins/poletaevvlad/proxy-logout](https://poletaevvlad.github.io/TiddlyProxy/#%24%3A%2Fplugins%2Fpoletaevvlad%2Fproxy-logout)
and drag the link into the window containing your wiki. See
[details](https://tiddlywiki.com/static/Manually%2520installing%2520a%2520plugin.html)
on manually installing plugins.

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
