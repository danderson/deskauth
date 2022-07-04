# DeskAuth

A small Go library to simplify the "desktop app OAuth" flow that is
required to call most APIs with your data these days.

## Usage

Go to your cloud thing of choice and create an OAuth app. You need to
make http://localhost a valid "redirect URL". Some providers ask you
to list redirect URLs directly, others (like Google) set that
automatically if you tell them you're making a desktop app. You should
get back a client ID and secret, and possibly also some OAuth endpoint
URLs that are used for various parts of the auth flow.

Using those things, build yourself an
[oauth2.Config](https://pkg.go.dev/golang.org/x/oauth2#Config). There
are subpackages of
[golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2#section-directories)
that might help you find the right OAuth endpoints, if your provider
of choice didn't give them to you. You'll also need to fill out the
requested scopes, which specify what data you'll have access to after
the auth exchange. These are provider-dependent, so look up your
provider's documentation.

Once you have the client config, the simplest use of DeskAuth is:

```go
auth := deskauth.Auth{
  Config: yourOAuthConfig,
  Storage: deskauth.DefaultFileStore("myappname"),
  ShowURL: deskauth.PrintURL,
}

tokens, err := auth.TokenSource(context.Background())
if err != nil {
  log.Fatal(err)
}

// Some API clients take a TokenSource directly. But, you need
// an HTTP client to make API calls? Here you go.
client := deskauth.HTTP(context.Background(), tokens)
```

## Why

OAuth is fairly hostile to things that aren't webapps. In the older
days, the desktop app would pop a browser window, run you through the
auth flow, and eventually you'd get back a code to paste into the
desktop app.

Clouds are increasingly breaking this flow, in favor of a
"webapp-only" style of flow: your desktop app has to spin up a web
server on localhost, and trigger a "web-ish" OAuth flow for that web
server. Eventually, that localhost server will get a callback from the
user's browser, containing the code you need to finalize the auth flow
and get your bearer tokens.

This package just MCs that whole flow: when you call
`auth.TokenSource(...)`, deskauth spins up a temporary webserver on
localhost, constructs the appropriate OAuth URLs to trigger the flow,
and tells you what starting URL you should visit in a browser. When
the flow finishes, the temporary webserver receives the auth code and
finalizes token creation for you.

Most of these OAuth providers provide a "refresh token", which lets
you get new API tokens non-interactively even after the original one
expires (usually a few hours/days). So, once the initial auth exchange
is done, deskauth can optionally cache the tokens it got to persistent
storage. That way, subsequent runs of your program won't need to do an
interactive authentication, they can just pull the cached credentials
from disk and motor right on.

## Licensing

This project is [not open source](/LICENSE) according to the FSF/OSI
definitions, since it restricts permitted uses.

If you'd like to purchase a license with different terms, [contact
me](mailto:dave@natulte.net) to discuss.

## Contributing

This project is not currently open to code contributions, so that I
can easily relicense it later if I so wish. Bug reports are welcome.
