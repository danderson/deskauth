package deskauth

import (
	"context"
	"log"

	"golang.org/x/oauth2"
)

// Simplest usage, with default storage and printing of the auth URL
// to stdout.
func Example(oauthConfig *oauth2.Config) {
	auth := Auth{
		Config:  oauthConfig,
		Storage: DefaultFileStore("myapp"),
		ShowURL: PrintURL,
	}

	tokens, err := auth.TokenSource(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	// Some API clients take a TokenSource directly. But, you need
	// an HTTP client to make API calls? Here you go.
	client := HTTP(context.Background(), tokens)
	client.Get("http://example.com/my/api/call/with/auth")
}
