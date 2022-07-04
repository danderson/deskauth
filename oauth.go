// Package deskauth provides a simplified API to do OAuth interactive
// login flows in desktop programs (as opposed to webapps).
package deskauth

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"
)

// Storage stores and retrieves cached OAuth tokens.
type Storage interface {
	Read() (*oauth2.Token, error)
	Write(*oauth2.Token) error
}

// Auth produces OAuth tokens from a local cache or by running an
// interactive OAuth exchange.
type Auth struct {
	// Config is the OAuth provider configuration to use for
	// authentication and ongoing token management. See the
	// subpackages of golang.org/x/oauth2 for provider configurations.
	Config *oauth2.Config
	// Storage saves tokens from interactive authentications for
	// future use. If nil, interactive auth will be required for every
	// TokenSource call.
	Storage Storage
	// ShowURL is a function that displays the URL for interactive
	// authentication. If nil, interactive auth is disabled and
	// Storage must be able to provide a stored token.
	ShowURL func(context.Context, string) error
}

// PrintURL is an Auth.ShowURL function that prints the authentication
// URL to standard output.
func PrintURL(ctx context.Context, url string) error {
	fmt.Printf("To authenticate, please open %v in your browser.\n", url)
	return nil
}

// FileStore returns a Storage that stores tokens at filename. Any
// missing parent directories are created with mode 0700.
func FileStore(filename string) Storage {
	return fileStore(filename)
}

// DefaultFileStore returns a Storage that stores tokens in a
// reasonable long-term storage location given the current
// environment.
//
// DefaultFileStore prefers to store state in systemd's
// $STATE_DIRECTORY if defined. Otherwise, a subdirectory called
// appName within the OS-dependent user configuration directory is
// used. If that is also undefined, state is stored in appName.json in
// the current working directory.
func DefaultFileStore(appName string) Storage {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return fileStore(filepath.Join(d, "oauth.json"))
	}
	if d, err := os.UserConfigDir(); err == nil {
		return fileStore(filepath.Join(d, appName, "oauth.json"))
	}
	return fileStore(appName + ".json")
}

type fileStore string

func (f fileStore) Read() (*oauth2.Token, error) {
	bs, err := os.ReadFile(string(f))
	if errors.Is(err, fs.ErrNotExist) {
		// No cached file yet. Not an error, just no token.
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var ret oauth2.Token
	if err := json.Unmarshal(bs, &ret); err != nil {
		return nil, fmt.Errorf("unmarshaling auth config: %w", err)
	}
	return &ret, nil
}

func (f fileStore) Write(tok *oauth2.Token) error {
	bs, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("marshaling OAuth token: %w", err)
	}

	dir := filepath.Dir(string(f))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating parent dirs for %q: %w", f, err)
	}

	if err := os.WriteFile(string(f), bs, 0600); err != nil {
		return fmt.Errorf("saving OAuth token: %w", err)
	}

	return nil
}

// TokenSource returns an oauth2.TokenSource, doing the interactive
// authentication flow as needed.
func (a *Auth) TokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	tok, err := a.tokenFromStorage(ctx)
	if err != nil {
		return nil, err
	}
	if tok != nil {
		return a.Config.TokenSource(ctx, tok), nil
	}
	tok, err = a.tokenInteractive(ctx)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, fmt.Errorf("interactive auth returned no error but also no token")
	}
	return a.Config.TokenSource(ctx, tok), nil
}

// HTTP returns an http.Client that adds OAuth bearer token
// authentication to outgoing requests.
func HTTP(ctx context.Context, src oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(ctx, src)
}

func (a *Auth) tokenFromStorage(ctx context.Context) (*oauth2.Token, error) {
	if a.Storage == nil {
		return nil, nil
	}

	return a.Storage.Read()
}

func (a *Auth) tokenInteractive(ctx context.Context) (*oauth2.Token, error) {
	if a.ShowURL == nil {
		return nil, errors.New("interactive authentication is unavailable")
	}

	path := "/" + randhex()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("creating socket for local HTTP server: %w", err)
	}
	defer ln.Close()

	cfg := a.Config
	cfg.RedirectURL = fmt.Sprintf("http://%s%s", ln.Addr(), path)

	state := randhex()
	startURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)

	type resp struct {
		code string
		err  error
	}
	ch := make(chan resp, 1)

	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			st := r.URL.Query().Get("state")
			if st == "" {
				http.Redirect(w, r, startURL, http.StatusFound)
				return
			} else if st != state {
				http.Error(w, "bad state", http.StatusPreconditionFailed)
				return
			}

			var rsp resp
			if err := r.URL.Query().Get("error"); err != "" {
				rsp.err = fmt.Errorf("OAuth server returned error: %s", err)
			} else if c := r.URL.Query().Get("code"); c != "" {
				rsp.code = c
			} else {
				rsp.err = errors.New("OAuth server returned invalid response, no code or error")
			}
			select {
			case ch <- rsp:
			default:
			}

			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html><body><h2>Authentication successful, you may close this window</h2></body></html>")
		}),
	}
	go func() {
		err := s.Serve(ln)
		select {
		case ch <- resp{err: err}:
		default:
		}
	}()
	defer s.Shutdown(ctx)

	if err := a.ShowURL(ctx, cfg.RedirectURL); err != nil {
		return nil, err
	}

	select {
	case rsp := <-ch:
		if rsp.err != nil {
			return nil, rsp.err
		}
		return cfg.Exchange(ctx, rsp.code, oauth2.AccessTypeOffline)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func randhex() string {
	var bs [8]byte
	if _, err := io.ReadFull(crand.Reader, bs[:]); err != nil {
		panic("ran out of random")
	}
	return hex.EncodeToString(bs[:])
}
