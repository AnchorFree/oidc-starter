package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/coreos/go-oidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

type app struct {
	clientID      string
	clientSecret  string
	redirectURI   string
	vaultVersion  string
	webPathPrefix string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool

	client *http.Client

	stateCache gcache.Cache
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	rootCABytes, err := ioutil.ReadFile(filepath.Clean(rootCAs))
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

func cmd() *cobra.Command {
	var (
		a         app
		issuerURL string
		listen    string
		tlsCert   string
		tlsKey    string
		rootCAs   string
		debug     bool
	)
	c := cobra.Command{
		Use:   "example-app",
		Short: "An example OpenID Connect client",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("surplus arguments provided")
			}

			redirectURL, err := url.Parse(a.redirectURI)
			if err != nil {
				return fmt.Errorf("parse redirect-uri: %v", err)
			}

			listenURL, err := url.Parse(listen)
			if err != nil {
				return fmt.Errorf("parse listen address: %v", err)
			}

			// Ensure trailing slash on webPathPrefix
			if a.webPathPrefix != "/" {
				if strings.HasPrefix(a.webPathPrefix, "/") {
					a.webPathPrefix = fmt.Sprintf("%s/", path.Clean(a.webPathPrefix))
				} else {
					return fmt.Errorf("web-path-prefix must start with /")
				}
			}

			// Update Path in listenURL
			listenURL.Path = a.webPathPrefix

			if rootCAs != "" {
				client, err := httpClientForRootCAs(rootCAs)
				if err != nil {
					return err
				}
				a.client = client
			}

			if debug {
				if a.client == nil {
					a.client = &http.Client{
						Transport: debugTransport{http.DefaultTransport},
					}
				} else {
					a.client.Transport = debugTransport{a.client.Transport}
				}
			}

			if a.client == nil {
				a.client = http.DefaultClient
			}

			// TODO(ericchiang): Retry with backoff
			ctx := oidc.ClientContext(context.Background(), a.client)
			provider, err := oidc.NewProvider(ctx, issuerURL)
			if err != nil {
				return fmt.Errorf("failed to query provider %q: %v", issuerURL, err)
			}

			var s struct {
				// What scopes does a provider support?
				//
				// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
				ScopesSupported []string `json:"scopes_supported"`
			}
			if err := provider.Claims(&s); err != nil {
				return fmt.Errorf("failed to parse provider scopes_supported: %v", err)
			}

			if len(s.ScopesSupported) == 0 {
				// scopes_supported is a "RECOMMENDED" discovery claim, not a required
				// one. If missing, assume that the provider follows the spec and has
				// an "offline_access" scope.
				a.offlineAsScope = true
			} else {
				// See if scopes_supported has the "offline_access" scope.
				a.offlineAsScope = func() bool {
					for _, scope := range s.ScopesSupported {
						if scope == oidc.ScopeOfflineAccess {
							return true
						}
					}
					return false
				}()
			}

			a.provider = provider
			a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})

			indexHandler := promhttp.InstrumentHandlerCounter(
				promauto.NewCounterVec(
					prometheus.CounterOpts{
						Name: "oidc_starter_index_requests_total",
						Help: "Total number of index requests by HTTP status code.",
					},
					[]string{"code"},
				),
				http.HandlerFunc(a.handleIndex),
			)
			http.HandleFunc(listenURL.Path, indexHandler)
			log.Printf("Registered index handler at: %s", listenURL.Path)

			callbackHandler := promhttp.InstrumentHandlerCounter(
				promauto.NewCounterVec(
					prometheus.CounterOpts{
						Name: "oidc_starter_callback_response_total",
						Help: "Total number of index response by HTTP status code.",
					},
					[]string{"code"},
				),
				http.HandlerFunc(a.handleCallback),
			)
			http.HandleFunc(redirectURL.Path, callbackHandler)
			log.Printf("Registered callback handler at: %s", redirectURL.Path)

			healthzPattern := path.Join(listenURL.Path, "healthz")
			http.HandleFunc(healthzPattern, a.handleHealthz)
			log.Printf("Registered healthz handler at: %s", healthzPattern)

			fs := http.FileServer(http.Dir("web/static/"))
			staticPattern := path.Join(listenURL.Path, "static") + "/"
			http.Handle(staticPattern, http.StripPrefix(staticPattern, fs))
			log.Printf("Registered static assets handler at: %s", staticPattern)

			http.Handle("/metrics", promhttp.Handler())
			log.Printf("Registered metrics handler at: %s", "/metrics")

			server := &http.Server{
				Addr:              fmt.Sprintf("%s:%s", listenURL.Hostname(), listenURL.Port()),
				ReadHeaderTimeout: 5 * time.Second,
			}

			switch listenURL.Scheme {
			case "http":
				log.Printf("listening on %s", listenURL)
				return server.ListenAndServe()
			case "https":
				log.Printf("listening on %s", listenURL)
				return server.ListenAndServeTLS(tlsCert, tlsKey)
			default:
				return fmt.Errorf("listen address %q is not using http or https", listen)
			}
		},
	}
	c.Flags().StringVar(&a.clientID, "client-id", "example-app", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&a.clientSecret, "client-secret", "ZXhhbXBsZS1hcHAtc2VjcmV0", "OAuth2 client secret of this application.")
	c.Flags().StringVar(&a.redirectURI, "redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	c.Flags().StringVar(&a.webPathPrefix, "web-path-prefix", "/", "A path-prefix from which to serve requests and assets.")
	c.Flags().StringVar(&issuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	c.Flags().StringVar(&listen, "listen", "http://127.0.0.1:5555", "HTTP(S) address to listen at.")
	c.Flags().StringVar(&tlsCert, "tls-cert", "", "X509 cert file to present when serving HTTPS.")
	c.Flags().StringVar(&tlsKey, "tls-key", "", "Private key for the HTTPS cert.")
	c.Flags().StringVar(&rootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
	c.Flags().StringVar(&a.vaultVersion, "vault-version", "1.0.1", "Vault version which provides a download link to the the binary.")
	c.Flags().BoolVar(&debug, "debug", false, "Print all request and responses from the OpenID Connect issuer.")

	a.stateCache = gcache.New(1_000).LRU().Expiration(time.Hour).Build()
	return &c
}

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	var scopes []string
	authCodeURL := ""
	scopes = append(scopes, "groups", "openid", "profile", "email")

	state, err := GenerateRandomString(16)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate state: %v", err), http.StatusInternalServerError)
		return
	}

	err = a.stateCache.Set(state, true)
	if err != nil {
		http.Error(w, fmt.Sprintf("falied to store state: %v", err), http.StatusInternalServerError)
		return
	}

	authCodeURL = a.oauth2Config(scopes).AuthCodeURL(state)
	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (a *app) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, fmt.Sprintf("%v: %v", html.EscapeString(errMsg), html.EscapeString(r.FormValue("error_description"))), http.StatusBadRequest)
			return
		}
		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "no state in request", http.StatusBadRequest)
			return
		}
		_, err = a.stateCache.GetIFPresent(state)
		if err != nil {
			http.Error(w, fmt.Sprintf("unknown state in request: %v", html.EscapeString(state)), http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "no code in request", http.StatusBadRequest)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
	case "POST":
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			http.Error(w, "no refresh_token in request", http.StatusBadRequest)
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %v", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}
	var claims json.RawMessage
	err = idToken.Claims(&claims)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get token claims: %v", err), http.StatusInternalServerError)
		return
	}
	buff := new(bytes.Buffer)
	err = json.Indent(buff, []byte(claims), "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to do json indent: %v", err), http.StatusInternalServerError)
		return
	}
	renderToken(w, a.redirectURI, rawIDToken, buff.String(), a.webPathPrefix, a.vaultVersion)
}

func (a *app) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status": "ok"}`)); err != nil {
		log.Printf("error in response writing: %#v", err)
	}
}
