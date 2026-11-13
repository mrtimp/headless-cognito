package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	const (
		username = "alice@example.com"
		password = "correct horse battery staple"
	)
	var submitted url.Values
	var authorizeProvider string
	var requestPaths []string

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestPaths = append(requestPaths, request.Method+" "+request.URL.RequestURI())
		switch request.URL.Path {
		case "/":
			if _, err := request.Cookie("AWSELBAuthSessionCookie-0"); err == nil {
				writer.WriteHeader(http.StatusOK)

				return
			}

			http.Redirect(writer, request, "/first-redirect", http.StatusFound)

		case "/first-redirect":
			authorize := url.URL{Path: "/oauth2/authorize", RawQuery: url.Values{
				"client_id":     {"client"},
				"redirect_uri":  {"https://example.com/oauth2/idpresponse"},
				"response_type": {"code"},
				"scope":         {"openid email profile"},
			}.Encode()}

			http.Redirect(writer, request, authorize.String(), http.StatusFound)

		case "/oauth2/authorize":
			authorizeProvider = request.URL.Query().Get("identity_provider")
			writer.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(writer, `<form method="post" action="/login"><input type="hidden" name="_csrf" value="csrf-value"><input type="hidden" name="_csrf" value="csrf-value"><input type="text" name="username"><input type="password" name="password"><input type="hidden" name="continue" value="yes"></form>`)

		case "/login":
			if err := request.ParseForm(); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			submitted = request.PostForm
			writer.Header().Add("Set-Cookie", "AWSALBAuthNonce=nonce; Path=/")
			writer.Header().Add("Set-Cookie", "AWSELBAuthSessionCookie-0=session-zero; Path=/")
			writer.Header().Add("Set-Cookie", "AWSELBAuthSessionCookie-1=session-one; Path=/")

			http.Redirect(writer, request, "/", http.StatusSeeOther)
		default:
			http.NotFound(writer, request)
		}
	}))

	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:     server.URL,
		Username:     username,
		Password:     password,
		MaxRedirects: 10,
	})

	if err != nil {
		t.Fatal(err)
	}
	client.httpClient.Transport = server.Client().Transport

	result, err := client.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("%v; requests: %v", err, requestPaths)
	}

	if authorizeProvider != DefaultIdentityProvider {
		t.Fatalf("identity provider = %q, want %q", authorizeProvider, DefaultIdentityProvider)
	}

	if submitted.Get("_csrf") != "csrf-value" || submitted.Get("continue") != "yes" {
		t.Fatalf("hidden form values were not preserved: %v", submitted)
	}

	if len(submitted["_csrf"]) != 2 {
		t.Fatalf("duplicate hidden form values were not preserved: %v", submitted)
	}

	if submitted.Get("username") != username || submitted.Get("password") != password {
		t.Fatalf("credentials were not submitted correctly: %v", submitted)
	}

	if result.Cookies[awsALBAuthNonce] != "nonce" || result.Cookies[awsELBAuthSessionZero] != "session-zero" || result.Cookies[awsELBAuthSessionOne] != "session-one" {
		t.Fatalf("unexpected cookies: %v", result.Cookies)
	}
}

func TestWithIdentityProviderReplacesExistingValue(t *testing.T) {
	source, err := url.Parse("https://example.com/oauth2/authorize?client_id=client&identity_provider=EntraID")
	if err != nil {
		t.Fatal(err)
	}

	updated, err := withIdentityProvider(source, "COGNITO")
	if err != nil {
		t.Fatal(err)
	}

	if got := updated.Query().Get("identity_provider"); got != "COGNITO" {
		t.Fatalf("identity provider = %q, want COGNITO", got)
	}

	if got := updated.Query().Get("client_id"); got != "client" {
		t.Fatalf("client id was not preserved: %q", got)
	}
}

func TestParseLoginFormRequiresCredentials(t *testing.T) {
	pageURL, err := url.Parse("https://example.com/login")
	if err != nil {
		t.Fatal(err)
	}

	_, err = parseLoginForm(strings.NewReader(`<form><input type="hidden" name="_csrf" value="csrf"></form>`), pageURL)

	if err == nil {
		t.Fatal("parseLoginForm unexpectedly succeeded")
	}
}

func TestParseLoginFormSkipsNonLoginForms(t *testing.T) {
	pageURL, err := url.Parse("https://example.com/login")
	if err != nil {
		t.Fatal(err)
	}

	form, err := parseLoginForm(strings.NewReader(`<form><input type="hidden" name="language" value="en"></form><form method="post" action="/login"><input type="hidden" name="_csrf" value="csrf"><input type="email" name="username"><input type="password" name="password"></form>`), pageURL)
	if err != nil {
		t.Fatal(err)
	}

	if form.Action.String() != "https://example.com/login" || form.UsernameName != "username" || form.PasswordName != "password" {
		t.Fatalf("unexpected login form: %+v", form)
	}
}
