package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	DefaultIdentityProvider = "COGNITO"
	DefaultMaxRedirects     = 20

	awsALBAuthNonce       = "AWSALBAuthNonce"
	awsELBAuthSessionZero = "AWSELBAuthSessionCookie-0"
	awsELBAuthSessionOne  = "AWSELBAuthSessionCookie-1"
)

var requiredCookieNames = []string{
	awsALBAuthNonce,
	awsELBAuthSessionZero,
	awsELBAuthSessionOne,
}

type Config struct {
	Endpoint         string
	Username         string
	Password         string
	IdentityProvider string
	MaxRedirects     int
	Logger           logrus.FieldLogger
}

type Result struct {
	Cookies  map[string]string `json:"cookies"`
	FinalURL string            `json:"final_url"`
}

type Client struct {
	httpClient *http.Client
	config     Config
}

func NewClient(config Config) (*Client, error) {
	if config.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if config.Username == "" {
		return nil, errors.New("username is required")
	}
	if config.Password == "" {
		return nil, errors.New("password is required")
	}
	if config.IdentityProvider == "" {
		config.IdentityProvider = DefaultIdentityProvider
	}
	if config.MaxRedirects <= 0 {
		config.MaxRedirects = DefaultMaxRedirects
	}

	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}

	if endpoint.Scheme != "https" && endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "localhost" {
		return nil, errors.New("endpoint must use HTTPS")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) Authenticate(ctx context.Context) (Result, error) {
	endpoint, err := url.Parse(c.config.Endpoint)
	if err != nil {
		return Result{}, fmt.Errorf("parse endpoint: %w", err)
	}

	authorizeURL, err := c.findAuthorizeURL(ctx, endpoint)
	if err != nil {
		return Result{}, err
	}

	authorizeURL, err = withIdentityProvider(authorizeURL, c.config.IdentityProvider)
	if err != nil {
		return Result{}, fmt.Errorf("set identity provider: %w", err)
	}

	form, err := c.findLoginForm(ctx, authorizeURL)
	if err != nil {
		return Result{}, err
	}

	finalResponse, err := c.submitForm(ctx, form)
	if err != nil {
		return Result{}, err
	}

	defer finalResponse.Body.Close()

	if finalResponse.StatusCode != http.StatusOK {
		if hint := responseHint(finalResponse); hint != "" {
			return Result{}, fmt.Errorf("authentication flow ended with HTTP %d at %s: %s", finalResponse.StatusCode, redactURL(finalResponse.Request.URL), hint)
		}

		return Result{}, fmt.Errorf("authentication flow ended with HTTP %d at %s", finalResponse.StatusCode, redactURL(finalResponse.Request.URL))
	}

	if !sameEndpoint(finalResponse.Request.URL, endpoint) {
		return Result{}, fmt.Errorf("authentication flow ended at %s instead of %s", finalResponse.Request.URL, endpoint)
	}

	cookies := make(map[string]string, len(requiredCookieNames))
	for _, cookie := range c.httpClient.Jar.Cookies(endpoint) {
		for _, requiredName := range requiredCookieNames {
			if cookie.Name == requiredName {
				cookies[cookie.Name] = cookie.Value
			}
		}
	}
	for _, requiredName := range requiredCookieNames {
		if cookies[requiredName] == "" {
			return Result{}, fmt.Errorf("authentication succeeded but cookie %q was not returned", requiredName)
		}
	}

	return Result{Cookies: cookies, FinalURL: finalResponse.Request.URL.String()}, nil
}

func (c *Client) findAuthorizeURL(ctx context.Context, endpoint *url.URL) (*url.URL, error) {
	current := endpoint
	for redirect := 0; redirect <= c.config.MaxRedirects; redirect++ {
		response, err := c.do(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, fmt.Errorf("request protected endpoint: %w", err)
		}

		if response.Body != nil {
			response.Body.Close()
		}

		if !isRedirect(response.StatusCode) {
			return nil, fmt.Errorf("protected endpoint returned HTTP %d instead of a Cognito redirect", response.StatusCode)
		}

		location, err := redirectURL(current, response)
		if err != nil {
			return nil, err
		}

		if location.Path == "/oauth2/authorize" && location.Query().Get("client_id") != "" {
			return location, nil
		}

		current = location
	}

	return nil, fmt.Errorf("authorization redirect limit exceeded (%d)", c.config.MaxRedirects)
}

func (c *Client) findLoginForm(ctx context.Context, authorizeURL *url.URL) (loginForm, error) {
	current := authorizeURL
	for redirect := 0; redirect <= c.config.MaxRedirects; redirect++ {
		response, err := c.do(ctx, http.MethodGet, current, nil)
		if err != nil {
			return loginForm{}, fmt.Errorf("request Cognito login page: %w", err)
		}

		if isRedirect(response.StatusCode) {
			location, redirectErr := redirectURL(current, response)
			response.Body.Close()

			if redirectErr != nil {
				return loginForm{}, redirectErr
			}
			current = location

			continue
		}

		if response.StatusCode != http.StatusOK {
			response.Body.Close()

			return loginForm{}, fmt.Errorf("Cognito login page returned HTTP %d", response.StatusCode)
		}

		form, parseErr := parseLoginForm(response.Body, current)
		response.Body.Close()
		if parseErr != nil {
			return loginForm{}, parseErr
		}

		return form, nil
	}

	return loginForm{}, fmt.Errorf("login page redirect limit exceeded (%d)", c.config.MaxRedirects)
}

func (c *Client) submitForm(ctx context.Context, form loginForm) (*http.Response, error) {
	values := form.Values
	values.Set(form.UsernameName, c.config.Username)
	values.Set(form.PasswordName, c.config.Password)
	payload := values.Encode()

	if c.config.Logger != nil {
		c.config.Logger.WithField("fields", formFieldSummary(values)).Debug("Cognito form submission")
	}

	current := form.Action
	method := form.Method

	for redirect := 0; redirect <= c.config.MaxRedirects; redirect++ {
		var body io.Reader

		if method == http.MethodPost {
			body = strings.NewReader(payload)
		}

		response, err := c.do(ctx, method, current, body)
		if err != nil {
			return nil, fmt.Errorf("submit Cognito login form: %w", err)
		}

		if !isRedirect(response.StatusCode) {
			return response, nil
		}

		location, redirectErr := redirectURL(current, response)

		response.Body.Close()

		if redirectErr != nil {
			return nil, redirectErr
		}

		if response.StatusCode != http.StatusTemporaryRedirect && response.StatusCode != http.StatusPermanentRedirect {
			method = http.MethodGet
		}

		current = location
	}

	return nil, fmt.Errorf("post-login redirect limit exceeded (%d)", c.config.MaxRedirects)
}

func (c *Client) do(ctx context.Context, method string, target *url.URL, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)

	if err != nil {
		return nil, err
	}

	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; headless-cognito/1.0)")

	if c.config.Logger != nil {
		c.config.Logger.WithFields(logrus.Fields{
			"method": request.Method,
			"url":    redactURL(request.URL),
		}).Debug("HTTP request")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	c.logRequest(request, response)

	return response, nil
}

func (c *Client) logRequest(request *http.Request, response *http.Response) {
	if c.config.Logger == nil {
		return
	}

	fields := logrus.Fields{
		"method": request.Method,
		"url":    redactURL(request.URL),
		"status": response.StatusCode,
	}

	if location := response.Header.Get("Location"); location != "" {
		fields["location"] = redactLocation(request.URL, location)
	}

	if setCookies := response.Header.Values("Set-Cookie"); len(setCookies) > 0 {
		fields["set_cookie_names"] = cookieNames(setCookies)
	}

	c.config.Logger.WithFields(fields).Debug("HTTP response")
}

func formFieldSummary(values url.Values) []string {
	fields := make([]string, 0, len(values))
	for name, fieldValues := range values {
		lengths := make([]string, len(fieldValues))
		for index, value := range fieldValues {
			lengths[index] = fmt.Sprintf("%d", len(value))
		}

		fields = append(fields, fmt.Sprintf("%s[%s]", name, strings.Join(lengths, ",")))
	}

	sort.Strings(fields)

	return fields
}

func cookieNames(setCookies []string) []string {
	names := make([]string, 0, len(setCookies))
	for _, setCookie := range setCookies {
		if name := strings.SplitN(setCookie, "=", 2)[0]; name != "" {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return names
}

func responseHint(response *http.Response) string {
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return ""
	}

	text := strings.ToLower(string(body))

	for _, phrase := range []string{
		"incorrect username or password",
		"user does not exist",
		"not authorized",
		"invalid password",
	} {
		if strings.Contains(text, phrase) {
			return phrase
		}
	}

	return ""
}

func redactURL(source *url.URL) string {
	copyURL := *source
	query := copyURL.Query()

	for _, key := range []string{"code", "state", "id_token", "access_token", "client_secret", "password"} {
		if query.Has(key) {
			query.Set(key, "<redacted>")
		}
	}

	copyURL.RawQuery = query.Encode()

	return copyURL.String()
}

func redactLocation(base *url.URL, location string) string {
	resolved, err := base.Parse(location)
	if err != nil {
		return "<invalid redirect location>"
	}

	return redactURL(resolved)
}

func withIdentityProvider(source *url.URL, provider string) (*url.URL, error) {
	copyURL := *source
	query := copyURL.Query()
	query.Set("identity_provider", provider)
	copyURL.RawQuery = query.Encode()

	return &copyURL, nil
}

func redirectURL(current *url.URL, response *http.Response) (*url.URL, error) {
	location := response.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("HTTP %d response did not include a Location header", response.StatusCode)
	}

	resolved, err := current.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse redirect location: %w", err)
	}

	return resolved, nil
}

func isRedirect(status int) bool {
	return status >= http.StatusMultipleChoices && status < http.StatusBadRequest
}

func sameEndpoint(actual, expected *url.URL) bool {
	actualPath := actual.Path
	if actualPath == "" {
		actualPath = "/"
	}

	expectedPath := expected.Path
	if expectedPath == "" {
		expectedPath = "/"
	}

	return actual.Scheme == expected.Scheme && actual.Host == expected.Host && actualPath == expectedPath
}
