# Headless Application Load Balancer Cognito

`headless-cognito` authenticates against an application protected by an AWS Application Load Balancer Cognito action and 
stores the ALB authentication cookies as JSON that can be exposed safely for reuse within GitHub Actions workflow steps.

## Usage

```sh
headless-cognito auth \
  --endpoint https://test.unfuddle.nz
```

The identity provider defaults to `COGNITO`. Use `--identity-provider EntraID` to select the federated EntraID provider instead.

The username can also be supplied with `--username` (or via `COGNITO_USERNAME`), the password can also be supplied with `--password` (or via `COGNITO_PASSWORD`), but `--password-stdin` avoids exposing it in shell history and process listings.

On success, the command writes JSON containing `AWSALBAuthNonce`, `AWSELBAuthSessionCookie-0`, and `AWSELBAuthSessionCookie-1`.

Write JSON to a protected file for Playwright setup code:

```sh
./headless-cognito auth \
  --endpoint https://test.unfuddle.nz
  --output-file /tmp/cognito-auth.json
```

For GitHub Actions, export a previously generated JSON file directly to `GITHUB_ENV` without using `jq`:

```sh
./headless-cognito export-env \
  --input-file /tmp/cognito-auth.json
```

`export-env` validates that the JSON file exists and contains `AWSALBAuthNonce`, `AWSELBAuthSessionCookie-0`, and `AWSELBAuthSessionCookie-1`. It creates `AWSALB_AUTH_NONCE`, `AWSELB_AUTH_SESSION_COOKIE_0`, and `AWSELB_AUTH_SESSION_COOKIE_1` for subsequent steps and emits GitHub masking commands for their values.

These cookies are bearer credentials. Protect command output and do not commit or persist it in build logs.

## Development

```sh
make test
make vet
make build
```
