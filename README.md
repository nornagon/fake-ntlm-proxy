# fake-ntlm-proxy

fake-ntlm-proxy is an
[NTLM](https://docs.microsoft.com/en-us/windows/desktop/secauthn/microsoft-ntlm)
proxy for testing purposes. It does not actually proxy any data, nor
authenticate users. It does, however, send the appropriate `Proxy-Authenticate`
headers and statuses.

### Usage

```
$ PORT=4848 npx fake-ntlm-proxy
```
