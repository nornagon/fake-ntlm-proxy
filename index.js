const express = require('express')
const {
  decode_http_authorization_header,
  decode_message_type,
  parse_ntlm_authenticate,
  fake_ntlm_challenge,
} = require('./ntlm')

async function handle_negotiate(request, response, next, ntlm_message, callback) {
  const challenge = fake_ntlm_challenge();
  response.statusCode = 407;
  response.setHeader('Proxy-Authenticate', 'NTLM ' + challenge.toString('base64'));
  response.end();
}
async function handle_authenticate(request, response, next, ntlm_message, callback) {
  const [user, domain, workstation] = parse_ntlm_authenticate(ntlm_message);

  // if we were going to do proper authentication, here's where it would happen.
  const authenticated = !user.startsWith('unauth')

  var userData = {
    domain,
    user,
    workstation,
    authenticated
  };

  request.ntlm = userData;
  request.connection.ntlm = userData;

  if (!authenticated) {
    return response.sendStatus(403);
  } else {
    return next();
  }
}

const app = express();

app.use((request, response, next) => {
  const auth_headers = request.headers['proxy-authorization'];
  if (!auth_headers) {
    console.log(`Got unauthenticated request: ${request.method} ${request.url}, returning 407`)
    response.statusCode = 407;
    response.setHeader('Proxy-Authenticate', 'NTLM');
    return response.end();
  }

  const ah_data = decode_http_authorization_header(auth_headers);

  if (!ah_data) {
    console.log('Error 400: Proxy-Authorization header not present', request)
    return response.sendStatus(400);
  }

  const message_type = decode_message_type(ah_data[1]);

  switch (message_type) {
    case 1:
      console.log(`Received NEGOTIATE: Proxy-Authorization: ${auth_headers}`)
      return handle_negotiate(request, response, next, ah_data[1]).then(() => {}, function(error) {
        console.error(error)
        return response.sendStatus(500)
      });
    case 3:
      console.log(`Received AUTHENTICATE: Proxy-Authorization: ${auth_headers}`)
      return handle_authenticate(request, response, next, ah_data[1]).then(() => {}, function(error) {
        console.error(error)
        return response.sendStatus(500)
      });
  }
  console.log('Error 400: Unknown authorization message type', request)
  return response.sendStatus(400);
});

app.all('*', function(request, response) {
  response.end(JSON.stringify(request.ntlm));
});

const port = process.env.PORT || 4848
app.listen(port, (e) => {
  console.log(`listening on port ${port}`)
});
