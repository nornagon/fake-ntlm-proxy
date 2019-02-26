
function decode_http_authorization_header(auth) {
  var ah = auth.split(' ');
  if (ah.length === 2) {
    if (ah[0] === 'NTLM') {
      return ['NTLM', Buffer.from(ah[1], 'base64')];
    }
  }
  return false;
}

function decode_message_type(msg) {
  if (msg.toString('utf8', 0, 8) != 'NTLMSSP\0') {
    return new Error('Not a valid NTLM message:', msg.toString('hex'));
  }
  var msg_type = msg.readUInt8(8);
  if (!~[1, 2, 3].indexOf(msg_type)) {
    return new Error('Incorrect NTLM message Type', msg_type);
  }
  return msg_type;
}

function parse_ntlm_authenticate(msg) {
  const NTLMSSP_NEGOTIATE_UNICODE = 0b00000001;
  const DomainNameLen = msg.readUInt16LE(0x1C);
  const DomainNameBufferOffset = msg.readUInt32LE(0x20);
  const DomainName = msg.slice(DomainNameBufferOffset, DomainNameBufferOffset + DomainNameLen);
  const UserNameLen = msg.readUInt16LE(0x24);
  const UserNameBufferOffset = msg.readUInt32LE(0x28);
  const UserName = msg.slice(UserNameBufferOffset, UserNameBufferOffset + UserNameLen);
  const WorkstationLen = msg.readUInt16LE(0x2C);
  const WorkstationBufferOffset = msg.readUInt32LE(0x30);
  const Workstation = msg.slice(WorkstationBufferOffset, WorkstationBufferOffset + WorkstationLen);

  const encoding = (msg.readUInt8(0x3C) & 0b00000001) ? 'utf16le' : undefined;
  return [
    UserName.toString(encoding),
    DomainName.toString(encoding),
    Workstation.toString(encoding)
  ]
}

function fake_ntlm_challenge() {
  const challenge = Buffer.alloc(40);
  let offset = 0;

  offset = challenge.write('NTLMSSP\0', offset, 8, 'ascii');

  // MessageType
  offset = challenge.writeUInt32LE(0x00000002, offset);

  // TargetNameFields
  //   TargetNameLen
  offset = challenge.writeUInt16LE(0x0000, offset);
  //   TargetNameMaxLen
  offset = challenge.writeUInt16LE(0x0000, offset);
  //   TargetNameBufferOffset
  offset = challenge.writeUInt32LE(0x00002800, offset);

  // NegotiateFlags
  offset = challenge.writeUInt32LE(0x00008201, offset);

  // ServerChallenge (8 bytes)
  offset = challenge.write('\x01\x23\x45\x67\x89\xab\xcd\xef', offset, 8, 'ascii')

  // Reserved (8 bytes)
  //offset += challenge.writeUInt32LE(0x00000000, offset);
  //offset += challenge.writeUInt32LE(0x00000000, offset);
  
  return challenge;
};

module.exports = {
  decode_http_authorization_header,
  decode_message_type,
  parse_ntlm_authenticate,
  fake_ntlm_challenge,
}
