"""Bounded LDAP BER codec for an anonymous rootDSE-over-UDP lab fixture.

Implements a deliberately small subset of RFC 4511 messages, using the
SearchResultEntry + SearchResultDone framing described by MS-ADTS for UDP.
This is not a directory server, AD domain controller, or Netlogon responder.
"""

MAX_DATAGRAM = 4096
ROOT_ATTRIBUTES = {
    'objectClass': ['top'],
    'supportedLDAPVersion': ['3'],
    'namingContexts': ['dc=lab,dc=local'],
}
QUERY_ATTRIBUTES = ('supportedLDAPVersion', 'namingContexts')


def tlv(tag, value):
    size = len(value)
    if size > MAX_DATAGRAM:
        raise ValueError('BER value too large')
    length = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, 'big')
    return bytes([tag]) + length + value


def number(value, tag=0x02):
    if not 0 <= value <= 2147483647:
        raise ValueError('LDAP integer out of range')
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    return tlv(tag, (b'\0' if raw[0] & 0x80 else b'') + raw)


def octets(value):
    return tlv(0x04, value.encode('utf-8'))


class Reader:
    def __init__(self, data):
        if len(data) > MAX_DATAGRAM:
            raise ValueError('LDAP datagram too large')
        self.data, self.pos = data, 0

    def take(self, expected=None):
        if self.pos + 2 > len(self.data):
            raise ValueError('Truncated BER header')
        tag, length = self.data[self.pos:self.pos + 2]
        self.pos += 2
        if tag & 0x1f == 0x1f:
            raise ValueError('High-tag BER unsupported')
        if length & 0x80:
            count = length & 0x7f
            if not 1 <= count <= 4 or self.pos + count > len(self.data):
                raise ValueError('Invalid definite BER length')
            length = int.from_bytes(self.data[self.pos:self.pos + count], 'big')
            self.pos += count
        if length > MAX_DATAGRAM or self.pos + length > len(self.data):
            raise ValueError('Truncated or oversized BER value')
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        if expected is not None and tag != expected:
            raise ValueError('Unexpected BER tag: %02x' % tag)
        return tag, value

    def integer(self, tag=0x02):
        raw = self.take(tag)[1]
        if not 1 <= len(raw) <= 4 or raw[0] & 0x80:
            raise ValueError('Invalid LDAP integer')
        return int.from_bytes(raw, 'big')

    def text(self):
        return self.take(0x04)[1].decode('utf-8')

    def done(self):
        if self.pos != len(self.data):
            raise ValueError('Unexpected trailing BER fields')

    def more(self):
        return self.pos < len(self.data)


def message(message_id, operation):
    if not 1 <= message_id <= 2147483647:
        raise ValueError('Expected positive LDAP message ID')
    return tlv(0x30, number(message_id) + operation)


def read_message(reader):
    envelope = Reader(reader.take(0x30)[1])
    message_id = envelope.integer()
    if not 1 <= message_id <= 2147483647:
        raise ValueError('Expected positive LDAP message ID')
    tag, payload = envelope.take()
    envelope.done()
    return message_id, tag, Reader(payload)


def search_request(message_id):
    fields = (octets('') + number(0, 0x0a) + number(0, 0x0a)
              + number(1) + number(1) + tlv(0x01, b'\0')
              + tlv(0x87, b'objectClass')
              + tlv(0x30, b''.join(octets(name) for name in QUERY_ATTRIBUTES)))
    return message(message_id, tlv(0x63, fields))


def parse_search_request(data):
    reader = Reader(data)
    message_id, tag, fields = read_message(reader)
    reader.done()
    if tag != 0x63 or fields.text() != '':
        raise ValueError('Only rootDSE SearchRequest is supported')
    if fields.integer(0x0a) != 0 or fields.integer(0x0a) != 0:
        raise ValueError('Only baseObject/no-dereference is supported')
    if fields.integer() not in (0, 1) or fields.integer() not in (0, 1):
        raise ValueError('Unsupported search limits')
    if fields.take(0x01)[1] != b'\0' or fields.take(0x87)[1] != b'objectClass':
        raise ValueError('Only values and (objectClass=*) are supported')
    attributes = Reader(fields.take(0x30)[1])
    names = []
    while attributes.more():
        name = attributes.text()
        if name not in ROOT_ATTRIBUTES or name in names:
            raise ValueError('Unsupported or duplicate rootDSE attribute')
        names.append(name)
    fields.done()
    if not names:
        names = list(ROOT_ATTRIBUTES)
    return message_id, names


def search_response(message_id, names):
    attributes = b''
    for name in names:
        values = b''.join(octets(value) for value in ROOT_ATTRIBUTES[name])
        attributes += tlv(0x30, octets(name) + tlv(0x31, values))
    entry = message(message_id, tlv(0x64, octets('') + tlv(0x30, attributes)))
    done = message(message_id, tlv(0x65, number(0, 0x0a) + octets('') + octets('')))
    return entry + done


def parse_search_response(data, expected_id):
    reader = Reader(data)
    message_id, tag, entry = read_message(reader)
    if message_id != expected_id or tag != 0x64 or entry.text() != '':
        raise ValueError('Expected matching rootDSE SearchResultEntry')
    attributes, result = Reader(entry.take(0x30)[1]), {}
    entry.done()
    while attributes.more():
        attribute = Reader(attributes.take(0x30)[1])
        name = attribute.text()
        values = Reader(attribute.take(0x31)[1])
        attribute.done()
        if name in result:
            raise ValueError('Duplicate response attribute')
        result[name] = []
        while values.more():
            result[name].append(values.text())
    message_id, tag, done = read_message(reader)
    if message_id != expected_id or tag != 0x65 or done.integer(0x0a) != 0:
        raise ValueError('Expected matching successful SearchResultDone')
    if done.text() != '' or done.text() != '':
        raise ValueError('Unexpected search result details')
    done.done()
    reader.done()
    expected = {name: ROOT_ATTRIBUTES[name] for name in QUERY_ATTRIBUTES}
    if result != expected:
        raise ValueError('RootDSE attributes differ from the lab fixture')
    return result
