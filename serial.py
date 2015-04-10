class InvalidSerialNumberOperationError(Exception):
    def __init__(self, msg='Invalid serial number operation.'):
        super(InvalidSerialNumberOperationError, self).__init__(self, msg)

class SerialNumber(object):
    def __init__(self, initial=0, bits=32):
        self.value = initial
        self.bits = bits

        self.modulo = 2 ** bits

    def __add__(self, n):
        if not isinstance(n, SerialNumber):
            n = SerialNumber(n, self.bits)

        if n.value > 2 ** (self.bits - 1) - 1:
            raise InvalidSerialNumberOperationError(
                'Cannot increment a {}-bit serial number by more than {}.'.format(
                    self.bits, 2 ** (self.bits - 1) - 1))

        m = (self.value + n.value) % self.modulo
        return SerialNumber(m, self.bits)

    def __radd__(self, n):
        return self + n

    def __eq__(self, n):
        if not isinstance(n, SerialNumber):
            n = SerialNumber(n, self.bits)

        return self.bits == n.bits and self.value == n.value

    def __neq__(self, n):
        return not self == n

    def __lt__(self, n):
        if not isinstance(n, SerialNumber):
            n = SerialNumber(n, self.bits)

        lv = self.value
        rv = n.value
        return (lv < rv and rv - lv < 2 ** (self.bits - 1)) or \
            (lv > rv and lv - rv > 2 ** (self.bits - 1))

    def __gt__(self, n):
        return not self < n

    def __repr__(self):
        return '<SerialNumber value={} serial_bits={}>'.format(self.value, self.bits)
