def parse_error_if_not(cond, buf, pos):
    if cond:
        raise ParseError(buf, pos)

def parse_ident(buf, pos):
    c = buf[pos]
    pos += 1
    parse_error_if_not(c >= 'a' and c <= 'z') or c == '_', buf, pos)
    ident = c
    while True:
        c = buf[pos]
        if (c >= '0' and c <= '9') or (c >= 'a' and c <= 'z') or c == '_':
            pos += 1
            ident += c
        else:
            break
    return ident, pos

def parse_hex_digit(buf, pos):
    d = buf[pos]
    pos += 1
    if d >= '0' and d <= '9':
        return ord(d) - ord('0')
    parse_error_if_not(d >= 'a' and d <= 'f', buf, pos)
    return ord(d) - ord('a') + 10

_escapes = { 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t' }

def parse_string(buf, pos, closing='"', triple=False):
    start_loc = pos
    string = ''
    while True:
        c = buf[pos]
        pos += 1
        if not triple:
            parse_error_if_not(c <> "\n", buf, start_loc)
        if c == closing:  # ..."??
            if not triple:
                break
            if buf[pos] == closing:
                pos += 1
                if buf[pos] == closing:
                    pos += 1
                    break
                else:  # ...""X
                    string += closing + closing
                    continue
        if c != '\\':
            string += c
            continue
        c = buf[pos]
        pos += 1
        parse_error_if_not(c <> "\n", buf, start_loc)
        if c == 'u':
            a, pos = parse_hex_digit(buf, pos)
            b, pos = parse_hex_digit(buf, pos)
            c, pos = parse_hex_digit(buf, pos)
            d, pos = parse_hex_digit(buf, pos)
            string += unichr(a * 16 * 256 + b * 256 + c * 16 + d)
        elif c in _escapes:
            string += _escapes[c]
        else:
            string += c
    return string, pos



    if c in ('-','+'):
        #print('@-/+')
        if reader.exhausted():
            return _mk_symbol(c, c_loc)
        sign = c
        c = reader.next()
    else:
        sign = ''
    if c == '0':
        #print('@0')
        if reader.exhausted():
            return mk_number(sign + '0')
        c = reader.next()
        if c == 'x':
            return mk_number(sign + '0x' + parse_hex_number(reader))
        if c >= '0' and '9' >= c:
            return mk_number(sign + '0' + c + _parse_number(reader))
        if c == '.':
            return mk_number(sign + '0.' + _parse_frac(reader))  # normalize numbers like .5
        reader.push_back(c)
        return mk_number(sign + '0')
    if c >= '1' and '9' >= c:
        #print('@1..9')
        return mk_number(sign + c + _parse_number(reader))
    if c == '.':
        #print('@.')
        c = reader.next()
        if c >= '0' and '9' >= c:
            return mk_number(sign + '0.' + c + _parse_frac(reader))  # normalize numbers like .5
        return _mk_symbol(sign + '.' + c + _parse_symbol(reader), c_loc)
    if sign:
        #print('@-/+(2)')
        reader.push_back(c)
        return _mk_symbol(sign + _parse_symbol(reader), c_loc)

def _parse_number(reader):
    number = ''
    while not reader.exhausted():
        c = reader.next()
        if c == '.':
            return number + '.' + _parse_frac(reader)
        if not (c >= '0' and '9' >= c) and c != '_':
            assert not (c >= 'a' and 'z' >= c) and not (c >= 'A' and 'Z' >= c), repr(c)
            reader.push_back(c)
            break
        number += c
    return number

def parse_hex_number(reader):
    number = ''
    while not reader.exhausted():
        c = reader.next()
        if not (c >= '0' and '9' >= c) and not (c >= 'a' and 'f' >= c) and c != '_':
            assert not (c >= 'a' and 'z' >= c) and not (c >= 'A' and 'Z' >= c)
            reader.push_back(c)
            break
        number += c
    assert number, repr(number) + repr(reader.loc())
    return number

def _parse_frac(reader):
    frac = ''
    while not reader.exhausted():
        c = reader.next()
        if not (c >= '0' and '9' >= c) and c != '_':
            reader.push_back(c)
            break
        frac += c
    return frac if frac else '0'  # normalize numbers like 5.
