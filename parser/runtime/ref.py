from ..runtime.types import *
from ..runtime.symbol import *
from lib.unique import unique
from lib.data.list_utils import pairwise
from lib.data.dict_utils import reverse_dict
import lib.strings.char_classes as uc

def char_set(string):
    return set(list(string))

def _mk_symbol(name, loc):
    return mk_symbol(name, { "srcloc": loc })


spaces = char_set(' \t\r\n')
parens = set('()[]{}')
singletons = set(',') # [!] ???
symbolstops = parens | spaces | singletons
macros = { "'": 'boot.quote', '`': 'boot.syntax_quote', '~': { '': 'boot.unquote', '@': 'boot.unquote_splicing' } }

def parse_simple_macro(reader, rule, loc):
    while isinstance(rule, dict):
        c = reader.next()
        if c in rule:
            rule = rule[c]
        else:
            reader.push_back(c)
            rule = rule['']
            break
    assert isinstance(rule, (str,unicode))
    skip_spaces(reader)
    return mk_term(_mk_symbol(rule, loc), parse_sexp(reader))




def skip_spaces(reader):
    #print('enter skip spaces')
    while True:
        while not reader.exhausted() and reader._peek() in spaces:
            reader.next()
        if reader._peek() != ';':
            break
        c = reader.next()
        if reader._peek() != ';':
            reader.push_back(c)
            break
        while reader._peek() != '\n' and not reader.exhausted():
            reader.next()
        if not reader.exhausted():
            reader.next()
    assert reader._peek() not in " \r\n\t"
    #print('exit skip spaces')

def parse_reader_macro(reader, loc):
    c = reader.next()
    if c == '{':
        return mk_term(_mk_symbol('__hash_braces__', loc), *parse_list(reader, '}'))
    if c == '(':
        return mk_term(_mk_symbol('xinx.lambda', loc), *parse_list(reader, ')'))  # [!] __hash_parens__??
    if c == '_':
        _parse_sexp(reader)
        return None
    if c == '"':
        return mk_term(_mk_symbol("__regex__", loc), parse_string(reader, '"'))
    if c >= 'a' and c <= 'z':
        tag = parse_ident(c, reader)
        return mk_term(_mk_symbol("__tagged__", loc), _mk_symbol(tag, loc), parse_sexp(reader))
    assert False, repr(reader.loc()) + repr(c)

def _parse_symbol(reader):
    symbol = ''
    while not reader.exhausted():
        c = reader.next()
        if c in symbolstops:
            reader.push_back(c)
            break
        symbol += c
    return symbol



def parse_symbol(reader):
    loc = reader.loc()
    symbol = _parse_symbol(reader)
    assert len(symbol) > 0, repr(loc)
    return mk_keyword(symbol) if symbol.startswith(':') else _mk_symbol(symbol, loc)

def parse_meta(reader):
    metadata = mk_omap()
    while True:
        skip_spaces(reader)
        item = parse_sexp(reader, False)
        skip_spaces(reader)
        if is_omap(item):
            update = item
        elif is_keyword(item):
            update = { item: mk_bool(True) }
        elif is_symbol(item):
            if uc.is_upper(ord(symbol_to_string(item)[0])):
                update = { mk_keyword(':tag'): item }
            else:
                assert uc.is_lower(ord(symbol_to_string(item)[0])), repr(item)
                update = { item: mk_bool(True) }
        else:
            update = { mk_keyword(':tag'): item }
        for k,v in update.viewitems():
            if k in metadata:
                add_warning('overriding metadata %s' % k)
            metadata[k] = v
        if not reader.got('^'):  # one more
            break
    symbol = parse_symbol(reader)  # metadata allowed only for symbols so far (and it will remain, most likely)
    return update_metadata(symbol, metadata)

_codes_to_characters = {
     7: 'bell',
     8: 'backspace',
     9: 'tab',
    10: 'newline',
    11: 'vertical_tab',
    12: 'formfeed',
    13: 'return',
    32: 'space'}

_characters_to_codes = reverse_dict(_codes_to_characters)

def parse_sexp(reader, allow_metadata=True):
    result = None
    while not reader.exhausted():
        result = _parse_sexp(reader, allow_metadata)
        if result is not None and not is_term(result, 'comment'):
            break
        skip_spaces(reader)
        result = None
    return result

def _parse_sexp(reader, allow_metadata=True):
    c_loc = reader.loc()
    c = reader.next()
    if allow_metadata and c == '^':
        c = reader.next()
        if uc.is_punct(ord(c)) and c not in "{}[]<>()":  # [!] magic constants
            return _mk_symbol('^' + c + _parse_symbol(reader), c_loc)
        reader.push_back(c)
        #print('@meta')
        return parse_meta(reader)
    if c == '{':
        #print('@map')
        pairs = pairwise(parse_list(reader, '}', 2))
        pairs = [ mk_term(_mk_symbol('mk_tuple', c_loc), k,v) for k,v in pairs ]
        return mk_term(_mk_symbol('__braces__', c_loc), *pairs)
    if c == '(':
        #print('@tuple')
        skip_spaces(reader)
        c = reader.next()
        if c == '.':
            symbol = _parse_symbol(reader)
            if symbol:
                return mk_term(_mk_symbol('__dotsym__', c_loc), _mk_symbol(symbol, c_loc),  *parse_list(reader, ')'))
            return mk_term(_mk_symbol('__dot__', c_loc), *parse_list(reader, ')'))
        reader.push_back(c)
        return mk_tuple(*parse_list(reader, ')'))  # [!] mk_term(_mk_symbol('__parens__', c_loc), *parse_list(reader, ')'))
    if c == '[':
        #print('@list')
        return mk_list(*parse_list(reader, ']'))  # [!] mk_term(_mk_symbol('__brackets__', c_loc), *parse_list(reader, ']'))
    if False and c == '\\':
        c = reader.next()
        if c in parens:
            return mk_char(c)
        reader.push_back(c)
        char_name = symbol_to_string(parse_symbol(reader))
        return mk_char(_characters_to_codes.get(char_name, char_name))  # [!] directly or via mk_term?!
    if c == '"':
        if reader.got('"'):
            if reader.got('"'):
                return parse_string(reader, '"', True)
            else:
                return mk_string("")
        return parse_string(reader, '"')
    if c == '%':
        rest_sym_str = _parse_symbol(reader)
        if rest_sym_str == '':
            return mk_term(_mk_symbol('xinx.lambda.arg', c_loc))
        if len(rest_sym_str) == 1 and rest_sym_str >= '0' and rest_sym_str <= '9':
            return mk_term(_mk_symbol('xinx.lambda.arg', c_loc), ord(rest_sym_str) - ord('0'))
        return _mk_symbol('%' + rest_sym_str, c_loc)


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


    if c == ',':
        return _mk_symbol(c, c_loc)
    if c == '#':
        #print('@reader-macro')
        return parse_reader_macro(reader, c_loc)
        #return _mk_symbol(c, c_loc)
    if c in macros:
        #print('@simple-macro')
        return parse_simple_macro(reader, macros[c], c_loc)    #print('@symbol')
    reader.push_back(c)
    return parse_symbol(reader)

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

def parse_list(reader, until=None, comma_groups=None):
    start_loc = reader.loc()
    list = []
    skip_spaces(reader)
    comma_mode = None
    count = 0
    while True:
        #print('@parse_list', until, count, comma_groups, start_loc)

        if until is None:
            if reader.exhausted():
                break
        else:
            assert not reader.exhausted(), 'paren %s opened at %s is not closed' % (until, start_loc)
            if reader.got(until):
                break

        sexp = parse_sexp(reader)
        if sexp is None:
            break
        list.append(sexp)
        count += 1

        #print('parsed',list)
        skip_spaces(reader)

        if False and count == comma_groups:
            c = reader.next()
            count = 0
            if comma_mode == True:
                if c == until:
                    break
                assert c == ','
                skip_spaces(reader)
            elif comma_mode == None:  # unknown
                if c == ',':
                    comma_mode = True
                    skip_spaces(reader)
                else:
                    comma_mode = False
                    reader.push_back(c)

    return list
