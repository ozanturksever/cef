import re

CEF_HEADERS = (
    'version', 'device_vendor', 'device_product', 'device_version', 'signature_id', 'name', 'severity', 'extension')
VISIBLE_CEF_HEADERS = (
    'device_vendor', 'device_product', 'device_version', 'signature_id', 'name', 'severity')
LABEL_POSTIX = 'Label'
COMMON_VAR_PREFIXES = ['cn', 'cs']
WORD_SPERATOR = ' '
EQUAL_SIGN = '='
STOP_CHARS = [EQUAL_SIGN, WORD_SPERATOR]
MESSAGE_PATTERN = '(?P<date>\w+\s+\d+ \d+:\d+:\d+) (?P<host>[\w\-.()]+) (?P<message>.*)'

class ParseFailed(Exception):
    pass

class CefParser:
    def __init__(self, line, replace_space_with=' '):
        self._setup_replace_space(replace_space_with)
        self._setup_variables(line)
        self.parse()

    def parse(self):
        self.extract_message()
        self.extract_cef_message()
        self.extract_extension_key_positions()
        self.extract_extension_values()
        self.extract_common_values()

    def extract_message(self):
        r = re.compile(MESSAGE_PATTERN)
        grp = r.match(self.line)
        if grp:
            self.syslog_message = grp.groupdict()
        else:
            raise ParseFailed

    def extract_cef_message(self):
        try:
            s = self.syslog_message['message'].split('|')
            s.reverse()
            for header in CEF_HEADERS:
                self.cef_message[header] = s.pop()
        except:
            raise ParseFailed

    def extract_extension_key_positions(self):
        (key, keys) = ('', [])
        (start_position, end_position) = (0, len(self.cef_message['extension']))
        current_position = len(self.cef_message['extension'])
        for c in reversed(self.cef_message['extension']):
            if c not in STOP_CHARS:
                if key == '':
                    end_position = current_position
                key = c + key
            else:
                start_position = current_position
                if self.cef_message['extension'][end_position:end_position + 1] == EQUAL_SIGN:
                    if len(key) > 0:
                        keys.append((key, start_position, end_position))
                key = ''
            current_position -= 1
        keys.append((key, current_position, end_position)) # last key
        self.extension_keys = keys

    def extract_extension_values(self):
        values = {}
        for (key, start_position, end_position) in self.extension_keys:
            value = ''
            for c in self.cef_message['extension'][end_position + 1:]:
                if c not in EQUAL_SIGN:
                    value += c
                else:
                    values[key] = WORD_SPERATOR.join(value.split(WORD_SPERATOR)[:-1])
                    value = ''
                    break
        self.extension_values = values

    def extract_common_values(self):
        with_common_values = {}
        values = self.extension_values
        for key in values:
            if key[0:2] in COMMON_VAR_PREFIXES and key[-len(LABEL_POSTIX):] == LABEL_POSTIX:
                if self.replace_space:
                    k = values[key].replace(WORD_SPERATOR, self.replace_space_with)
                else:
                    k = values[key]
                with_common_values[k] = values[key[0:3]]
            elif key[0:2] not in COMMON_VAR_PREFIXES:
                with_common_values[key] = values[key]
        self.with_common_values = with_common_values

    def get(self):
        vals = self.with_common_values
        for header in VISIBLE_CEF_HEADERS:
            vals[header] = self.cef_message[header]
        return vals

    def _setup_variables(self, line):
        self.line = line
        self.syslog_message = {'date':'','host':'','message':''}
        self.cef_message = {}
        self.extension_values = {}
        self.with_common_values = {}
        self.extension_keys = []

    def _setup_replace_space(self, replace_space_with):
        self.replace_space = False
        if replace_space_with != ' ':
            self.replace_space = True
            self.replace_space_with = replace_space_with

    def get_syslog_message(self):
        return self.syslog_message

    def get_cef_message(self):
        return self.cef_message

    def get_extension_keys(self):
        positions = self.get_extension_key_positions()
        return [k[0] for k in positions]

    def get_extension_key_positions(self):
        return self.extension_keys

    def get_extension_values(self):
        return self.extension_values

    def get_with_common_values(self):
        return self.with_common_values
