# irc client in python
# since it uses alarm() with a 1 second timeout.. it should only be used whenever wanting other nodes..
# some bots (maybe 5-10%) should keep it on.. maybe i can fork() it or find a better script
# either way its good enough to launch..
# itll be able to return the messages for processing to the calling c++ program
# and allow the c++ program to distribute messages via the python script

import zokket
import re
import datetime

from zokket.tcp import TCPSocket
import signal
from contextlib import contextmanager

#id to return as the 'module' identifier.. for redirecting messages to this module
irc_client_module_id = 9

class TimeoutException(Exception): pass


class Nick(object):
    IRC_USERHOST_REGEX = re.compile(r'^(.*)!(.*)@(.*)$')

    @classmethod
    def parse(cls, client, userhost):
        m = cls.IRC_USERHOST_REGEX.match(userhost)
        if m:
            return cls(client, m.group(1), m.group(2), m.group(3))
        return cls(client, host=userhost)

    def __init__(self, client, nick='', ident='', host=''):
        self.client = client
        self.nick = nick
        self.ident = ident
        self.host = host

        self.channel_modes = []

    def __str__(self):
        return self.nick

    def __repr__(self):
        return '<Nick %s!%s@%s>' % (self.nick, self.ident, self.host)

    def __eq__(self, other):
        return str(other) == self.nick

    def send(self, message):
        """
        Sends a message to the nick.
        """
        self.client.send('PRIVMSG', self, message, force=True)

    @property
    def channels(self):
        """
        Returns all the Channels that both the nick and the client has joined.
        """
        return [channel for channel in self.client.channels if channel.has_nick(self)]

    # Channel

    def has_perm(self, perm):
        return perm in self.channel_modes

    def add_perm(self, perm):
        if not self.has_perm(perm):
            self.channel_modes.append(perm)

    def remove_perm(self, perm):
        self.channel_modes.remove(perm)

    def set_nick(self, nick):
        if self == self.client.nick:
            self.client.nick.nick = nick

        for channel in self.client.channels:
            n = channel.find_nick(self)
            if n:
                n.nick = nick

        self.nick = nick

    def update(self):
        if self == self.client.nick:
            self.client.nick.ident = self.ident
            self.client.nick.host = self.host

        for channel in self.client.channels:
            n = channel.find_nick(self)
            if n:
                n.ident = self.ident
                n.host = self.host


class Channel(object):
    def __init__(self, client, name):
        self.client = client
        self.name = name
        self.modes = {}

        self.key = None

        self.is_attached = False

        self.creation_date = None

        self.topic = None
        self.topic_date = None
        self.topic_owner = None

        self.nicks = []

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Channel %s>' % self.name

    def __in__(self, other):
        return other in self.nicks

    def send(self, message):
        """
        Sends a message to the channel.
        """
        self.client.send('PRIVMSG', self, message, force=True)

    def add_nick(self, nick):
        if self.client.nick == nick:
            self.is_attached = True
            self.client.send('MODE', self)

        if not self.has_nick(nick):
            self.nicks.append(nick)

    def remove_nick(self, nickname):
        nick = self.find_nick(nickname)
        if nick:
            self.nicks.remove(nick)

            if self.client.nick == nick:
                self.leave()

    def has_nick(self, nick):
        return bool(self.find_nick(nick))

    def find_nick(self, nickname):
        for nick in self.nicks:
            if nick == nickname:
                return nick

    def mode_change(self, modes):
        add = True
        args = []

        if ' ' in modes:
            modes, args = modes.split(' ', 1)
            args = args.split()

        for mode in modes:
            if mode == '+':
                add = True
            elif mode == '-':
                add = False
            elif mode in self.client.isupport['prefix']:
                # Its a permission mode (like op, voice etc)

                nick = self.find_nick(args.pop(0))
                if nick:
                    if add:
                        nick.add_perm(mode)
                    else:
                        nick.remove_perm(mode)

            elif mode in self.client.isupport['chanmodes']:
                args_type = self.client.isupport['chanmodes'][mode]

                if args_type == list:
                    if mode not in self.modes:
                        self.modes[mode] = []

                    if add:
                        self.modes[mode].append(args.pop(0))
                    else:
                        self.modes[mode].remove(args.pop(0))

                elif args_type == 'arg':
                    arg = args.pop(0)

                    if add:
                        self.modes[mode] = arg
                    elif mode in self.modes and self.modes[mode] == arg:
                        del self.modes[mode]

                elif args_type == 'arg_set':
                    if add:
                        self.modes[mode] = args.pop(0)
                    else:
                        if mode in self.modes:
                            del self.modes[mode]

                elif args_type == None:
                    if add:
                        self.modes[mode] = True
                    elif mode in self.modes:
                        del self.modes[mode]

    def leave(self):
        self.is_attached = False
        self.nicks = []

    def join(self):
        self.client.send('JOIN', self)

    def part(self):
        """
        Part the Channel.
        """
        self.client.send('PART', self)


IRC_CAP_REGEX = re.compile(r"^(\S+) (\S+) :(.+)$")
IRC_PRIVMSG_REGEX = re.compile(r"^(\S+) :(.+)$")
IRC_NAMES_REGEX = re.compile(r'^(@|=|\+) (\S+) :(.+)$')

IRC_KICK_REGEX = re.compile(r'^(\S+) (\S+) :(.+)$')


class IRCIgnoreLine(Exception):
    pass


class Client(TCPSocket):
    channel_class = Channel
    nick_class = Nick

    def __init__(self, nickname='irctk', ident='irctk', realname='irctk', password=None):
        super(Client, self).__init__()

        self.nickname = nickname
        self.ident = ident
        self.realname = realname
        self.password = password

        self.is_registered = False
        self.secure = False
        self.read_until_data = "\r\n"
        self.nick = self.nick_class(self)

        self.channels = []
        self.isupport = ISupport()

        self.cap_accepted = []
        self.cap_pending = []

        self.resolver = RegexResolver(
            (r'^:(\S+) (\d{3}) ([\w*]+) :?(.+)$', self.handle_numerical),
            (r'^:(\S+) (\S+) (.+)$', self.handle_command),
            (r'^PING :?(.+)$', self.handle_ping)
        )

    # Variables

    def get_nickname(self):
        return self.nickname

    def get_alt_nickname(self, nickname):
        return nickname + '_'

    def get_ident(self):
        return self.ident

    def get_realname(self):
        return self.realname

    def get_password(self):
        return self.password

    # CAP

    def supports_cap(self, cap):
        return cap in ['multi-prefix']

    # Channels

    def is_channel(self, channel):
        if isinstance(channel, Channel):
            return True

        return self.isupport.is_channel(channel)

    def find_channel(self, name):
        for channel in self.channels:
            if channel.name == name:
                return channel

    def add_channel(self, name, key=None):
        channel = self.find_channel(name)

        if not channel:
            channel = self.channel_class(self, name)
            self.channels.append(channel)

        if key:
            channel.key = key

        return channel

    # Socket

    def connect(self, host, port, use_tls=False):
        """
        Connect the client to a server.
        """
        self.secure = use_tls
        super(Client, self).connect(host, port, timeout=1)

    def socket_did_connect(self):
        if self.secure:
            self.start_tls()
        else:
            self.authenticate()

    def socket_did_secure(self):
        self.authenticate()

    def socket_did_disconnect(self, err=None):
        super(Client, self).socket_did_disconnect(err)
        self.is_registered = False

    def quit(self, message='Disconnected'):
        """
        Disconnects from IRC and closes the connection. Accepts an optional
        reason.
        """
        self.send("QUIT", message)
        self.close()

    def send_line(self, line):
        """
        Sends a raw line to IRC

        Example::

            >>> client.send_line('PRIVMSG kylef :Hey!')
        """
        super(Client, self).send(line + "\r\n")

    def send(self, *args, **kwargs):
        force = kwargs.get('force', False)
        args = [str(arg) for arg in args]

        try:
            last = args[-1]
        except IndexError:
            return

        if force or last.startswith(':') or ' ' in last:
            args.append(':' + args.pop())

        self.send_line(' '.join(args))

    def authenticate(self):
        if not self.is_registered:
            self.send('CAP', 'LS')

            password = self.get_password()
            if password:
                self.send('PASS', password)

            self.send('NICK', self.get_nickname())
            self.send('USER', self.get_ident(), '0', '*', self.get_realname(), force=True)

    # Handle IRC lines

    def read_data(self, data):
        line = data.strip()

        try:
            self.irc_raw(line)
        except IRCIgnoreLine:
            return

        self.resolver(line)

    def handle_numerical(self, server, command, nick, args):
        numeric = int(command)
        if hasattr(self, 'handle_%s' % numeric):
            getattr(self, 'handle_%s' % numeric)(server, nick, args)

    def handle_command(self, sender, command, args):
        command = command.lower()
        nick = self.nick_class.parse(self, sender)

        if hasattr(self, 'handle_%s' % command):
            getattr(self, 'handle_%s' % command)(nick, args)

    def handle_1(self, server, nick, args):
        self.is_registered = True
        self.nick.nick = nick

        self.send('WHO', self.nick)
        self.irc_registered()

    def handle_5(self, server, nick, args):
        self.isupport.parse(args)

    def handle_324(self, server, nick, args): # MODE
        channel_name, mode_line = args.split(' ', 1)

        channel = self.find_channel(channel_name)
        if channel:
            channel.modes = {}
            channel.mode_change(mode_line)

    def handle_329(self, server, nick, args):
        channel_name, timestamp = args.split(' ', 1)

        channel = self.find_channel(channel_name)
        if channel:
            channel.creation_date = datetime.datetime.fromtimestamp(int(timestamp))

    def handle_332(self, server, nick, args):
        chan, topic = args.split(' ', 1)
        if topic.startswith(':'):
            topic = topic[1:]

        channel = self.find_channel(chan)
        if channel:
            channel.topic = topic

    def handle_333(self, server, nick, args):
        chan, owner, timestamp = args.split(' ', 2)

        channel = self.find_channel(chan)
        if channel:
            channel.topic_owner = owner
            channel.topic_date = datetime.datetime.fromtimestamp(int(timestamp))

    def handle_352(self, server, nick, args):
        args = args.split(' ')

        try:
            nick = args[4]
            ident = args[1]
            host = args[2]
        except IndexError:
            return

        if self.nick.nick == nick:
            self.nick.ident = ident
            self.nick.host = host

    def handle_432(self, server, nick, args):
        # Erroneous Nickname: Illegal characters
        self.handle_433(server, nick, args)

    def handle_433(self, server, nick, args):
        # Nickname is already in use
        if nick == '*':
            nick = self.get_nickname()

        if not self.is_registered:
            self.send('NICK', self.get_alt_nickname(nick))

    def names_353_to_nick(self, nick):
        for mode, prefix in self.isupport['prefix'].items():
            if nick.startswith(prefix):
                nickname = nick[len(mode):]
                if '@' in nickname:
                    n = self.nick_class.parse(self, nickname)
                else:
                    n = self.nick_class(self, nick=nickname)
                n.add_perm(mode)
                return n
        if '@' in nick:
            return self.nick_class.parse(self, nick)
        return self.nick_class(self, nick=nick)

    def handle_353(self, server, nick, args):
        m = IRC_NAMES_REGEX.match(args)
        if m:
            channel = self.find_channel(m.group(2))
            if channel:
                users = m.group(3)

                for user in users.split():
                    nick = self.names_353_to_nick(user)
                    channel.add_nick(nick)

    def handle_ping(self, line):
        self.send('PONG', line)

    def handle_cap(self, nick, line):
        m = IRC_CAP_REGEX.match(line)
        if m:
            command = m.group(2).lower()
            args = m.group(3)

            if command == "ls":
                supported_caps = args.lower().split()

                for cap in supported_caps:
                    if self.supports_cap(cap):
                        self.send('CAP', 'REQ', cap)
                        self.cap_pending.append(cap)
            elif command == "ack":
                caps = args.lower().split()

                for cap in caps:
                    if cap in self.cap_pending:
                        self.cap_pending.remove(cap)
                        self.cap_accepted.append(cap)
            elif command == "nak":
                supported_caps = args.lower().split()

                for cap in supported_caps:
                    if cap in self.cap_pending:
                        self.cap_pending.remove(args)

        if not self.cap_pending:
            self.send('CAP', 'END')

    def handle_join(self, nick, line):
        if line.startswith(':'):
            chan = line[1:]
        else:
            chan = line

        channel = self.find_channel(chan)
        if channel:
            channel.add_nick(nick)
            self.irc_channel_join(nick, channel)

    def handle_part(self, nick, line):
        if ' :' in line:
            chan, message = line.split(' :', 1)
        else:
            chan = line
            message = ''

        channel = self.find_channel(chan)
        if channel:
            channel.remove_nick(nick)
            self.irc_channel_part(nick, channel, message)

    def handle_kick(self, nick, line):
        m = IRC_KICK_REGEX.match(line)
        if m:
            chan = m.group(1)
            kicked_nick = m.group(2)
            kicked_nick = self.nick_class(self, nick=kicked_nick)
            message = m.group(3)

            channel = self.find_channel(chan)
            if channel:
                channel.remove_nick(kicked_nick)
                self.irc_channel_kick(nick, channel, message)

    def handle_topic(self, nick, line):
        chan, topic = line.split(' ', 1)
        if topic.startswith(':'):
            topic = topic[1:]

        channel = self.find_channel(chan)
        if channel:
            channel.topic = topic
            channel.topic_owner = nick
            channel.topic_date = datetime.datetime.now()

            self.irc_channel_topic(nick, channel)

    def handle_nick(self, nick, new_nick):
        nick.set_nick(new_nick)

    def handle_privmsg(self, nick, line):
        m = IRC_PRIVMSG_REGEX.match(line)
        if m:
            message = m.group(2)
            if m.group(1) == str(self.nick):
                self.irc_private_message(nick, message)
            else:
                channel = self.find_channel(m.group(1))
                if channel:
                    self.irc_channel_message(channel.find_nick(nick), channel, message)

    def handle_mode(self, nick, line):
        subject, mode_line = line.split(' ', 1)

        if self.is_channel(subject):
            channel = self.find_channel(subject)

            if channel:
                channel.mode_change(mode_line)

    def handle_quit(self, nick, reason):
        for channel in nick.channels:
            self.irc_channel_quit(nick, channel, reason)
            channel.remove_nick(nick)

    # Delegation methods

    def irc_registered(self):
        if hasattr(self.delegate, 'irc_registered'):
            self.delegate.irc_registered(self)

    def irc_raw(self, line):
        if hasattr(self.delegate, 'irc_raw'):
            self.delegate.irc_raw(self, line)

    def irc_private_message(self, nick, message):
        if hasattr(self.delegate, 'irc_private_message'):
            self.delegate.irc_private_message(self, nick, message)

    def irc_channel_message(self, nick, channel, message):
        if hasattr(self.delegate, 'irc_channel_message'):
            self.delegate.irc_channel_message(self, nick, channel, message)

    def irc_channel_join(self, nick, channel):
        if hasattr(self.delegate, 'irc_channel_join'):
            self.delegate.irc_channel_join(self, nick, channel)

    def irc_channel_quit(self, nick, channel, message):
        if hasattr(self.delegate, 'irc_channel_quit'):
            self.delegate.irc_channel_quit(self, nick, channel, message)

    def irc_channel_part(self, nick, channel, message):
        if hasattr(self.delegate, 'irc_channel_part'):
            self.delegate.irc_channel_part(self, nick, channel, message)

    def irc_channel_kick(self, nick, channel, message):
        if hasattr(self.delegate, 'irc_channel_kick'):
            self.delegate.irc_channel_kick(self, nick, channel, message)

    def irc_channel_topic(self, nick, channel):
        if hasattr(self.delegate, 'irc_channel_topic'):
            self.delegate.irc_channel_topic(self, nick, channel)

    def irc_channel_mode(self, nick, channel, mode, arg, added):
        pass




class ISupport(dict):
    IRC_ISUPPORT_PREFIX = re.compile(r'^\((.+)\)(.+)$')

    def __init__(self):
        self['casemapping'] = 'rfc1459'
        self['chanmodes'] = {
            'b': list,
            'e': list,
            'I': list,
            'k': 'arg',
            'l': 'arg_set',
            'p': None,
            's': None,
            't': None,
            'i': None,
            'n': None,
        }

        self['prefix'] = { 'o': '@', 'v': '+' }
        self['channellen'] = 200
        self['chantypes'] = ['#', '&']
        self['modes'] = 3
        self['nicklen'] = 9

        # Unlimited
        self['topiclen'] = 0
        self['kicklen'] = 0
        self['modes'] = 0

    def __str__(self):
        values = []

        for key in self:
            method = getattr(self, 'to_str_{}'.format(key), None)
            if method:
                value = method()
            else:
                value = self[key]

            if value is not None:
                if value is True:
                    value = '1'
                elif value is False:
                    value = '0'
                elif isinstance(value, list):
                    value = ''.join(value)

                values.append('{}={}'.format(key.upper(), value))
            else:
                values.append(key.upper())

        return ' '.join(values)

    def to_str_chanmodes(self):
        chanmodes = self.get('chanmodes', {})
        list_args, arg, arg_set, no_args = [], [], [], []

        for mode in chanmodes:
            value = chanmodes[mode]

            if value is list:
                list_args.append(mode)
            elif value is 'arg':
                arg.append(mode)
            elif value is 'arg_set':
                arg_set.append(mode)
            elif value is None:
                no_args.append(mode)

        return ','.join(map(lambda modes: ''.join(modes), [list_args, arg, arg_set, no_args]))

    def to_str_prefix(self):
        prefix = self.get('prefix', {})

        modes = ''
        prefixes = ''

        for mode in prefix:
            modes += mode
            prefixes += prefix[mode]

        return '({}){}'.format(modes, prefixes)

    # Parsing

    def parse(self, line):
        for pair in line.split():
            if '=' not in pair:
                self[pair] = None
                continue

            key, value = pair.split('=', 1)

            if key == 'PREFIX':
                self.parse_prefix(value)
            elif key == 'CHANMODES':
                self.parse_chanmodes(value)
            elif key == 'CHANTYPES':
                self['chantypes'] = list(value)
            elif key in ('CHANNELLEN', 'NICKLEN', 'MODES', 'TOPICLEN', 'KICKLEN', 'MODES'):
                self[key.lower()] = int(value)
            elif key == 'CASEMAPPING':
                self[key.lower()] = value

    def parse_prefix(self, value):
        self['prefix'] = {}

        m = self.IRC_ISUPPORT_PREFIX.match(value)
        if m and len(m.group(1)) == len(m.group(2)):
            for x in range(0, len(m.group(1))):
                self['prefix'][m.group(1)[x]] = m.group(2)[x]

    def parse_chanmodes(self, value):
        try:
            list_args, arg, arg_set, no_args = value.split(',')
        except:
            return

        self['chanmodes'] = {}

        for mode in list_args:
            self['chanmodes'][mode] = list

        for mode in arg:
            self['chanmodes'][mode] = 'arg'

        for mode in arg_set:
            self['chanmodes'][mode] = 'arg_set'

        for mode in no_args:
            self['chanmodes'][mode] = None

    # Get

    @property
    def maximum_nick_length(self):
        """
        Returns the maximum length of a nickname.

        Example::

            >>> support.maximum_nick_length
            9
        """
        return self['nicklen']

    @property
    def maximum_channel_length(self):
        """
        Returns the maximum length of a channel name.

        Example::

            >>> support.maximum_channel_length
            200
        """
        return self['channellen']

    @property
    def channel_prefixes(self):
        """
        Returns a list of channel prefixes.

        Example::

            >>> support.channel_prefixes
            ['#', '&']
        """
        return self['chantypes']

    #

    def is_channel(self, channel_name):
        """
        Returns True if supplied channel name is a valid channel name.

        Example::

            >>> support.is_channel('#darkscience')
            True

            >>> support.is_channel('kylef')
            False
        """
        if ',' in channel_name or ' ' in channel_name:
            return False

        if len(channel_name) > self.maximum_channel_length:
            return False

        for prefix in self['chantypes']:
            if channel_name.startswith(prefix):
                return True

        return False





class RegexPattern(object):
    def __init__(self, regex, handler, default_kwargs={}):
        self.regex = re.compile(regex, re.UNICODE)
        self.callback = handler
        self.default_kwargs = default_kwargs

    def resolve(self, line):
        match = self.regex.search(line)
        if match:
            return self.match_found(line, match)

    def match_found(self, line, match):
        kwargs = match.groupdict()

        if kwargs:
            args = tuple()
        else:
            args = match.groups()

        kwargs.update(self.default_kwargs)

        return self.callback, args, kwargs

class RegexResolver(object):
    def __init__(self, *patterns):
        self.patterns = []

        for pattern in patterns:
            if isinstance(pattern, (list, tuple)):
                pattern = RegexPattern(*pattern)

            self.patterns.append(pattern)

    def resolve(self, line):
        for pattern in self.patterns:
            result = pattern.resolve(line)
            if result is not None:
                return result
        return

    def __call__(self, line):
        result = self.resolve(line)
        if result:
            callback, args, kwargs = result
            return callback(*args, **kwargs)




class Bot(object):
    def __init__(self):
        print "ok"
    def irc_registered(self, client):
        channel = client.add_channel('#test')
        channel.join()

    def irc_private_message(self, client, nick, message):
        if message == 'ping':
            nick.send('pong')

    def irc_channel_message(self, client, nick, channel, message):
        if message == 'ping':
            channel.send('{}: pong'.format(nick))

    def connectit(self, hostname, port=6667, secure=False):
        client = Client()
        client.delegate = self
        self.client = client
        client.connect(hostname, 6667, False)


# this must 'connect' using the global variable (which is at the bottom)
# but cannot put the framework into an endless loop
def init():
    bot.connectit('127.0.0.1', 6667, False)
    return irc_client_module_id


#this is the real command for looping.. however it is infinite.. so we will wrap it
# so we can set a timeout..    
def loop0():
    while True:
        zokket.DefaultRunloop.run()

#this will set a timer (so we timeout after x seconds) and then run the socket loop...
#this allows it to process whats required, and then go back to the application
#this is a bad way to perform this.. but im still learning enough python to modify
#it quickly
def loop():
    @contextmanager
    def time_limit(seconds):
        def signal_handler(signum, frame):
            raise TimeoutException, "T"
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)


    try:
        with time_limit(1):
            loop0()
    except TimeoutException, msg:
        a = 1

# the global variable must be initialized at the end
bot = Bot()
