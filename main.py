#!/usr/bin/python3
import re
import argparse
import os

# Parser

parser = argparse.ArgumentParser()
parser.add_argument('certname', help="Certbot certificate name (--cert-name) to update, can be found from command certbot certificates")
parser.add_argument('webroot', help="Webroot path, must be filled in manually (since there can be multiple ways to target acme-challenge folder)")
parser.add_argument('nginxconfpath', help="Path to nginx config. This script will automatically find all domains.")
parser.add_argument('-p', help="If there is servers that listen to other ports rather than 443, just skip any other ports and jump straight to 443 domains. It is a bad practice tho.", action="store_true")
parser.add_argument('-d', '--dry-run', help="With this flag, a certbot dry-run will be initiated instead of real cert change.", action="store_true")
parser.add_argument('-s', '--script-dry-run', help="With this flag, no action will be sent - script only will show command it is about to execute.", action="store_true")
args = parser.parse_args()

# Thank you stackoverflow!

class Node(object):
    def __init__(self, directive=None, args=None, children=None, root=False):
        if not directive and not root:
            raise Exception('If not root node, directive must be set.')
        if directive and root:
            raise Exception('Directive must not be set for root node.')
        self.directive = directive
        self.root = root
        if not args:
            args = []
        self.args = args
        if not children:
            children = []
        self.children = children

    def __repr__(self):
        if len(self.args) > 0:
            args = ' ' + ' '.join(self.args)
        else:
            args = ''
        return '<Node: {}{}>'.format(
            self.directive or '*root*',
            args
        )

    def query(self, directive, *args, first=False, **kwargs):
        results = filter(lambda c: c.directive == directive, self.children)
        i = 0
        results = filter(lambda c: len(c.args) >= len(args), results)
        for arg in args:
            old_results = results
            results = []
            for result in old_results:
                try:
                    if args[i] == arg:
                        results.append(result)
                except IndexError:
                    pass
            i += 1

        if first:
            return list(results)[0]

        return results

    def dump(self, indent=0):
        def get_children(_indent):
            return '\n'.join(
                [child.dump(_indent) for child in self.children]
            )
        spaces = indent * '    '
        if self.children:
            if self.root:
                return get_children(indent)
            else:
                return '{0}{1} {2} {{\n{3}\n{0}}}'.format(
                    spaces,
                    self.directive,
                    ' '.join(self.args),
                    get_children(indent + 1)
                )
        else:
            return '{}{} {};'.format(
                spaces,
                self.directive,
                ' '.join(self.args))

    def __str__(self):
        return self.dump(indent=0)

def loads(string):
    """Loads a nginx config file into memory as a dict."""
    stack = []
    current_block = Node(root=True)
    current_statement = []
    current_word = ''

    for char in string:
        if char == '{':
            """Put the current block on the stack, start a new block.
            Also, if we are in a word, "finish" that off, and end the current
            statement."""
            stack.append(current_block)
            if len(current_word) > 0:
                current_statement.append(current_word)
                current_word = ''
            current_block = Node(
                current_statement[0],
                args=current_statement[1:]
            )
            current_statement = []
        elif char == '}':
            """Finalize the current block, pull the previous (outer) block off
            of the stack, and add the inner block to the previous block's dict
            of blocks."""
            inner = current_block
            current_block = stack.pop()
            directive = current_block.directive
            current_block.children.append(inner)
        elif char == ';':
            """End the current word and statement."""
            current_statement.append(current_word)
            current_word = ''
            if len(current_statement) > 0:
                key = current_statement[0]
                current_block.children.append(Node(
                        current_statement[0],
                        args=current_statement[1:]
                ))
            current_statement = []
        elif char in ['\n', ' ', '\t']:
            """End the current word."""
            if len(current_word) > 0:
                current_statement.append(current_word)
                current_word = ''
        else:
            """Add current character onto current word."""
            current_word += char

    return current_block

# My program
def getListeningPorts(serverNode):
    ports = list(serverNode.query("listen"))
    answer = []
    for port in ports:
        answer.append(re.search('\d+', str(port)).group(0))
    return answer

def prepareDomains(serverNode):
    q = str(serverNode.query("server_name", first=True))
    q = re.sub('server_name\s+', '', q)
    q = re.sub('\s+', ',', q)
    q = re.sub(';', '', q)
    return q

def executeCertbot(domains):
    dryrun = '--dry-run ' if args.dry_run else ''
    command = f'certbot certonly {dryrun}--cert-name {args.certname} --webroot -w {args.webroot} -d {domains}'
    if args.script_dry_run:
        print('Script will dry-run without executing command!')
        print(command)
    else:
        print('Script will run in battlemode.')
        os.system(command)

try:
    with open(args.nginxconfpath, 'r', encoding='utf-8') as f:
        config_file = f.read()
except Exception as E:
    print(f'File not found. Error {E}.')
    exit(1)

nginx_config = loads(config_file)
servers_in_config = list(nginx_config.query("server"))
if len(servers_in_config) == 0:
    print("ERROR: No servers found in config. Prehaps, you loaded wrong file?")
    exit(1)
elif len(servers_in_config) == 1:
    print("Found only one server section in config. Lets see about ports inside. Expecting 443 or double-ported 80/443.")
    listenports = getListeningPorts(servers_in_config[0])
    if len(listenports) == 0:
        print("No listen ports found. Emergency shutdown! Check your configuration file!")
        exit(1)
    else:
        print(f"Found {len(listenports)} available ports. Searching for 443th.")
        if '443' not in listenports:
            print("ERROR: 443 port not found in server config! Shutting down!")
            exit(1)
        else:
            print("443th port confirmed. Gathering domains and executing certbot.")
            domains_on_server = prepareDomains(servers_in_config[0])
            executeCertbot(domains_on_server)  
elif len(servers_in_config) == 2:
    print("Good. Found two server sections. Presumably, 80 and 443 ports. Althrough we must check.")
    listenport1 = getListeningPorts(servers_in_config[0])
    listenport2 = getListeningPorts(servers_in_config[1])
    if '443' in listenport1:
        print("First section have 443th port. Thats good.")
        secureDomains, nonsecureDomains = prepareDomains(servers_in_config[0]), prepareDomains(servers_in_config[1])
        if secureDomains != nonsecureDomains and not args.p:
            print("ERROR: server_name directives have different strings for both servers! Exiting now...")
            exit(1)
        else:
            print("Both server parts have same server_name directives or -p flag was sent. Executing certbot on domains found in 443 port!")
            executeCertbot(secureDomains)
    elif '443' in listenport2:
        print("Second section have 443th port. Thats good.")
        secureDomains, nonsecureDomains = prepareDomains(servers_in_config[1]), prepareDomains(servers_in_config[0])
        if secureDomains != nonsecureDomains and not args.p:
            print("ERROR: server_name directives have different strings for both servers! Exiting now...")
            exit(1)
        else:
            print("Both server parts have same server_name directives or -p flag was sent. Executing certbot on domains found in 443 port!")
            executeCertbot(secureDomains)
    else:
        print("ERROR: No section have 443th port! Shutting down!")
        exit(1)
else:
    print("ERROR: There is more than 2 global server-sections in file. I haven't been taught for this so I just shut down.")
    exit(1)