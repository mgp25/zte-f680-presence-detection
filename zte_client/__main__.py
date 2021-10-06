import sys
from argparse import ArgumentParser
from ZteClient import ZteClient

def argparser():

    parser = ArgumentParser(prog='ZteClient')

    router_args = parser.add_argument_group('router connection config')
    router_args.add_argument('--host', help='Hostname or IP address, defaults to \'10.0.0.20\'')
    router_args.add_argument('--user', help='Web UI admin username account, defaults to \'admin\'')
    router_args.add_argument('--password', help='Web UI admin password')
    
    subparsers = parser.add_subparsers(
            description='Runs subcommand against the specified router',
            dest='subcommand')
    subparsers.add_parser('get_connected_devices', help='Get all connected devices')

    return parser

def main():
    args = argparser().parse_args(sys.argv[1:])
    zte_client = ZteClient(args.host, args.user, args.password, )
    zte_client.login()
    if args.subcommand == 'get_connected_devices':
        print(zte_client.get_connected_devices())

if __name__ == '__main__':
    main()
