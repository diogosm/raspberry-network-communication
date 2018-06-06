#! /usr/bin/env python
# encoding: utf-8

# Copyright Steinwurf ApS 2014.
# Distributed under the "STEINWURF EVALUATION LICENSE 1.0".
# See accompanying file LICENSE.rst or
# http://www.steinwurf.com/licensing

import os
import socket
import time
import sys
import datetime

import argparse
import json

import kodo

# type of message sent
TYPE_FILE=1
TYPE_STRING=2

# How to run it
# Server: python3 udp_unicast_sem_network_coding.py server
# Client: python3 udp_unicast_sem_network_coding.py --file-path lena.jpg client
# @TODO need to change if host is not localhost

def main():
    """UDP Server/Client for sending and receiving files."""
    parser = argparse.ArgumentParser(description=main.__doc__)

    parser.add_argument(
        '--settings-port',
        type=int,
        help='settings port on the server.',
        default=41001)

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run without network use, for testing purposes')

    parser.add_argument(
        '--file-path',
        type=str,
        help='Path to the file which should be send.',
        default=os.path.realpath(__file__))

    subparsers = parser.add_subparsers(
        dest='role', help='help for subcommand')
    subparsers.add_parser(
        'server',
        description="UDP server for sending and receiving files.",
        help='Start a server')

    client_parser = subparsers.add_parser(
        'client',
        description="UDP client for sending and receiving files.",
        help='Start a client')

    client_parser.add_argument(
        '--server-ip',
        type=str,
        help='ip of the server.',
        default='127.0.0.1')

    client_parser.add_argument(
        '--client-control-port',
        type=int,
        help='control port on the client side, used for signaling.',
        default=41003)

    client_parser.add_argument(
        '--server-control-port',
        type=int,
        help='control port on the server side, used for signaling.',
        default=41005)

    client_parser.add_argument(
        '--data-port',
        type=int,
        help='port used for data transmission.',
        default=41011)

    client_parser.add_argument(
        '--direction',
        help='direction of data transmission',
        choices=[
            'client_to_server',
            'server_to_client',
            'client_to_server_to_client'],
        #default='client_to_server_to_client')
        default='client_to_server')

    client_parser.add_argument(
        '--symbols',
        type=int,
        help='number of symbols in each generation/block.',
        default=64)

    client_parser.add_argument(
        '--symbol-size',
        type=int,
        help='size of each symbol, in bytes.',
        default=1400)

    client_parser.add_argument(
        '--max-redundancy',
        type=float,
        help='maximum amount of redundancy to be sent, in percent.',
        default=200)

    client_parser.add_argument(
        '--timeout',
        type=float,
        help='timeout used for various sockets, in seconds.',
        default=.2)

    # We have to use syg.argv for the dry-run parameter, otherwise a subcommand
    # is required.
    if '--dry-run' in sys.argv:
        return

    args = parser.parse_args()

    # Check file.
    if not os.path.isfile(args.file_path):
        print("{} is not a valid file.".format(args.file_path))
        sys.exit(1)

    if args.role == 'client':
        client(args)
    else:
        server(args)


def server(args):
    """Init server."""
    settings_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    settings_socket.bind(('', args.settings_port))

    # Wait for settings connections
    print("Server running, press ctrl+c to stop.")
    while True:
        print("\nwaiting some data...")
        data, address = receive(settings_socket, 1024)
        try:
            settings = json.loads(data)
        except Exception:
            print("Settings message invalid.")
            continue

        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("Settings Received")
        #print("\t\tData settings: \n")
        #print("\t{}".format(json.dumps(settings, indent=4, sort_keys=True)))

        settings['role'] = 'server'
        settings['client_ip'] = address[0]

        if settings['direction'] == 'server_to_client':
            send_data(settings, 'server')
        elif settings['direction'] == 'client_to_server':
            receive_data(settings, 'server')
        else:
            print("Invalid direction.")
            continue


def client(args):
    """Init client."""
    if args.symbol_size > 65000:
        print("Resulting packets too big, reduce symbol size")
        return

    settings = vars(args)
    direction = settings.pop('direction')

    # Note: "server>client>server" matches both cases.
    if 'server_to_client' in direction:
        settings['direction'] = 'server_to_client'
        receive_data(settings, 'client')

    if 'client_to_server' in direction:
        settings['direction'] = 'client_to_server'
        send_data(settings, 'client')


def send_data(settings, role):
    """Send data to the other node."""
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    control_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    control_socket.settimeout(0.00000000000000000001)

    if role == 'client':
        address = (settings['server_ip'], settings['data_port'])

        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("Sending client settings")

        send_settings(settings)
        
        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("Client settings sent")

        control_socket.bind(('', settings['client_control_port']))
    else:  # server
        address = (settings['client_ip'], settings['data_port'])
        server_address = (
            settings['server_ip'],
            settings['client_control_port'])
        control_socket.bind(('', settings['server_control_port']))
        send(send_socket, "settings OK, sending", server_address, TYPE_STRING)

    f = open(os.path.expanduser(settings['file_path']), 'rb')
    fileOpened = f.read(1024)

    sent = 0
    start = time.time()
    end = None
    while fileOpened:
        #print('Sent ',repr(packet))
        packet = fileOpened

        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("Sending file {}...".format(settings['file_path']))
        send(send_socket, packet, address, TYPE_FILE)
        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("File sent...")
        sent += 1

        fileOpened = f.read(1024)

        try:
            print("[{}]: ".format(str(datetime.datetime.now())), end='')
            print("Trying to receive control socket...")

            control_socket.recv(1024)
            if end is None:
                end = time.time()
            break
        except socket.timeout:
            continue

        break
    # while sent < settings['symbols'] * settings['max_redundancy'] / 100:
    #     packet = encoder.write_payload()
    #     send(send_socket, packet, address)
    #     sent += 1

    #     try:
    #         control_socket.recv(1024)
    #         if end is None:
    #             end = time.time()
    #         break
    #     except socket.timeout:
    #         continue

    # if no ack was received we sent all packets
    if end is None:
        end = time.time()

    control_socket.close()
    f.close()

    # size = encoder.block_size() * (float(sent) / settings['symbols'])
    # seconds = end - start
    # print("Sent {0} packets, {1} kB, in {2}s, at {3:.2f} kb/s.".format(
    #     sent, size / 1000, seconds, size * 8 / 1000 / seconds))


def receive_data(settings, role):
    """Receive data from the other node."""

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set receiving sockets
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_socket.settimeout(settings['timeout'])
    data_socket.bind(('', settings['data_port']))

    if role == 'client':
        address = (settings['server_ip'], settings['server_control_port'])
        send_settings(settings)
    else:  # server
        address = (settings['client_ip'], settings['client_control_port'])
        
        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("Settings OK received")

        send(send_socket, "settings OK, receiving", address, TYPE_STRING)

    # Decode coded packets
    received = 0
    start = time.time()
    end = None
    with open('received_file.jpg', 'wb') as f:
        print("[{}]: ".format(str(datetime.datetime.now())), end='')
        print("Server file opened...")

        while True:
            try:
                print("[{}]: ".format(str(datetime.datetime.now())), end='')
                print("Receiving file...")            

                packet = data_socket.recv(1024)

                if not packet:
                    break

                f.write(packet)
            except socket.timeout:
                break # no more data arriving

        send(send_socket, "Stop sending", address, TYPE_STRING) # force stop sending
    # while 1:
    #     try:
    #         packet = data_socket.recv(settings['symbol_size'] + 100)

    #         if not decoder.is_complete():
    #             decoder.read_payload(packet)
    #             received += 1

    #         if decoder.is_complete():
    #             if end is None:
    #                 end = time.time()  # stopping time once
    #             send(send_socket, "Stop sending", address, TYPE_STRING)

    #     except socket.timeout:
    #         break  # no more data arriving

    # in case we did not complete
    if end is None:
        end = time.time()

    data_socket.close()

    #if not decoder.is_complete():
    #    print("Decoding failed")

    # size = decoder.block_size() * (float(received) / settings['symbols'])
    # seconds = end - start
    # print("Received {0} packets, {1}kB, in {2}s, at {3:.2f} kb/s.".format(
    #     received,
    #     size / 1000,
    #     seconds,
    #     decoder.block_size() * 8 / 1000 / seconds
    # ))


def send_settings(settings):
    """
    Send settings to server.

    This function blocks until confirmation received that settings
    was correctly received.
    """
    control_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    control_socket.settimeout(settings['timeout'])
    control_socket.bind(('', settings['client_control_port']))

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_address = (settings['server_ip'], settings['settings_port'])

    message = json.dumps(settings)
    ack = None
    address = ''
    while ack is None:
        # Send settings
        send(send_socket, message, send_address, TYPE_STRING)
        # Waiting for respons
        try:
            ack, address = receive(control_socket, 1024)  # Server ack
        except socket.timeout:
            print("Timeout - server not responding to settings.")

    control_socket.close()


def send(socket, message, address, type):
    """
    Send message to address using the provide socket.

    Works for both python2 and python3

    :param socket: The socket to use.
    :param message: The message to send.
    :param address: The address to send to.
    """
    if type == TYPE_STRING:
        if sys.version_info[0] == 2:
            message = message
        else:
            if isinstance(message, str):
                message = bytes(message, 'utf-8')
    socket.sendto(message, address)


def receive(socket, number_of_bytes):
    """
    Receive an amount of bytes.

    Works for both python2 and python3

    :param socket: The socket to use.
    :param number_of_bytes: The number of bytes to receive.
    """
    data, address = socket.recvfrom(number_of_bytes)
    if sys.version_info[0] == 2:
        return data, address
    else:
        if isinstance(data, bytes):
            return str(data, 'utf-8'), address

if __name__ == "__main__":
    main()
