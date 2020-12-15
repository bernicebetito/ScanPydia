#! /usr/bin/env python
from scapy.all import *
from signal import signal, SIGINT
from sys import exit
import argparse
import time
import socket

"""
print_border(to_printA, to_printB, numbers)
A function that prints the borders and others

to_printA - the title to be printed
to_printB - the subtitle/s to be printed
numbers - signifies what to print
"""


def print_border(to_printA, to_printB, numbers):
    for i in numbers:
        if i == 0:
            print("{:<18}xx{:<10}xx{:<10}xx{:<18}xx{:<12}xx{:<11}".format(
                'xxxxxxxxxxxxxxxxxx', 'xxxxxxxxxx', 'xxxxxxxxxx', 'xxxxxxxxxxxxxxxxxx',
                'xxxxxxxxxxxx', 'xxxxxxxxxxx'
            ))
        if i == 1:
            print("{:<18}--{:<10}--{:<10}--{:<18}--{:<12}--{:<11}".format(
                '------------------', '----------', '----------', '------------------',
                '------------', '-----------'
            ))

        if i == 2:
            print("{:<18}  {:<10}  {:<10}  {:<18}  {:<12}  {:<11}".format(
                '                  ', '          ', '          ', '                  ',
                '            ', '           '
            ))

        if i == 3:
            print("{:<20}  {:<10}  {:<20}  {:<10}  {:<20}".format(
                '                    ', '          ', to_printA, '          ',
                '                    '
            ))

        if i == 4:
            print('\nTarget Host = IP Address Entered')
            print('\nNumber of Packets = Total # of packets sent to the target host')
            print('\nResponse to Echo Request (*) = # of packets containing Echo-Reply of the target host')
            print('\nNo Response = Packets unanswered by the target host')

        if i == 5:
            print("\n{:<15}  {:<50}  {:<15}".format(
                '               ', '   Packet/s were %s with the following details:  ' % to_printB, '               '
            ))

        if i == 6:
            print('\nTarget Host = IP Address Entered')
            print('\nPort Number = Port Number selected to do a TCP Scan to')
            print('\nRequest Packet Sent = # of packets sent and the flags sent with the packet/s')
            print('\nResponse Packet Received (*) = # of packets received and the flags\nreceived with the packet/s')
            print('\nResponse Packet Sent = # of packets sent and the flags sent with the packet/s')

        if i == 7:
            print("\n{:<15}  {:<50}  {:<15}".format(
                '               ', '       Information needed for all Types:         ', '               '
            ))
            print('\n  IP - IP Address of the Target Host')
            print('\n  -p - Port number to scan')


"""
get_version()
A function that prints a short write-up about ScanPydia.
"""


def get_version():
    print_border('     ScanPydia', '', [0, 2, 3])
    print("\n{:<15}  {:<50}  {:<15}".format(
        '               ', 'Created by: Bernice Marie M. Betito NSSECU2 - S12', '               '
    ))
    print_border('', '', [2, 1])
    print('\t\tScanPydia is a Network Scanning Tool created by Bernice Betito')
    print('\tin order to accomplish her requirements for Advanced and Offensive')
    print('\tSecurity (NSSECU2). The name is a combination of three words, Scan,')
    print('\tPython, and Encyclopedia. Scan came from the project requirement, which')
    print('\tis a Network Scanning Tool, Python is the programming language to be')
    print('\tused, and lastly, Encyclopedia came from the idea that all the needed')
    print('\tinformation would be provided regarding the scanned hosts and ports.\n\n')
    print('\t\tThe goal of ScanPydia is to be able to do Network Scanning. This')
    print('\tincludes ICMP Echo Request, TCP Connect Scan, TCP SYN (Half-Open) Scan,')
    print('\tXmas Scan, FIN Scan, Null Scan, and ACK Scan. In order to be able to do')
    print('\tso, an additional library/tool is utilized which is called Scapy. Scapy')
    print('\tis a powerful program and library which could be used when dealing with')
    print('\tnetwork packets.')
    print_border('', '', [0])


"""
get_time(start)
A function that gets the total time spent by the program and then prints the result.

start - The time that the program started executing
"""


def get_time(start):
    total = time.time() - start
    print_border('', '', [1])
    print("{:<15}  {:<50}  {:<15}".format(
        '               ', '       Total Time Spent: %f' % total, '               '
    ))
    print_border('', '', [1])


"""
icmp_echo(ip, repeat)
A function that performs ICMP Echo Request and gives the user useful information
about the exchange of packets between the user and the target host.

ip - IP Address of Target Host
repeat - number of packets to be sent
"""


def icmp_echo(ip, repeat):
    try:
        # Packet details
        ip_layer = IP(dst=ip)
        icmp_layer = ICMP(type=8)
        single = ip_layer / icmp_layer

        # Lists for the packets sent and received
        positive = []  # List for the packets who received a response
        negative = []  # List for the packets who did not receive a response
        packets = []  # List of packets to be sent

        # Adding packets to the list to be sent to the target host
        for i in range(repeat):
            packets.append(single)

        # Prints the border
        print_border('ICMP ECHO REQUEST', ' ', [0, 2, 3, 2, 0])
        print('\n\n')

        # Send and receive the packets and print the information provided by Scapy
        print_border('1. Scapy Information', ' ', [1, 3, 1])
        ans, unans = sr(packets, retry=0, timeout=1)

        # Divide the packets into two: one list for those with a response and one list for those without
        for responded in ans:
            positive.append(responded)
        for no_response in unans:
            negative.append(no_response)

        # Prints the explanation for the information provided by Scapy
        print_border(' Info Explained', ' ', [1, 3, 4, 1])
        print("  {:<18} | {:<10} | {:<25} | {:<25}".format(
            '                  ', '  Number  ', '                         ', '                         '
        ))
        print("  {:<18} | {:<10} | {:<25} | {:<25}".format(
            '                  ', '    of    ', 'Response to Echo Requests', '                         '
        ))
        print("  {:<18} | {:<10} | {:<25} | {:<25}".format(
            '   Target Host    ', ' Packets  ', '           (*)           ', 'Packets without Response'
        ))
        print("--{:<18} | {:<10} | {:<25} | {:<25}".format(
            '------------------', '----------', '-------------------------', '-------------------------'
        ))

        print("  {:<18} | {:<10} | {:<25} | {:<25}".format(
            ip, repeat, len(positive), len(negative)
        ))
        print_border(' ', ' ', [1])

        # Prints the details of the packets sent and received
        print('\n\n')
        print_border('2. Packets Details  ', ' ', [1, 3])
        print_border('  Sending Packets   ', 'sent', [1, 3, 5, 1])

        print("  {:<18} | {:<10} | {:<53}".format(
            '                  ', '  Number  ', '                                                     '
        ))
        print("  {:<18} | {:<10} | {:<53}".format(
            '                  ', '    of    ', '                                                     '
        ))
        print("  {:<18} | {:<10} | {:<53}".format(
            '   Target Host    ', ' Packets  ', '                        Type                         '
        ))
        print("--{:<18} | {:<10} | {:<25}---{:<25}".format(
            '------------------', '----------', '-------------------------', '-------------------------'
        ))
        print("  {:<18} | {:<10} | {:<53}".format(
            ip, repeat, '  8 - ICMP Echo Request                              '
        ))
        print_border(' ', ' ', [1])

        print_border('Receiving Packets ', 'received', [3, 5, 1])
        print("  {:<18} | {:<10} | {:<53}".format(
            '                  ', '  Number  ', '                                                     '
        ))
        print("  {:<18} | {:<10} | {:<53}".format(
            '                  ', '    of    ', '                                                     '
        ))
        print("  {:<18} | {:<10} | {:<53}".format(
            '   Target Host    ', ' Packets  ', '                        Type                         '
        ))
        print("--{:<18} | {:<10} | {:<25}---{:<25}".format(
            '------------------', '----------', '-------------------------', '-------------------------'
        ))
        print("  {:<18} | {:<10} | {:<53}".format(
            ip, len(positive), '  0 - ICMP Echo Reply                                '
        ))
        print_border(' ', ' ', [1])
    except socket.gaierror:
        raise ValueError('Target Host {} could not be resolved.'.format(ip))


"""
print_tcp(first_state, first_flag, second_state, second_flag, third_state, third_flag, ip, port, num)
A function that prints the TCP scan results

first_state - What the first packet sent means
first_flag - What was the set flag for the first packet
second_state - What the second packet sent means
second_flag - What was the set flag for the second packet
third_state - What the third packet sent means
third_flag - What was the set flag for the third packet
ip - IP Address of the Target Host
port - Port number to scan
num - Signifies the type of scan to perform
    - Could be the following:
        1 - TCP Connect Scan
        2 - TCP SYN (Half-Open) Scan
        3 - Xmas Scan
        4 - FIN Scan
        5 - Null Scan
        6 - ACK Scan
"""


def print_tcp(first_state, first_flag, second_state, second_flag, third_state, third_flag, ip, port, num):
    # An explanation of the information provided by Scapy
    print_border(' Info Explained', ' ', [1, 3, 6, 1])
    print(" {:<18} | {:<8} | {:<15} | {:<18} | {:<15}".format(
        '                  ', '  Port  ', ' Request Packet', '  Response Packet ', 'Response Packet'
    ))
    print(" {:<18} | {:<8} | {:<15} | {:<18} | {:<18}".format(
        '   Target Host    ', ' Number ', '     Sent      ', '   Received (*)   ', '     Sent      '
    ))
    print(" {:<18} | {:<8} | {:<15} | {:<18} | {:<18}".format(
        '------------------', '--------', '---------------', '------------------', '---------------'
    ))
    print(" {:<18} | {:<8} | {:<15} | {:<18} | {:<18}".format(
        ip, port, '     ' + first_flag, second_flag, third_flag
    ))
    print_border(' ', ' ', [1])

    # An explanation of all the packets exchanged between the target host and the user
    print('\n\n')
    print_border('2. Packets Details  ', ' ', [1, 3])
    print_border('    First Packet    ', 'sent', [1, 3, 5, 1])
    print(" {:<25} | {:<26} | {:<31}".format(
        '       Target Host       ', '        Port Number       ', '            Flag Set           '
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '-------------------------', '--------------------------', '------------------------------'
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '     ' + ip, port, '     ' + first_state
    ))
    print_border(' ', ' ', [1])

    print_border('   Second Packet    ', 'received', [3, 5, 1])
    print(" {:<25} | {:<26} | {:<31}".format(
        '       Target Host       ', '        Port Number       ', '            Flag Set           '
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '-------------------------', '--------------------------', '------------------------------'
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '     ' + ip, port, '     ' + second_state
    ))
    print_border(' ', ' ', [1])

    if 1 <= num <= 2:
        print_border('    Third Packet    ', 'sent', [3, 5, 1])
        print(" {:<25} | {:<26} | {:<31}".format(
            '       Target Host       ', '        Port Number       ', '            Flag Set           '
        ))
        print(" {:<25} | {:<26} | {:<31}".format(
            '-------------------------', '--------------------------', '------------------------------'
        ))
        print(" {:<25} | {:<26} | {:<31}".format(
            '     ' + ip, port, '     ' + third_state
        ))
        print_border(' ', ' ', [1])


"""
tcp_scan(ip, port, flag, num)
A function that performs a singular TCP Scan chosen by the user and gives the user
useful information about the exchange of packets between he user and the target host.

ip - IP Address of Target Host
port - Port Number to scan
flag - Flag/s to send
num - Signifies the type of scan to perform
    - Could be the following:
        1 - TCP Connect Scan
        2 - TCP SYN (Half-Open) Scan
        3 - Xmas Scan
        4 - FIN Scan
        5 - Null Scan
        6 - ACK Scan
"""


def tcp_scan(ip, port, flag, num):
    try:
        # Creation of the first packet
        first_packet = IP(dst=ip) / TCP(dport=port, flags=flag)

        first_flag = 'No Packet'
        first_state = 'No Packet'
        second_flag = 'No Packet'
        second_state = 'No Packet'
        third_flag = 'No Packet'
        third_state = 'No Packet'

        # Setting of values and printing of borders and headers under each type of scan
        # first_flag: the first flag that was sent will be printed and shown to the user
        # first_state: an explanation of what the first flag was for
        # final_flag: third and final flag to be sent ('none' for those who would not be sending a third packet)
        # third_flag: the third flag that was sent will be printed and shown to the user
        # third_state: an explanation of what the third flag was for
        if num == 1 or num == 7:
            if num == 1:
                print_border('TCP CONNECT SCAN', ' ', [0, 2, 3, 2, 0])
            else:
                print_border('   ALL TCP SCANS  ', ' ', [0, 2, 3, 2, 0])
                print_border('', '', [1])
                print("{:<15}  {:<50}  {:<15}".format(
                    '               ', '               Target IP: %s' % ip, '               '
                ))
                print("{:<15}  {:<50}  {:<15}".format(
                    '               ', '             Port Number: %d' % port, '               '
                ))
                print_border('', '', [1])
            first_flag = '1 - S'
            first_state = 'SYN: Initiating Connect'
            final_flag = 'RA'
            third_state = 'RA: RST and ACK'
        elif num == 2 or num == 8:
            if num == 2:
                print_border('TCP SYN (Half-Open) SCAN', ' ', [0, 2, 3, 2, 0])
            first_flag = '1 - S'
            first_state = 'SYN: Initiating Syn'
            final_flag = 'R'
            third_state = 'R: RST'
        elif num == 3 or num == 9:
            if num == 3:
                print_border('XMAS SCAN', ' ', [0, 2, 3, 2, 0])
            first_flag = '1 - FPU'
            first_state = 'FPU: Initiate Xmas'
            final_flag = 'none'
            third_flag = 'No Packet'
            third_state = 'No Packet'
        elif num == 4 or num == 10:
            if num == 4:
                print_border('FIN SCAN', ' ', [0, 2, 3, 2, 0])
            first_flag = '1 - F'
            first_state = 'F: Initiate Fin'
            final_flag = 'none'
            third_flag = 'No Packet'
            third_state = 'No Packet'
        elif num == 5 or num == 11:
            if num == 5:
                print_border('NULL SCAN', ' ', [0, 2, 3, 2, 0])
            first_flag = '1 - Null'
            first_state = 'Null: Initiate Null'
            final_flag = 'none'
            third_flag = 'No Packet'
            third_state = 'No Packet'
        elif num == 6 or num == 12:
            if num == 6:
                print_border('ACK SCAN', ' ', [0, 2, 3, 2, 0])
            first_flag = '1 - A'
            first_state = 'ACK: Initiate Ack'
            final_flag = 'none'
            third_flag = 'No Packet'
            third_state = 'No Packet'

        # Sending the first packet through Scapy, printing the information
        # provided by Scapy
        if num <= 7:
            print('\n\n')
            print_border('1. Scapy Information', ' ', [1, 3, 1])
        second_packet = sr1(first_packet, timeout=1, retry=0)

        # Analyzing the second packet and identifying the next step
        # second_flag: the second flag that was sent will be printed and shown to the user
        # second_state: an explanation of what the second flag was for
        # third_flag: the third flag that was sent will be printed and shown to the user
        # third_state: an explanation of what the third flag was for
        if 1 <= num <= 2 or 7 <= num <= 8:
            if str(type(second_packet)) == "<class 'NoneType'>":
                second_flag = '0 - No Response'
                second_state = 'Filtered'
                third_flag = 'No Packet'
                third_state = 'No Packet'
            elif second_packet.haslayer(TCP):
                if second_packet[TCP].flags == 'R' or second_packet[TCP].flags == 'RA' or second_packet[TCP].flags == 'AR':
                    second_flag = '1 - {}'.format(second_packet[TCP].flags)
                    second_state = 'Port is Closed'
                    third_flag = 'No Packet'
                    third_state = 'No Packet'
                elif second_packet[TCP].flags == 'SA' or second_packet[TCP].flags == 'AS':
                    second_flag = '1 - {}'.format(second_packet[TCP].flags)
                    second_state = 'Port is Open'

                    # Creation of the last packet to be sent
                    last = TCP(dport=port, flags=final_flag, seq=second_packet.ack, ack=second_packet.seq + 1)
                    third_packet = IP(dst=ip) / last

                    # Sending the last packet
                    send(third_packet)

                    third_flag = '1 - {}'.format(final_flag)
            elif second_packet.haslayer(ICMP):
                if int(second_packet[ICMP].type) == 3 and int(second_packet[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                    second_flag = '1 - {} (ICMP)'.format(second_packet[ICMP].type)
                    second_state = 'Filtered'
                    third_flag = 'No Packet'
                    third_state = 'No Packet'
        elif 3 <= num <= 5 or 9 <= num <= 11:
            if str(type(second_packet)) == "<class 'NoneType'>":
                second_flag = '0 - No Response'
                second_state = 'Open/Filtered'
            elif second_packet.haslayer(TCP):
                if second_packet[TCP].flags == 'R' or second_packet[TCP].flags == 'RA' or second_packet[TCP].flags == 'AR':
                    second_flag = '1 - {}'.format(second_packet[TCP].flags)
                    second_state = 'Port is Closed'
            elif second_packet.haslayer(ICMP):
                if int(second_packet[ICMP].type) == 3 and int(second_packet[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                    second_flag = '1 - {} (ICMP)'.format(second_packet[ICMP].type)
                    second_state = 'Filtered'
        elif num == 6 or num == 12:
            if str(type(second_packet)) == "<class 'NoneType'>":
                second_flag = '0 - No Response'
                second_state = 'Filtered'
            elif second_packet.haslayer(ICMP):
                if int(second_packet[ICMP].type) == 3 and int(second_packet[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                    second_flag = '1 - {} (ICMP)'.format(second_packet[ICMP].type)
                    second_state = 'Filtered'
            elif second_packet.haslayer(TCP):
                if second_packet[TCP].flags == 'R':
                    second_flag = '1 - {}'.format(second_packet[TCP].flags)
                    second_state = 'Unfiltered'
        if 1 <= num <= 6:
            print_tcp(first_state, first_flag, second_state, second_flag, third_state, third_flag, ip, port, num)
        else:
            tcp_list = [first_state, first_flag, second_state, second_flag, third_state, third_flag]
            return tcp_list
    except socket.gaierror:
        raise ValueError('Target Host {} could not be resolved.'.format(ip))


def all_scans(ip, port):
    try:
        scans = ['  Connect ', '   SYN    ', '   Xmas   ', '   FIN    ', '   Null   ', '   ACK    ']

        # Get the results
        connect = tcp_scan(ip, port, 'S', 7)
        syn = tcp_scan(ip, port, 'S', 8)
        xmas = tcp_scan(ip, port, 'FPU', 9)
        fin = tcp_scan(ip, port, 'F', 10)
        null = tcp_scan(ip, port, '', 11)
        ack = tcp_scan(ip, port, 'A', 12)

        # Collate all the states of the packets into a list
        states = []
        for i in range(0, len(connect), 2):
            states.append(connect[i])
        for i in range(0, len(syn), 2):
            states.append(syn[i])
        for i in range(0, len(xmas), 2):
            states.append(xmas[i])
        for i in range(0, len(fin), 2):
            states.append(fin[i])
        for i in range(0, len(null), 2):
            states.append(null[i])
        for i in range(0, len(ack), 2):
            states.append(ack[i])

        # Collate all the flags of the packets into a list
        flags = []
        for i in range(1, len(connect), 2):
            flags.append(connect[i])
        for i in range(1, len(syn), 2):
            flags.append(syn[i])
        for i in range(1, len(xmas), 2):
            flags.append(xmas[i])
        for i in range(1, len(fin), 2):
            flags.append(fin[i])
        for i in range(1, len(null), 2):
            flags.append(null[i])
        for i in range(1, len(ack), 2):
            flags.append(ack[i])

        # An explanation of the information provided by Scapy
        print_border(' Info Explained', ' ', [1, 3])
        print('\n\nTCP Scan = Type of TCP Scan')
        print('\nFirst Packet = Flag Received with the First Packet')
        print('\nSecond Packet = Flag Received with the Second Packet')
        print('\nThird Packet = Flag Received with the Third Packet')
        print_border('', '', [1])
        print("  {:<10} | {:<22} | {:<23} | {:<23}".format(
            ' TCP Scan ', '     First Packet     ', '     Second Packet     ', '      Third Packet     '
        ))
        for a in range(0, len(flags), 3):
            print("  {:<10} | {:<22} | {:<23} | {:<23}".format(
                '----------', '----------------------', '-----------------------', '-----------------------'
            ))
            print("  {:<10} | {:<22} | {:<23} | {:<23}".format(
                scans[int(a / 3)], '     ' + flags[a], flags[a + 1], '     ' + flags[a + 2]
            ))
        print_border(' ', ' ', [1])

        # An explanation of the packets exchanged between the user and Target Host
        print('\n\n')
        print_border('2. Packets Details  ', ' ', [1, 3, 1])
        print("  {:<10} | {:<26} | {:<23} | {:<19}".format(
            ' TCP Scan ', '       First Packet       ', '     Second Packet     ', '   Third Packet   '
        ))
        for a in range(0, len(states), 3):
            print("  {:<10} | {:<26} | {:<23} | {:<19}".format(
                '----------', '--------------------------', '-----------------------', '-------------------'
            ))
            print("  {:<10} | {:<26} | {:<23} | {:<19}".format(
                scans[int(a / 3)], states[a], states[a + 1], states[a + 2]
            ))
        print_border(' ', ' ', [1])
    except socket.gaierror:
        raise ValueError('Target Host {} could not be resolved.'.format(ip))


"""
full_list()
A function that prints out all the available scans in ScanPydia
"""


def full_list():
    # Print the borders/header
    print_border('Scans in ScanPydia', ' ', [0, 2, 3, 2, 0])

    # Print the ICMP Echo Request information
    print_border('ICMP ECHO REQUEST', ' ', [1, 3, 1])
    print(" {:<25} | {:<26} | {:<31}".format(
        '    Needed Information   ', 'What is Sent to the Target', '    What could be Received    '
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '-------------------------', '--------------------------', '------------------------------'
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        'IP - IP Address of Target', 'Packets signaling ICMP    ', 'Packets signaling ICMP Echo   '
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '-c - Number of Packets to', 'Echo Request              ', 'Reply (Acknowledging the Echo '
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '     send to the Target  ', '     (ICMP Type = 8)      ', 'Request/s sent)               '
    ))
    print(" {:<25} | {:<26} | {:<31}".format(
        '                         ', '                          ', '       (ICMP Type = 0)        '
    ))
    print_border(' ', ' ', [1])
    print('\n\n')

    # Print the different types of TCP Scans and their respective information
    print_border('     TCP SCANS', ' ', [1, 3, 7, 1])
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        ' Type of  ', '                  ', 'What is sent to the Target ', ' What could be Received'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        ' TCP Scan ', '    Flag/s Set    ', '(1st & 3rd Packet Contents)', '  (2nd Packet Contents)'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '----------', '------------------', '---------------------------', '-----------------------'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '  Connect ', '   S - SYN Flag   ', 'FIRST PACKET: SYN Flag (S) ', 'Filtered, R/RA(Closed),'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', 'THIRD PACKET: RST/ACK (RA) ', 'SA (Open)              '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '----------', '------------------', '---------------------------', '-----------------------'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '    SYN/  ', '   S - SYN Flag   ', ' FIRST PACKET: SYN Flag (S)', 'Filtered, R/RA(Closed),'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        ' Half-Open', '                  ', ' THIRD PACKET: RST (R)     ', 'SA (Open)              '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '----------', '------------------', '---------------------------', '-----------------------'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '   Xmas   ', '  FPU - FIN, PSH, ', '  FIRST PACKET: FPU Flags  ', 'Open/Filtered, R/RA    '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '     URG Flags    ', '                           ', '(Closed), Filtered,    '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', '                           ', 'No Response (Open)     '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '----------', '------------------', '---------------------------', '-----------------------'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '   FIN    ', '   F - FIN Flag   ', '  FIRST PACKET: FIN Flag   ', 'Open/Filtered, R/RA    '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', '                           ', '(Closed), Filtered,    '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', '                           ', 'No Response (Open)     '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '----------', '------------------', '---------------------------', '-----------------------'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '   Null   ', '   No flags set   ', '  FIRST PACKET: No flags   ', 'Open/Filtered, R/RA    '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', '                           ', '(Closed), Filtered,    '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', '                           ', 'No Response (Open)     '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '----------', '------------------', '---------------------------', '-----------------------'
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '   ACK    ', '   A - ACK Flag   ', '  FIRST PACKET: ACK Flag   ', 'R (Unfiltered),        '
    ))
    print("  {:<10} | {:<18} | {:<27} | {:<23}".format(
        '          ', '                  ', '                           ', 'Filtered               '
    ))
    print_border(' ', ' ', [1])


"""
lobby()
A function that brings the user to the lobby / prints the help page
"""


def lobby():
    print_border('', '', [0, 2])
    print("{:<15}    {:<50}  {:<15}".format(
        '               ', '             Welcome to ScanPydia!               ', '               '
    ))
    print("\n{:<15}    {:<50}  {:<15}".format(
        '               ', 'Created by: Bernice Marie M. Betito NSSECU2 - S12', '               '
    ))
    print_border('', '', [2, 1])
    print("\n{:<15}   {:<50}  {:<15}".format(
        '               ', '   To use ScanPydia, use the following format:   ', '               '
    ))
    print("\n{:<15}    {:<50}  {:<15}".format(
        '               ', 'sudo python3 ScanPydia.py -<?> <positional args> ', '               '
    ))
    print("\n{:<15}{:<50}  {:<15}".format(
        '               ', 'Wherein -<?> and <positional args> are any of the following:', '               '
    ))
    print('\nTo do an ICMP Echo Request:')
    print('\t-i     - Start an ICMP Echo Request')
    print('\t-c <#> - Number of packets to send to the Target Host')
    print('\tIP     - (Positional argument) IP address of the Target Host')

    print('\nTo do a TCP Scan:')
    print('\t-p <#> - The port number to scan')
    print('\t-t     - Do a TCP Connect Scan')
    print('\t-s     - Do a TCP SYN (Half-Open) Scan')
    print('\t-x     - Do an Xmas Scan')
    print('\t-f     - Do a FIN Scan')
    print('\t-n     - Do a Null Scan')
    print('\t-a     - Do an ACK Scan')
    print('\t-ALL   - Do all TCP Scans available')
    print('\tIP     - (Positional argument) IP address of the Target Host')

    print('\nOther options:')
    print('\t-v     - Know more about ScanPydia')
    print('\t-T     - Find out how much time ScanPydia spent executing')
    print('\t-l     - See a full list and details of all the scans available')
    print('\t-h     - See a complete guide on how to use ScanPydia')
    print_border('', '', [0])


def main():
    # Time when the program started
    start = time.time()

    # For the command line arguments
    parser = argparse.ArgumentParser(add_help=False)

    # Different options available
    parser.add_argument('-v', '--version', action='store_true', help='Know more about ScanPydia')
    parser.add_argument('-T', '--time', action='store_true', help='Time spent by ScanPydia')
    parser.add_argument('-l', '--list', action='store_true',
                        help='See the full list and details of the available scans')
    parser.add_argument('-h', '--help', action='store_true', help='See a complete guide on how to use ScanPydia')

    # Needed arguments in doing ICMP Echo Request
    parser.add_argument('-i', '--icmp', action='store_true', help='Do an ICMP Echo Request')
    parser.add_argument('-c', '--packets', type=int, help='Send multiple packets')
    parser.add_argument('IP', nargs='?', help='IP Address of Target Host', default='none')

    # Needed arguments in doing TCP Scans
    parser.add_argument('-p', '--port', type=int, help='Port number')
    parser.add_argument('-ALL', '--all', action='store_true', help='Do all TCP Scans')
    parser.add_argument('-t', '--connect', action='store_true', help='Do a TCP Connect Scan')
    parser.add_argument('-s', '--syn', action='store_true', help='Do a TCP SYN (Half-Open) Scan')
    parser.add_argument('-x', '--xmas', action='store_true', help='Do an Xmas Scan')
    parser.add_argument('-f', '--fin', action='store_true', help='Do a FIN Scan')
    parser.add_argument('-n', '--null', action='store_true', help='Do a Null Scan')
    parser.add_argument('-a', '--ack', action='store_true', help='Do a TCP ACK Scan')

    args = parser.parse_args()

    # Signals when a command is selected
    valid = 1

    # see if an IP address was entered
    if args.IP != 'none':
        # Check if the IP address entered is valid
        address = args.IP
        countA = address.count(".")
        if countA != 3:
            try:
                address = socket.gethostbyname(args.IP)
            except socket.gaierror:
                print('Target Host "{}" could not be resolved. Please try again.'.format(args.IP))
                exit(0)

        ip_add = list(address.split("."))
        for i in ip_add:
            temp = int(i)
            if temp < 0 or temp > 255:
                print('Target Host "{}" could not be resolved. Please try again.'.format(args.IP))
                exit(0)

        # Go to the ICMP Echo Request Function
        if args.icmp:
            if args.port:
                print('Port number detected when not allowed. Please try again.')
                exit(0)
            else:
                if args.packets:
                    packets = args.packets
                else:
                    packets = 1
                valid = 0
                icmp_echo(address, packets)
        if args.port:
            if args.icmp:
                print('Port number detected when not allowed. Please try again.')
                exit(0)
            elif 0 < args.port < 65536:
                port = args.port
                # Check and proceed with the TCP scan chosen
                if args.connect:
                    valid = 0
                    tcp_scan(address, port, 'S', 1)
                if args.syn:
                    valid = 0
                    tcp_scan(address, port, 'S', 2)
                if args.xmas:
                    valid = 0
                    tcp_scan(address, port, 'FPU', 3)
                if args.fin:
                    valid = 0
                    tcp_scan(address, port, 'F', 4)
                if args.null:
                    valid = 0
                    tcp_scan(address, port, '', 5)
                if args.ack:
                    valid = 0
                    tcp_scan(address, port, 'A', 6)
                if args.all:
                    valid = 0
                    all_scans(address, port)
            else:
                print('Invalid port number entered. Please try again.')
                exit(0)

    # see if any of the options were selected
    if args.version:
        valid = 0
        get_version()
    if args.time:
        valid = 0
        get_time(start)
    if args.list:
        valid = 0
        full_list()
    if args.help or valid == 1:
        valid = 0
        lobby()


"""
handler(signal_received, frame)
A function that allows the program to exit gracefully.

signal_received - SIGINT (Signals an interrupt from the keyboard (CTRL and C))
"""


def handler(signal_received, frame):
    print('\n\n')
    print_border('Exiting ScanPydia...', '', [1, 3, 1])
    exit(0)


if __name__ == '__main__':
    try:
        signal(SIGINT, handler)
        main()
    except KeyboardInterrupt:
        pass
