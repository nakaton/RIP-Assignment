"""
RIP Assignment

    sys.argv[1]: configure file for each router
"""
import sys
import configparser
import socket
import threading
import random
import select
import queue
import time

# Instance Variable
LOCAL_HOST = '127.0.0.1'
MAX_METRIC = 16

HEADER_COMMAND = 2
HEADER_VERSION = 2
MUST_BE_ZERO = 0
ADDRESS_FAMILY_IDENTIFIER = 2

# Timer Define
periodic_timer = None
timeout_timer = None
garbage_collection_timer = None

# Timer control
PERIODIC_TIME = 10  # default 30
TIME_OUT = 50  # default 180
GARBAGE_COLLECT_TIME = 30  # default 120
CHECK_TIME = 5  # Value can be adjusted (purpose is to to check timeout and garbage collection for routing table)

# Router Config Data
my_router_id = None
input_ports = []
outputs = []

# Initiate UDP sockets for input ports
sockets = []

# Initiate routing table
routing_table = []

# send update response control
is_periodic_send_on_process = False


#########################################################################################
#                      <Beginning stage>: Read Configuration File                       #
#########################################################################################
def read_config(config_file):
    """Read Configuration File"""
    config = configparser.ConfigParser()
    config.read(config_file)  # Configure File from Shell Parameter

    # Config file check
    check_result = config_file_check(config)

    if check_result:
        global my_router_id, input_ports, outputs
        my_router_id = int(config.get('Settings', 'router-id'))
        input_ports = config.get('Settings', 'input-ports').split(', ')
        outputs = config.get('Settings', 'outputs').split(', ')

        # add self into routing table
        table_line = {
            "destination": my_router_id,
            "metric": 0,
            "next_hop_id": my_router_id,
            "route_change_flag": False,
            "timeout": None,
            "garbage_collect": None
        }

        routing_table.append(table_line)

    return check_result


#########################################################################################
#                         <Next stage>: Bind Socket for inputPorts                      #
#########################################################################################
def bind_socket():
    """Bind socket for each input port"""
    if len(input_ports) > 0:
        for input_port in input_ports:
            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.bind((LOCAL_HOST, int(input_port)))
                sockets.append(udp_socket)
                print('Bind socket on port: ' + str(input_port))
            except socket.error as msg:
                print('Failed to bind socket on port' + str(input_port) + '. Message: ' + str(msg))
                sys.exit()


#########################################################################################
#                   <Final stage>: infinite loop for incoming events                    #
#########################################################################################
def event_handler():
    """Operation for coming event"""

    print(">>> Event Handler Start")

    # Initiate Periodic Timer Unsolicited RIP Response
    init_timer()

    # Start a Timeout timer for this specific entry
    init_timeout_timer()

    # Start a Garbage Collection timer for this specific entry
    init_garbage_collection_timer()

    # print('Current active thread: {}'.format(threading.activeCount()))

    message_queues = {}

    # RIP daemon to keep monitoring the incoming data
    while True:
        readable, writable, exceptional = select.select(sockets, [], sockets)

        # get data from neighbour router
        for readable_item in readable:
            read_data = readable_item.recvfrom(1024)  # result: tuple(data, address)
            data = read_data[0]
            address = read_data[1]

            # print("read_data from readable: " + str(read_data))
            # print("receive from %s:%s" % (address, data))

            message_queues[address[1]] = queue.Queue()  # Create message queue for each connection

            if data:
                message_queues[address[1]].put(data)

        # process received data from neighbour router
        for key in message_queues.keys():
            try:
                q = message_queues[key]
                # extract data from each message queue
                while not q.empty():
                    q_data = q.get_nowait()  # Remove and return an item from the queue without blocking.
                    # check the consistency fo the packet data
                    if data_consistency_check(q_data):
                        parse_packet(q_data)

            except KeyError:
                continue


#########################################################################################
#                                RIP Packet Create Relate                               #
#########################################################################################
def create_output_packet(is_update_only):
    """Create send packet by combining common header and RIP Entry"""

    packets = {}

    header = create_packet_header()  # Create RIP packet common header

    for output in outputs:
        neighbour = output.split('-')[2]
        packet = header

        if len(routing_table) > 0:
            for table_line in routing_table:
                # When trigger update, only send out route changed entry
                if is_update_only:
                    if table_line["route_change_flag"] == "False":
                        continue

                if str(table_line["next_hop_id"]) == neighbour and str(table_line["destination"]) != neighbour:
                    entry = create_packet_rip_entry(table_line["destination"], 16)  # poisoned reverse
                else:
                    entry = create_packet_rip_entry(table_line["destination"], table_line["metric"])

                if entry:
                    packet += entry

            packets[neighbour] = packet

    return packets


#########################################################################################
def create_packet_header():
    """Create common header for the RIP packet"""

    command = HEADER_COMMAND.to_bytes(1, byteorder='big', signed=False)
    version = HEADER_VERSION.to_bytes(1, byteorder='big', signed=False)
    sender = my_router_id.to_bytes(2, byteorder='big', signed=False)

    header = command + version + sender

    return header


#########################################################################################
def create_packet_rip_entry(destination, metric):
    """Creates a RIP Entry for RIP packet"""

    afi = ADDRESS_FAMILY_IDENTIFIER.to_bytes(2, byteorder='big', signed=False)
    must_be_zero1 = MUST_BE_ZERO.to_bytes(2, byteorder='big', signed=False)
    destination = destination.to_bytes(4, byteorder='big', signed=False)
    must_be_zero2 = MUST_BE_ZERO.to_bytes(4, byteorder='big', signed=False)
    next_hop = my_router_id.to_bytes(4, byteorder='big', signed=False)
    metric = int(metric).to_bytes(4, byteorder='big', signed=False)

    entry = afi + must_be_zero1 + destination + must_be_zero2 + next_hop + metric

    return entry


#########################################################################################
#                                Send Out RIP Response                                  #
#########################################################################################
def send_update_response(is_update_only):
    """Send RIP response periodic or by route invalid trigger"""
    readable, writable, exceptional = select.select([], [sockets[0]], [])

    output_socket = writable[0]

    packets = create_output_packet(is_update_only)

    # Once packet have been generated, the route change flags should be cleared.
    clear_route_change_flags()

    # send out unsolicited response
    if packets:
        for output in outputs:
            neighbour = output.split('-')[2]
            if packets[neighbour]:
                output_socket.sendto(packets[neighbour], (LOCAL_HOST, int(output.split('-')[0])))

    print_routing_table("send_unsolicited_response")


#########################################################################################
#                            Receive and Parse RIP Packet                               #
#########################################################################################
def parse_packet(packet):
    """Get routing information out of incoming RIP packet and update routing table"""
    sender = int(packet[2] + packet[3])  # Identified by router id which is set in common header
    number_of_entries = int((len(packet) - 4) / 20)  # common header size: 1 + 1 + 2 = 4 ;   Each Entry size: 20

    sender_entry = get_entry(sender)

    # When sender is not exist in routing table. Create by config outputs data
    if sender_entry:
        # Compare with config metric, update with the smaller metric
        sender_metric = get_config_metric(sender)
        if int(sender_metric) < int(sender_entry["metric"]):
            update_routing_table(sender, sender_metric, sender, route_change=True)
    else:
        sender_metric = get_config_metric(sender)
        add_routing_table(sender, sender_metric, sender)

    sender_entry = get_entry(sender)

    # Modify received packet: next hop into sender & metric into total metric
    entries = packet[4:]
    for i in range(0, number_of_entries):
        received_entry = entries[(i*20):((i+1)*20)]
        destination = int(received_entry[4] + received_entry[5] + received_entry[6] + received_entry[7])
        metric = int(received_entry[16] + received_entry[17] + received_entry[18] + received_entry[19])

        # total metric = metric(self -> sender) + metric(sender -> destination)
        total_metric = int(sender_entry["metric"]) + metric
        if total_metric >= MAX_METRIC:
            total_metric = MAX_METRIC

        # Check whether destination address already exist in routing table
        if is_destination_exist(destination):
            original_destination_entry = get_entry(destination)

            # Check whether next hop is same with original routing table entry
            if int(original_destination_entry["next_hop_id"]) == sender:

                # Directly update routing table by latest info
                if int(original_destination_entry["metric"]) != total_metric:
                    update_routing_table(destination, total_metric, sender, route_change=True)
                else:
                    update_routing_table(destination, total_metric, sender, route_change=False)

            else:
                # Compare original routing entry's metric with received entry's total metric
                if int(original_destination_entry["metric"]) <= total_metric:
                    pass
                else:
                    update_routing_table(destination, total_metric, sender, route_change=True)

        else:
            # Only when destination is valid, add to routing table
            if total_metric < MAX_METRIC:
                add_routing_table(destination, total_metric, sender)


#########################################################################################
#                               Routing Table Operation                                 #
#########################################################################################
def add_routing_table(destination, total_metric, next_hop_id):
    """add new route into routing table"""
    table_line = {
        "destination": destination,
        "metric": total_metric,
        "next_hop_id": next_hop_id,
        "route_change_flag": True,
        "timeout": time.time() + TIME_OUT,
        "garbage_collect": None
    }
    routing_table.append(table_line)
    print_routing_table("add_routing_table")


#########################################################################################
def update_routing_table(destination, total_metric, next_hop_id, route_change):
    """update routing table according according to new received packet"""
    if int(total_metric) >= 16:
        table_line = {
            "destination": destination,
            "metric": total_metric,
            "next_hop_id": next_hop_id,
            "route_change_flag": route_change,
            "timeout": None,
            "garbage_collect": time.time() + GARBAGE_COLLECT_TIME
        }

        index = get_entry_index(destination)
        routing_table[index] = table_line
        print_routing_table("update_routing_table --- total_metric >= 16")

        # Trigger a response due to route invalid
        if is_periodic_send_on_process:
            # suppress triggered update when a regular update is due by the time
            pass
        else:
            send_update_response(is_update_only=True)  # send out updated route only
    else:
        table_line = {
            "destination": destination,
            "metric": total_metric,
            "next_hop_id": next_hop_id,
            "route_change_flag": route_change,
            "timeout": time.time() + TIME_OUT,
            "garbage_collect": None
        }

        index = get_entry_index(destination)
        routing_table[index] = table_line
        print_routing_table("update_routing_table --- total_metric < 16")


#########################################################################################
#                                    Timer Relate                                       #
#########################################################################################
def init_timer():
    """Initiate Periodic Timer for sending unsolicited response"""
    global periodic_timer
    periodic_timer = threading.Timer(PERIODIC_TIME, send_unsolicited_response, [])
    periodic_timer.start()

    # print(">>> Periodic Timer Initiate")


#########################################################################################
def init_timeout_timer():
    """Initiate Timeout Timer for checking route status"""
    global timeout_timer
    timeout_timer = threading.Timer(CHECK_TIME, process_route_timeout, [])
    timeout_timer.start()

    # print(">>> Timeout Timer Initiate")


#########################################################################################
def init_garbage_collection_timer():
    """Initiate Garbage Collection Timer for removing invalid route"""
    global garbage_collection_timer
    garbage_collection_timer = threading.Timer(CHECK_TIME, process_garbage_collection, [])
    garbage_collection_timer.start()

    # print(">>> Garbage Collection Timer Initiate")


#########################################################################################
def send_unsolicited_response():
    """Send unsolicited RIP response periodic"""

    # print(">>> Periodic Timer Start")

    global is_periodic_send_on_process
    is_periodic_send_on_process = True  # periodic send is on process

    send_update_response(is_update_only=False)  # send out entire routing table

    is_periodic_send_on_process = False  # periodic send is finish

    # Create Timer offset
    random_offset = random.randint(-5, 5)
    period = PERIODIC_TIME + random_offset

    global periodic_timer
    periodic_timer.cancel()
    periodic_timer = threading.Timer(period, send_unsolicited_response, [])
    periodic_timer.start()

    # print(">>> Periodic Timer Re-Initiate. " + "Timer period: " + str(period))


#########################################################################################
def process_route_timeout():
    """Process route timeout"""

    # print(">>> Timeout Timer Start")

    for table_line in routing_table:
        destination = table_line["destination"]

        if destination != my_router_id:
            if table_line["timeout"] is None or time.time() < table_line["timeout"]:
                # Entry already updated again after Timeout timer initialized.
                # Or Metric is updated to 16 and trigger garbage collection Timer.
                # Pass and wait next started Timer to process
                pass
            else:
                next_hop_id = table_line["next_hop_id"]
                update_routing_table(destination, MAX_METRIC, next_hop_id, route_change=True)

    # Create Timer offset
    random_offset = random.randint(-5, 5)
    period = CHECK_TIME + random_offset

    global timeout_timer
    timeout_timer.cancel()
    timeout_timer = threading.Timer(period, process_route_timeout, [])
    timeout_timer.start()

    # print(">>> Timeout Timer Re-Initiate. " + "Timer period: " + str(period))


#########################################################################################
def process_garbage_collection():
    """Process garbage collection"""

    # print(">>> Garbage collection Timer Start")

    for table_line in routing_table:
        destination = table_line["destination"]

        if destination != my_router_id:
            if table_line["garbage_collect"] is None or time.time() < table_line["garbage_collect"]:
                # Entry already updated again after Garbage Collection timer initialized.
                # Or route is updated to valid and trigger Timeout Timer.
                # Pass and wait next started Timer to process
                pass
            else:
                entry_index = get_entry_index(destination)
                routing_table.pop(entry_index)  # delete garbage route from routing table

    # Create Timer offset
    random_offset = random.randint(-5, 5)
    period = CHECK_TIME + random_offset

    global garbage_collection_timer
    garbage_collection_timer.cancel()
    garbage_collection_timer = threading.Timer(period, process_garbage_collection, [])
    garbage_collection_timer.start()

    # print(">>> Garbage Collection Timer Re-Initiate. " + "Timer period: " + str(period))


#########################################################################################
#                               Print Routing Table                                     #
#########################################################################################
def print_routing_table(event):
    """Print routing table for each event"""
    print(" ")
    print(">>> " + str(time.asctime(time.localtime(time.time()))) + " On Process Event: " + event)
    print(">>> Routing Table for Router: " + str(my_router_id))
    print("+-----------------------------------------------------------------------------------------+")
    print("| Destination | Metric | Next Hop Id | Route Change |      Timeout      |     Garbage     |")
    print("+-----------------------------------------------------------------------------------------+")

    content_format = "|{0:^13}|{1:^8}|{2:^13}|{3:^14}|{4:^19}|{5:^17}|"

    for table_line in routing_table:
        if table_line["destination"] != my_router_id:
            if table_line["timeout"] is None:
                timeout = "-"
            else:
                timeout = int(table_line["timeout"]) - int(time.time())

            if table_line["garbage_collect"] is None:
                garbage = "-"
            else:
                garbage = int(table_line["garbage_collect"]) - int(time.time())

            if table_line["route_change_flag"] is None:
                route_change = "-"
            else:
                route_change = table_line["route_change_flag"]

            print(content_format.format(table_line["destination"], table_line["metric"], table_line["next_hop_id"],
                                        str(route_change), str(timeout), str(garbage)))
            print("+-----------------------------------------------------------------------------------------+")


#########################################################################################
#                                    Utils                                              #
#########################################################################################
def data_consistency_check(packet):
    """Perform consistency checks on incoming packets:
    have fixed fields the right values?
    is the metric in the right range?
    Non-conforming packets should be dropped"""
    is_valid = True
    number_of_entries = int((len(packet) - 4) / 20)  # common header size: 1 + 1 + 2 = 4 ;   Each Entry size: 20

    # fixed fields' values check
    command = int(packet[0])
    version = int(packet[1])
    sender = int(packet[2] + packet[3])

    if command != HEADER_COMMAND:  # 2: response
        is_valid = False

    if version != HEADER_VERSION:  # 2: version 2
        is_valid = False

    # metric's value check
    entries = packet[4:]
    for i in range(0, number_of_entries):
        entry = entries[(i * 20):((i + 1) * 20)]
        metric = int(entry[16] + entry[17] + entry[18] + entry[19])  # metric: last 4 bits
        if metric < 0 or metric > 16:
            is_valid = False

    print(" ")
    print(">>> Received Packet Consistency Check Result: [Command: " + str(command) + "], [Version: "
          + str(version) + "], [Sender: " + str(sender) + "] -> is valid ? " + str(is_valid))

    return is_valid


#########################################################################################
def config_file_check(config):
    """Config file check"""
    check_result = True
    print_content = ""

    # Check for "router-id" field
    try:
        print_content += "-----------------------------------\n"
        config.get('Settings', 'router-id')
    except configparser.NoOptionError:
        check_result = False
        print_content += "'router-id' field is not set!\n"
    else:
        if config.get('Settings', 'router-id') is not None:
            config_router_id = int(config.get('Settings', 'router-id'))
            if config_router_id < 1 or config_router_id > 64000:
                check_result = False
                print_content += "Router ID is invalid! :" + str(config_router_id) + "\n"

    # Check for "input-ports" field
    try:
        print_content += "-----------------------------------\n"
        config.get('Settings', 'input-ports')
    except configparser.NoOptionError:
        check_result = False
        print_content += "'input-ports' is not set!\n"
    else:
        if config.get('Settings', 'input-ports') is not None:
            config_input_ports = config.get('Settings', 'input-ports').split(', ')
            for config_input_port in config_input_ports:
                if int(config_input_port) < 1024 or int(config_input_port) > 64000:
                    check_result = False
                    print_content += "Input Port is invalid! :" + str(config_input_port) + "\n"

    # Check for "outputs" field
    try:
        print_content += "-----------------------------------\n"
        config.get('Settings', 'outputs')
    except configparser.NoOptionError:
        check_result = False
        print_content += "'outputs' field is not set!\n"
    else:
        if config.get('Settings', 'outputs') is not None:
            config_outputs = config.get('Settings', 'outputs').split(', ')
            for config_output in config_outputs:
                if int(config_output.split('-')[0]) < 1024 or int(config_output.split('-')[0]) > 64000:
                    check_result = False
                    print_content += "Output Port is invalid! :" + str(config_output.split('-')[0]) + "\n"

                if int(config_output.split('-')[1]) < 0 or int(config_output.split('-')[1]) > 16:
                    check_result = False
                    print_content += "Metric is invalid! :" + str(config_output.split('-')[1]) + "\n"

                if int(config_output.split('-')[2]) < 1 or int(config_output.split('-')[2]) > 64000:
                    check_result = False
                    print_content += "Neighbour Router ID is invalid! :" + str(config_output.split('-')[2]) + "\n"

    if check_result is False:
        print(">>> Config File check result: \n" + print_content)

    return check_result


#########################################################################################
def get_entry(router_id):
    """Returns entry in routing table by specific router id"""
    if len(routing_table) > 0:
        for table_line in routing_table:
            if int(table_line["destination"]) == router_id:
                return table_line

    return None


#########################################################################################
def get_entry_index(router_id):
    """Get specific router id's index in routing table"""
    for i in range(0, len(routing_table)):
        if routing_table[i]["destination"] == router_id:
            return i

    return None


#########################################################################################
def get_config_metric(router_id):
    """get metric from config for specific router"""
    for output in outputs:
        neighbour = int(output.split('-')[2])
        if router_id == neighbour:
            return output.split('-')[1]
    return None


#########################################################################################
def is_destination_exist(destination):
    """Check whether received destination already exist in routing table"""
    if len(routing_table) > 0:
        for table_line in routing_table:
            if int(table_line["destination"]) == destination:
                return True

    return False


#########################################################################################
def clear_route_change_flags():
    """Clear route change flags"""
    for i in range(0, len(routing_table)):
        routing_table[i]["route_change_flag"] = False


#########################################################################################
#                                    Main                                               #
#########################################################################################
def main():
    """Create RIP Daemon Instance Step by Step"""
    # <Beginning stage>: Read Configuration File
    check_result = read_config(sys.argv[1])

    # When any checking error from config file, following logic does not execute
    if check_result:
        # <Next stage>: Bind Socket for inputPorts
        bind_socket()

        # <Final stage>: infinite loop for incoming events
        event_handler()


if __name__ == '__main__':
    print('Start a RIP Daemon Instance')
    main()
