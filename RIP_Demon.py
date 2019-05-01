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
import time
import struct

# Instance Variable
LOCAL_HOST = '127.0.0.1'
MAX_METRIC = 16

HEADER_COMMAND = 2
HEADER_VERSION = 2
MUST_BE_ZERO = 0
ADDRESS_FAMILY_IDENTIFIER = 2

HEADER_FORMAT = 'BBH'  # B: integer (size: 1)   H: integer (size: 2)
ENTRY_FORMAT = 'HHIIII'  # H: integer (size: 2)  I: integer (size: 4)

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
# (when is True, there is no need to send trigger update again at the same time)
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
            "last_update_time": None,
            "garbage_collect_start": None
        }

        routing_table.append(table_line)

    return check_result


#########################################################################################
#                  <Next stage>: Create UDP Socket for each inputPorts                  #
#########################################################################################
def create_udp_socket():
    """Create UDP Socket for each inputPorts"""
    if len(input_ports) > 0:
        for input_port in input_ports:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind((LOCAL_HOST, int(input_port)))
            sockets.append(udp_socket)


#########################################################################################
#                   <Final stage>: infinite loop for incoming events                    #
#########################################################################################
def event_handler():
    """Operation for coming event"""

    print(">>> Event Handler Start")

# Step 1: Handler current exist routing table's data

    # Initiate Periodic Timer Unsolicited RIP Response
    init_periodic_timer()

    # Start a Timeout timer for this specific entry
    init_timeout_timer()

    # Start a Garbage Collection timer for this specific entry
    init_garbage_collection_timer()

    # print('Current active thread: {}'.format(threading.activeCount()))


# Step 2: Handler new receive routing table's data

    # Infinite loop to keep monitoring the incoming data
    while True:
        readable, writable, exceptional = select.select(sockets, [], sockets)

        # get data from neighbour router
        for readable_item in readable:
            read_data = readable_item.recvfrom(1024)  # result: tuple(packet_data, (host, port))
            # print("read_data: " + str(read_data))

            packet = read_data[0]
            if check_received_packet(packet):
                process_packet(packet)


#########################################################################################
#                                RIP Packet Create Relate                               #
#########################################################################################
def create_output_packet(is_update_only):
    """Create send packet"""

    packets_group = {}  # neighbour router : packet

    header = create_packet_header()  # Create RIP packet common header

    for output in outputs:
        neighbour_router_id = output.split('-')[2]
        packet = header

        if len(routing_table) > 0:
            for table_line in routing_table:
                # When trigger update, only send out route changed entry
                if is_update_only:
                    if table_line["route_change_flag"] == "False":
                        continue

                if str(table_line["next_hop_id"]) == neighbour_router_id \
                        and str(table_line["destination"]) != neighbour_router_id:
                    # poisoned reverse
                    entry = create_packet_entry(table_line["destination"], 16)
                else:
                    entry = create_packet_entry(table_line["destination"], table_line["metric"])

                packet += entry

            packets_group[neighbour_router_id] = packet

    return packets_group


#########################################################################################
def create_packet_header():
    """Create common header for the RIP packet"""
    header = struct.pack(HEADER_FORMAT, HEADER_COMMAND, HEADER_VERSION, my_router_id)

    return header


#########################################################################################
def create_packet_entry(destination, metric):
    """Creates a RIP Entry for RIP packet"""
    entry = struct.pack(ENTRY_FORMAT, ADDRESS_FAMILY_IDENTIFIER,
                        MUST_BE_ZERO, destination, MUST_BE_ZERO, my_router_id, int(metric))

    return entry


#########################################################################################
#                                Send Out RIP Response                                  #
#########################################################################################
def send_update_response(is_update_only):
    """Send RIP response periodic or by route invalid trigger"""
    readable, writable, exceptional = select.select([], [sockets[0]], [])

    send_socket = writable[0]

    packets_group = create_output_packet(is_update_only)

    # send out unsolicited response to each neighbour router
    if packets_group:
        for output in outputs:
            neighbour_router_id = output.split('-')[2]
            if packets_group[neighbour_router_id]:
                send_socket.sendto(packets_group[neighbour_router_id], (LOCAL_HOST, int(output.split('-')[0])))

    # Once packet have been generated and sent, the route change flags should be set into no change.
    for i in range(0, len(routing_table)):
        routing_table[i]["route_change_flag"] = False

    print_routing_table("send_unsolicited_response")


#########################################################################################
#                            Receive and Process Packet                                 #
#########################################################################################
def process_packet(packet):
    """Get routing information out of incoming RIP packet and update routing table"""
    # unpack result: tuple(command, version, sender)
    header = struct.unpack(HEADER_FORMAT, packet[0:4])  # common header size: 1 + 1 + 2 = 4

    sender = header[2]  # Identified by router id which is set in common header
    count_entry = len(packet) // 20  # Each Entry size: 20

    sender_line = get_touting_table_line(sender)

    # When sender is not exist in routing table. Create by config outputs data
    if sender_line:
        # Compare with config metric, update with the smaller metric
        sender_metric = get_config_metric(sender)
        if int(sender_metric) < int(sender_line["metric"]):
            update_routing_table(sender, sender_metric, sender, route_change=True)
    else:
        sender_metric = get_config_metric(sender)
        add_routing_table(sender, sender_metric, sender)

    sender_line = get_touting_table_line(sender)

    # Modify received packet: next hop into sender & metric into total metric
    for i in range(0, count_entry):
        # unpack result: tuple(afi, 0, destination, 0, sender, metric)
        received_entry = struct.unpack(ENTRY_FORMAT, packet[(4 + i * 20): (4 + (i + 1) * 20)])
        destination = received_entry[2]
        metric = received_entry[5]

        # total metric = metric(self -> sender) + metric(sender -> destination)
        total_metric = int(sender_line["metric"]) + metric
        if total_metric >= MAX_METRIC:
            total_metric = MAX_METRIC

        # Check whether destination address already exist in routing table
        if is_destination_exist(destination):
            original_destination_line = get_touting_table_line(destination)

            # Check whether next hop is same with original routing table entry
            if int(original_destination_line["next_hop_id"]) == sender:

                # Directly update routing table by latest info
                if int(original_destination_line["metric"]) != total_metric:
                    update_routing_table(destination, total_metric, sender, route_change=True)
                else:
                    update_routing_table(destination, total_metric, sender, route_change=False)

            else:
                # Compare original routing entry's metric with received entry's total metric
                if int(original_destination_line["metric"]) <= total_metric:
                    pass
                else:
                    update_routing_table(destination, total_metric, sender, route_change=True)

        else:
            # If not exist, only when destination is valid, add to routing table
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
        "last_update_time": time.time(),
        "garbage_collect_start": None
    }
    routing_table.append(table_line)
    print_routing_table("add_routing_table")


#########################################################################################
def update_routing_table(destination, total_metric, next_hop_id, route_change):
    """update routing table according according to new received packet or status change"""
    if int(total_metric) >= 16:
        # Only when first time metric is 16, update garbage_collect_start
        # When metric is 16 and the received metric is same, there is not need to update garbage_collect_start
        if route_change:
            table_line = {
                "destination": destination,
                "metric": total_metric,
                "next_hop_id": next_hop_id,
                "route_change_flag": route_change,
                "last_update_time": None,
                "garbage_collect_start": time.time()
            }

            index = get_routing_table_index(destination)
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
            "last_update_time": time.time(),
            "garbage_collect_start": None
        }

        index = get_routing_table_index(destination)
        routing_table[index] = table_line
        print_routing_table("update_routing_table --- total_metric < 16")


#########################################################################################
#                                    Timer Relate                                       #
#########################################################################################
def init_periodic_timer():
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
            if table_line["last_update_time"] is None or (time.time() - table_line["last_update_time"]) < TIME_OUT:
                # Metric is updated to 16 and trigger garbage collection Timer.
                # Or Entry already updated again after Timeout timer initialized.
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
            if table_line["garbage_collect_start"] is None \
                    or (time.time() - table_line["garbage_collect_start"]) < GARBAGE_COLLECT_TIME:
                # Route is updated to valid and trigger Timeout Timer.
                # Or Entry already updated again after Garbage Collection timer initialized.
                # Pass and wait next started Timer to process
                pass
            else:
                entry_index = get_routing_table_index(destination)
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
            if table_line["last_update_time"] is None:
                timeout = "-"
            else:
                timeout = int(TIME_OUT - (int(time.time() - table_line["last_update_time"])))

            if table_line["garbage_collect_start"] is None:
                garbage = "-"
            else:
                garbage = int(GARBAGE_COLLECT_TIME - (int(time.time() - table_line["garbage_collect_start"])))

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
def check_received_packet(packet):
    """Perform consistency checks on incoming packets:
    have fixed fields the right values?
    is the metric in the right range?
    Non-conforming packets should be dropped"""
    is_valid = True

    # print("len(packet) % 20:" + str(len(packet) % 20))

    # packet length check. common header size: 1 + 1 + 2 = 4
    if len(packet) % 20 != 4:
        is_valid = False
        return is_valid

    count_entry = len(packet) // 20  # Each Entry size: 20

    # fixed fields' values check
    header = struct.unpack(HEADER_FORMAT, packet[0:4])

    command = header[0]
    version = header[1]
    sender = header[2]

    if command != HEADER_COMMAND:  # 2: response
        is_valid = False
        return is_valid

    if version != HEADER_VERSION:  # 2: version 2
        is_valid = False
        return is_valid

    # metric's value check
    for i in range(0, count_entry):
        entry = struct.unpack(ENTRY_FORMAT, packet[(4 + i * 20): (4 + (i + 1) * 20)])
        metric = entry[5]  # metric: last 4 bits
        if metric < 0 or metric > 16:
            is_valid = False
            return is_valid

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
def get_touting_table_line(router_id):
    """Returns routing table line by specific router id"""
    if len(routing_table) > 0:
        for table_line in routing_table:
            if int(table_line["destination"]) == router_id:
                return table_line

    return None


#########################################################################################
def get_routing_table_index(router_id):
    """Get specific router id's index in routing table"""
    for i in range(0, len(routing_table)):
        if routing_table[i]["destination"] == router_id:
            return i

    return None


#########################################################################################
def get_config_metric(router_id):
    """get metric from config for specific router"""
    for output in outputs:
        neighbour_router_id = int(output.split('-')[2])
        if router_id == neighbour_router_id:
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
#                                    Main                                               #
#########################################################################################
def main():
    """Create RIP Daemon Instance Step by Step"""
    # <Beginning stage>: Read Configuration File
    check_result = read_config(sys.argv[1])

    # When any checking error from config file, following logic does not execute
    if check_result:
        # <Next stage>: Create UDP Socket for each inputPorts
        create_udp_socket()

        # <Final stage>: infinite loop for incoming events
        event_handler()


if __name__ == '__main__':
    print('Start a RIP Daemon Instance')
    main()
