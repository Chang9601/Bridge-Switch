############################################################################
##
##     This file is part of Purdue CS 422.
##
##     Purdue CS 422 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     Purdue CS 422 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with Purdue CS 422. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

import json
import argparse
import p4runtime_sh.shell as p4sh
from p4.v1 import p4runtime_pb2 as p4rt

###############################################################################
# Default parameters
###############################################################################

# Relative path of the configuration, logs, and topo directories
CFG_DIR = 'cfg'
LOGS_DIR = 'logs'

# Bridge ID and number of ports
BRIDGE_ID = 1

# Flows and logs threshold
NUM_ENTRIES_THRESHOLD = 100
NUM_LOGS_THRESHOLD = 10

# Ethernet type values (https://en.wikipedia.org/wiki/EtherType)
# - ARP: 0x0806
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN = 0x8100


###############################################################################
# Helper functions
###############################################################################

# MAC address in bytes to string
def mac2str(mac):
    return ':'.join('{:02x}'.format(b) for b in mac)


###############################################################################
# Multicast group functions
###############################################################################

# Create a multicast group entry
def InstallMcastGrpEntry(mcast_group_id, bridge_ports):
    mcast_entry = p4sh.MulticastGroupEntry(mcast_group_id)
    for port in bridge_ports:
        mcast_entry.add(port)
    mcast_entry.insert()

# Delete a multicast group entry
def DeleteMcastGrpEntry(mcast_group_id):
    mcast_entry = p4sh.MulticastGroupEntry(mcast_group_id)
    mcast_entry.delete()

###############################################################################
# VLAN Broadcast Rules functions
###############################################################################

# Create VLAN broadcast rules
def InstallVLANEntry(vlan_id_to_ports_map):
    for vlan_id in vlan_id_to_ports_map:
        vlan_entry = p4sh.MulticastGroupEntry(vlan_id)
        for port in vlan_id_to_ports_map[vlan_id]:
            vlan_entry.add(port)
        vlan_entry.insert()

# Delete VLAN broadcast rules
def DeleteVLANEntry(vlan_id_to_ports_map):
    for vlan_id in vlan_id_to_ports_map:
        vlan_entry = p4sh.MulticastGroupEntry(vlan_id)
        vlan_entry.delete()

###############################################################################
# Bits extracting function
###############################################################################

def ExtractBits(num, num_bits, pos):
    
    binary = num[2:]

    end_pos = len(binary) - pos
    start_pos = end_pos - num_bits + 1

    extracted = binary[start_pos : end_pos + 1]

    #print('Extracted={0}'.format(extracted))
    #print('Extracted={0}'.format(int(extracted, 2)))
    
    i = len(extracted) - 1
    candidates = []
    candidates.append(int(extracted, 2))
    while extracted[i] == '0':
        tmp = extracted[0 : i]
        candidates.append(int(tmp, 2))
        i = i - 1

    print('Candidiates={0}'.format(candidates))


###############################################################################
# Packet processing functions
###############################################################################

# Process incoming packets
def ProcPacketIn(switch_name, mcast_group_id,
                 eth_to_port_map, num_entries_threshold, 
                 vlan_id_to_ports_map,
                 logs_dir, num_logs_threshold):
    try:
        logs_count = 0
        while True:
            rep = p4sh.client.get_stream_packet("packet", timeout=1)
            if rep is not None:
                # Read the raw packet
                payload = rep.packet.payload




                ##################################################################################
                # Packet parsing logic - Begins ##################################################
                ##################################################################################

                # TODO: For each incoming packet, read the following fields:
                # - ingress port
                # - Ethernet header (source/destination MAC addresses and type)
                # - VLAN header (if present)

                # NOTE: please follow p4rt-src/bridge.py for a reference example


                #### ADD YOUR CODE HERE ... ####
                # Convert multicast group ID to bytes
                mcast_group_id_in_bytes = mcast_group_id.to_bytes(2, byteorder='big')

                # Parse Metadata
                # Convert an array of bytes into an integer
                ingress_port_in_bytes = rep.packet.metadata[0].value
                ingress_port = int.from_bytes(ingress_port_in_bytes, 'big')

                # Parse Ethernet header (source/destination MAC address and type)
                # Convert an array of bytes into a string (e.g., 08:00:08:15:ca:fe)
                dst_mac_in_bytes = payload[0:6]
                dst_mac = mac2str(dst_mac_in_bytes)

                src_mac_in_bytes = payload[6:12]
                src_mac = mac2str(src_mac_in_bytes)
                
                # Convert an array of bytes into an integer (e.g., b'\x00\x10' -> 16)
                eth_type_in_bytes = payload[12:14]
                eth_type = int.from_bytes(eth_type_in_bytes, 'big') # mac2str(eth_type_in_bytes)
                
                # Extract VLAN header if present
                vlan_header_in_bytes = payload[14:18]
                if eth_type == ETH_TYPE_VLAN:
                    vlan_header_in_bytes = payload[14:18]
                    # Bytes in big-endian, Bits in little-endian
                    vlan_header = bin(int.from_bytes(vlan_header_in_bytes, 'little')) # mac2str(vlan_header_in_bytes) #int.from_bytes(vlan_header_in_bytes, 'big')

                vlan_id = 0
                if vlan_header_in_bytes is not None:
                    # Extract VLAN id from VLAN header -> WIP
                    ExtractBits(vlan_header, 12, 5)

                print("PacketIn: dst={0} src={1} port={2} type={3} vlan_header={4}".format(
                    dst_mac, src_mac, ingress_port, eth_type, vlan_header))
                print()

                ##################################################################################
                # Packet parsing logic - Ends ####################################################
                ##################################################################################




                # Decrement table entry's counter
                del_mac_list = []
                for mac in eth_to_port_map:
                    eth_to_port_map[mac]['count'] -= 1
                    if eth_to_port_map[mac]['count'] == 0:
                        print("INFO: Flow entry deleted: mac={0} port={1}".format(
                            mac, eth_to_port_map[mac]['port']))
                        del_mac_list.append(mac)

                for mac in del_mac_list:
                    del eth_to_port_map[mac]




                ##################################################################################
                # Learning switch logic - Begins #################################################
                ##################################################################################

                # TODO: For each packet, carryout the following tasks:
                # - If the packet is an ARP request, 
                #   - learn the Ethernet address to port mapping by updating the `eth_to_port_map` 
                #     table with the new source MAC and ingress port pair
                #   - broadcast the ARP packet; however, make sure only those hosts belonging to 
                #     a partuclar VLAN receive the packet (use `vlan_id_to_ports_map` table 
                #     for this)
                # - Else, for any other packet,
                #   - forward it using the learned Ethernet address to port mapping (i.e., 
                #     `eth_to_port_map` table)
                #   - if no mapping exists, drop the packet (we haven't received an ARP request for 
                #     it yet)

                
                #### ADD YOUR CODE HERE ... ####
                if eth_type == ETH_TYPE_ARP:
                    eth_to_port_map[src_mac] = {'port': ingress_port, 'count': num_entries_threshold}
                    #ports = vlan_id_to_ports_map[vlan_id]
                    #egress_ports_in_bytes = ports.to_bytes(2, byteorder='big')
                    #ProcPacketOut(payload, mcast_group_id_in_bytes, ingress_port_in_bytes, egress_ports_in_bytes) 
                else:
                    if dst_mac in eth_to_port_map:
                        egress_port_in_bytes = eth_to_port_map[dst_mac]['port'].to_bytes(2, byteorder='big')
                        ProcPacketOut(payload, mcast_group_id_in_bytes, ingress_port_in_bytes, egress_port_in_bytes)
                    else:
                        None # Drop the packet

                ##################################################################################
                # Learning switch logic - Ends ###################################################
                ##################################################################################




            # Logs the Ethernet address to port mapping
            logs_count += 1
            if logs_count == num_logs_threshold:
                logs_count = 0
                with open('{0}/{1}-table.json'.format(logs_dir, switch_name), 'w') as outfile:
                    json.dump(eth_to_port_map, outfile)

                print(
                    "INFO: Logs committed to {0}/{1}-table.json".format(logs_dir, switch_name))
    except KeyboardInterrupt:
        return None

# Process outgoing packets
def ProcPacketOut(payload, mcast_grp_in_bytes=b'\00\00', ingress_port_in_bytes=None, egress_port_in_bytes=None):
    req = p4rt.StreamMessageRequest()
    packet = req.packet
    packet.payload = payload

    metadata = p4rt.PacketMetadata()
    # Append multicast group ID
    metadata.metadata_id = 1
    metadata.value = mcast_grp_in_bytes
    packet.metadata.append(metadata)
    if ingress_port_in_bytes is not None:
        # Append ingress port
        metadata.metadata_id = 2
        metadata.value = ingress_port_in_bytes
        packet.metadata.append(metadata)
    if egress_port_in_bytes is not None:
        # Append egress port
        metadata.metadata_id = 4
        metadata.value = egress_port_in_bytes
        packet.metadata.append(metadata)

    # Send packet out
    p4sh.client.stream_out_q.put(req)


###############################################################################
# Main 
###############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Switch Script')
    parser.add_argument('--grpc-port', help='GRPC Port', required=True,
                        type=str, action="store", default='50001')
    parser.add_argument('--topo-config', help='Topology Configuration File', required=True,
                        type=str, action="store")
    args = parser.parse_args()

    # Create a bridge name postfixed with the grpc port number
    switch_name = 'switch-{0}'.format(args.grpc_port)

    # Create a Ethernet address to port mapping
    eth_to_port_map = {}

    # Get Multicast/VLAN ID to ports mapping
    with open(args.topo_config, 'r') as infile:
        topo_config = json.loads(infile.read())

    mcast_group_id = topo_config['switch'][args.grpc_port]['mcast']['id']
    mcast_group_ports = topo_config['switch'][args.grpc_port]['mcast']['ports']

    vlan_id_to_ports_map = {}
    for vlan_id, ports in topo_config['switch'][args.grpc_port]['vlan_id_to_ports'].items():
        vlan_id_to_ports_map[int(vlan_id)] = ports

    # Setup the P4Runtime connection with the bridge
    p4sh.setup(
        device_id=BRIDGE_ID, grpc_addr='127.0.0.1:{0}'.format(args.grpc_port), election_id=(0, 1),
        config=p4sh.FwdPipeConfig(
            '{0}/{1}-p4info.txt'.format(CFG_DIR, switch_name),  # Path to P4Info file
            '{0}/{1}.json'.format(CFG_DIR, switch_name)  # Path to config file
        )
    )

    print("Switch Started @ Port: {0}".format(args.grpc_port))
    print("Press CTRL+C to stop ...")

    # Install broadcast rule
    InstallMcastGrpEntry(mcast_group_id, mcast_group_ports)




    ##################################################################################
    # Install VLAN Broadcast Rules - Begins ##########################################
    ##################################################################################

    # TODO: Install VLAN-specific broadcast rules (use `vlan_id_to_ports_map` table for 
    # this)

    #### ADD YOUR CODE HERE ... ####
    InstallVLANEntry(vlan_id_to_ports_map)

    ##################################################################################
    # Install VLAN Broadcast Rules - Ends ############################################
    ##################################################################################




    # Start the packet-processing loop
    ProcPacketIn(switch_name, mcast_group_id, 
                 eth_to_port_map, NUM_ENTRIES_THRESHOLD, 
                 vlan_id_to_ports_map,
                 LOGS_DIR, NUM_LOGS_THRESHOLD)

    print("Switch Stopped")

    # Delete broadcast rule
    DeleteMcastGrpEntry(mcast_group_id)




    ##################################################################################
    # Delete VLAN Broadcast Rules - Begins ###########################################
    ##################################################################################

    # TODO: Delete VLAN-specific broadcast rules (use `vlan_id_to_ports_map` table for 
    # this)

    #### ADD YOUR CODE HERE ... ####
    DeleteVLANEntry(vlan_id_to_ports_map)

    ##################################################################################
    # Delete VLAN Broadcast Rules - Ends #############################################
    ##################################################################################




    # Close the P4Runtime connection
    p4sh.teardown()
