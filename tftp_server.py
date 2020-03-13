# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.

    Failing to comply with those requirements will invalidate
    your submission.

    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        # tftp supports 5 packet types,with corresponding opodes should be two bytes
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        # define port, but should 
        self.port = 69 ### 69 for the server not for client!
        self.root_path = '//'
        self.client_address = None
        self.client_port = 0
        self.file_path = ''
        self.file_block_count = 0
        self.last_block_num = b'00'# takes 2 bytes 
        self.blocks_transferred = 0
        self.fail = False
        self.ignore_current_packet = False #ignore it if received packet's source is adifferent prot no
        self.tftp_mode = 'octet' # i choose it as default mode or whatever
        self.request_mode = None # 'RRQ' or 'WRQ'
        self.server_address = ('127.0.0.1', 69)
        self.file_bytes = []
        self.reached_end = False
        # self.client_socket = None, WRONG!
        self.packet_buffer = []
        

    def process_udp_packet(self, packet_data, packet_source):#is packet source an adress or what
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        self.ignore_current_packet = False
        in_packet = self._parse_udp_packet(packet_data)
        print('in_p:',in_packet)
        if self.ignore_current_packet:
            return 
        out_packet = self._do_some_logic(in_packet)
        print('out_p:',out_packet)
        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):# is it a byte or bytearray?
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        # format = '!H'
        # src_port = struct.unpack('!H', packet_bytes[0:2])[0]
        # if src_port != self.client_port:#ignore stray packets
        #     self.ignore_current_packet = True
        #     return 0
        # dest_port = struct.unpack('!H', packet_bytes[2:4])[0]
        # len = struct.unpack('!H', packet_bytes[4:6])[0]
        # checksum = struct.unpack('!H', packet_bytes[6:8])[0]
        
        return packet_bytes
    
    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        # input_packet is the data bytes in the udp packet
        opcode = struct.unpack('!H', input_packet[0:2])[0]
        packetTypes = { 1: 'RRQ', 2:'WRQ', 3:'DATA', 4:'ACK', 5:'ERROR'}
        curr_pack_type = packetTypes[opcode]
        filename = ''
        out_packet = None
        print(opcode)
        if opcode == 1 or opcode == 2: ##RRQ
            self.request_mode = packetTypes[opcode]
            seperator_idx = 2 + input_packet[2:].find(0)
            # + 2 because the index returned from find is relative to start index 2:
            filename_bytes = input_packet[2:seperator_idx]
            
            fmt_str = '!{}s'.format(len(filename_bytes)) #seperator_idx
            self.file_path = struct.unpack(fmt_str, filename_bytes)[0]
            print(filename_bytes,'zz')
            # dont need 
            pass
        if opcode == 1: ##RRQ
            #reply with Data Block #1
            #data packet with opcode = 3, block # = 1
            out_packet = struct.pack('!HH', 3,1) 
            
        elif opcode == 2:##WRQ
            out_packet = struct.pack('!HH',4,0)
        elif opcode == 3:# Data
            block_num = struct.unpack('!H', input_packet[2:4])[0]
            
            if len(input_packet) > 4:#last data packet can have 0 bytes in data
                len_data = len(input_packet[4:])
                if len_data != 512:
                    self.reached_end = True
                if self.tftp_mode == 'octet':
                    fmt_str = '!{}B'.format(len_data)
                else: # netascii
                    fmt_str = '!{}s'.format(len_data)
                print(input_packet[4:],'==')
                unpacked_data_bytes = struct.unpack(fmt_str, input_packet[4:])
                print(unpacked_data_bytes)
        
                #print('db',len(unpacked_data_bytes),'--', unpacked_data_bytes)
                self.file_bytes.extend(unpacked_data_bytes)
            else: #reached end of transmission
                self.reached_end = True
            
            out_packet = struct.pack('!HH',3 , block_num)
            
        elif opcode == 3:#ACK
            pass
            # send next data packet
            #out_packet = getnext 512 bytes from file
        
        elif opcode == 5:
            pass

        return out_packet

    def ignore_current(self):
        return self.ignore_current_packet
    
    

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        
        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0
    def save_file(self):
        with open(self.file_path, 'wb') as up_file:
            up_file.write(bytes(self.file_bytes))
    def _form_packet(self, packet_type, data=None):
        pass

    def get_request_mode(self):
        self.reached_end = False
        return self.request_mode
    def transmission_ended(self):
        return self.reached_end
    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        #return 
        pass
    
    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        pass
    def set_client_address(self, client_address):
        self.client_address = client_address
        #client port needed for 

        self.client_port =  client_address[1]


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    #print("*" * 50)
    #print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    #check_file_name()
    #print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    #ip_address = get_arg(1, "127.0.0.1")
    #operation = get_arg(2, "pull")
    #file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    #parse_user_input(ip_address, operation, file_name)
    tftp_proc = TftpProcessor()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 69))
    if True: #change it to while after debugging
        
        print('WAITING!')
        request_packet ,client_address = server_socket.recvfrom(2048)
        tftp_proc.set_client_address(client_address)
        print('REQUEST pack:', request_packet)
        tftp_proc.process_udp_packet(request_packet, client_address)
        request_mode = tftp_proc.get_request_mode()
        print(request_mode)
        if request_mode == 'RRQ' or request_mode == 'WRQ':
            print('Connecting')
            
            while tftp_proc.has_pending_packets_to_be_sent() :
                next_packet = tftp_proc.get_next_output_packet()
                server_socket.sendto(next_packet,client_address)
                if not tftp_proc.transmission_ended():
                    received_packet ,received_client = server_socket.recvfrom(2048)
                    tftp_proc.process_udp_packet(received_packet, received_client)
                else:
                    print('TRANSMISSION ENDED')
                while tftp_proc.ignore_current():
                    received_packet ,received_client = server_socket.recvfrom(2048)
                    tftp_proc.process_udp_packet(received_packet, received_client)
            print(tftp_proc.file_bytes)
            print(tftp_proc.file_path)
            print(bytes(tftp_proc.file_bytes))
            tftp_proc.save_file()

        else:
            print('ERROR!')



    



if __name__ == "__main__":
    main()
