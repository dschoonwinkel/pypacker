from pypacker import pypacker, triggerlist, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.layer3 import ip, ip6, ipx
import crcmod
import struct

crc16 = crcmod.mkCrcFun(0x18005, rev="True", initCrc=0xFFFF, xorOut=0x0000)
crc64 = crcmod.predefined.mkCrcFun('crc-64')

def crc_hash(msg):
	msg = msg.encode('ascii')
	return crc64(msg)

def crc_checksum(msg):
	return crc16(msg[:-2])

def print_hex(title, payload):
    if type(payload) == str:
        hextext = title + ' '.join('%02X' % ord(x) for x in str(payload))
        return hextext
    elif type(payload) == bytes:
        hextext = title + ' '.join('%02X' % x for x in payload)
        return hextext
    else:
        raise Exception("Incompatible type")
    # logging.debug(hextext)



class EncodedHeader(pypacker.Packet):
	__hdr__ = (
		("pkt_id", "Q", 0),
		("nexthop", "6s", b"\xff" * 6)
	)

	nexthop_s = pypacker.get_property_mac("nexthop")

	_size = 14

class ReportHeader(pypacker.Packet):
	__hdr__ = (
		("src_ip", "4s", b"\x00" * 4),
		("last_pkt", "I", 0),
		("bitmap", "B", 0)
	)

	src_ip_s = pypacker.get_property_ip4("src_ip")

	_size = 9

class ACKHeader(pypacker.Packet):
	__hdr__ = (
		("neighbour", "6s", b"\xff" * 6),
		("last_ack", "I", 0),
		("ackmap", "B", 0)
	)
	neighbour_s = pypacker.get_property_mac("neighbour")

	_size = 11

ETH_TYPE_IP		= 0x0800		# IPv4 protocol

ENCODED_NUM_SIZE = 2
ENCODEDHEADER_SIZE = EncodedHeader._size
REPORT_NUM_SIZE = 2
REPORTHEADER_SIZE = ReportHeader._size
ACK_NUM_SIZE = 2
ACKHEADER_SIZE = ACKHeader._size
LOCAL_PKT_SEQ_NUM_SIZE = 4
CHECKSUM_SIZE = 2

COPE_PACKET_TYPE = 0x7123

class COPE_packet(pypacker.Packet):
	__hdr__ = (
		("encoded_num", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("encoded_pkts", None, triggerlist.TriggerList),
		("report_num", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("reports", None, triggerlist.TriggerList),
		("ack_num", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("local_pkt_seq_num", "I", 0),
		("acks", None, triggerlist.TriggerList),
		("checksum", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)


	def _dissect(self, buf):

		encoded_num = struct.unpack(">H", buf[:2])[0]
		# print("Encoded num %d" % encoded_num)
		report_offset = ENCODED_NUM_SIZE + encoded_num * ENCODEDHEADER_SIZE
		# print("Report offset %d" % report_offset)
		self._init_triggerlist("encoded_pkts", buf[ENCODED_NUM_SIZE: report_offset], self.__parseEncodedPkts)
		report_num = struct.unpack(">H", buf[report_offset:report_offset+REPORT_NUM_SIZE])[0]
		# print("Report num %d" % report_num)
		ack_offset = report_offset + REPORT_NUM_SIZE + report_num * REPORTHEADER_SIZE
		# print("Ack offset %d" % ack_offset)
		self._init_triggerlist("reports", buf[report_offset + REPORT_NUM_SIZE:ack_offset], self.__parseReports)
		ack_num = struct.unpack(">H", buf[ack_offset:ack_offset+ACK_NUM_SIZE])[0]
		# print("ACK num %d" % ack_num)
		checksum_offset = ack_offset + ACK_NUM_SIZE + LOCAL_PKT_SEQ_NUM_SIZE + ack_num * ACKHEADER_SIZE
		self._init_triggerlist("acks", buf[ack_offset+ACK_NUM_SIZE + LOCAL_PKT_SEQ_NUM_SIZE:checksum_offset], self.__parseACKs)
		
		# print("Remaining buffer", buf[checksum_offset+CHECKSUM_SIZE:])
		self._init_handler(ETH_TYPE_IP, buf[checksum_offset+CHECKSUM_SIZE:])
		# self._init_handler(eth_type, buf[hlen: hlen + dlen])
		return checksum_offset + CHECKSUM_SIZE
		# return ENCODED_NUM_SIZE + ENCODEDHEADER_SIZE * encoded_num \
		 # + REPORT_NUM_SIZE + REPORTHEADER_SIZE * report_num + ACK_NUM_SIZE \
		 # + LOCAL_PKT_SEQ_NO_SIZE + ACKHEADER_SIZE * ack_num + CHECKSUM_SIZE

	@staticmethod
	def __parseEncodedPkts(buf):
	# 	"""Parse Encoded packets and return them as list."""
		encoded_pkts = list()
		# print("len(buf) %d"%len(buf))
		# print(print_hex("buffer ", buf))
		i = 0
		while i < len(buf):
			# print(i, i+ENCODEDHEADER_SIZE)
			# print(print_hex("subbuffer ", buf[i:i+ENCODEDHEADER_SIZE]))
			pkt = EncodedHeader(buf[i:i+ENCODEDHEADER_SIZE])
			# print(pkt)
			i += ENCODEDHEADER_SIZE
			encoded_pkts.append(pkt)
		
		return encoded_pkts

	@staticmethod
	def __parseReports(buf):
	# 	"""Parse Encoded packets and return them as list."""
		reports = list()

		# print("len(buf) %d"%len(buf))
		i = 0
		while i < len(buf):
			pkt = ReportHeader(buf[i:i+REPORTHEADER_SIZE])
			# print(pkt)
			i += REPORTHEADER_SIZE
			reports.append(pkt)
		
		return reports

	@staticmethod
	def __parseACKs(buf):
	# 	"""Parse Encoded packets and return them as list."""
		acks = list()

		# print("len(buf) %d"%len(buf))
		i = 0
		while i < len(buf):
			pkt = ACKHeader(buf[i:i+ACKHEADER_SIZE])
			# print(pkt)
			i += ACKHEADER_SIZE
			acks.append(pkt)
		
		return acks

	def calc_checksum(self):
		# Remember to calculate checksum only of COPE header and not the whole packet
		# print(self._pack_header())
		self.checksum = crc_checksum(self._pack_header())

	def get_pktid(self, neighbour):
		for encoded_header in self.encoded_pkts:
			if encoded_header.nexthop_s == neighbour:
				return encoded_header.pkt_id

	def check_nexthops(self, neighbour):
		# Check if neighbour is addressed in this packet's nexthops
		# print("\n\nStarting check_nexthops: len %d" % len(self.encoded_pkts))

		for encoded_header in self.encoded_pkts:
			# print("Encoded header.bin", encoded_header.bin())
			# print("Encoded header pkt_id dec %d" % encoded_header.pkt_id)
			# print("Encoded header", encoded_header)
			if encoded_header.nexthop_s == neighbour:
				# print("Encoded nexthop is me")
				return True

		return False

	@staticmethod
	def generatePktId(src_ip, pkt_seq_no):
		pkt_id_str = src_ip + str(pkt_seq_no)
		pkt_id = crc_hash(pkt_id_str)

		return pkt_id

	# def bin(self, update_auto_fields=True):
	# 	if update_auto_fields:
	# 		self._update_bodyhandler_id()


	# 		# Do packet field updates here


	# 	return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed():
			self._update_bodyhandler_id()

			if self.encoded_num_au_active:
				self.encoded_num = len(self.encoded_pkts)
				# self.len = len(self)
			if self.report_num_au_active:
				self.report_num = len(self.reports)
			if self.ack_num_au_active:
				self.ack_num = len(self.acks)

			if self.checksum_au_active:
				self.calc_checksum()
			# if self.v_hl_au_active:
			# 	# Update header length. NOTE: needs to be a multiple of 4 Bytes.
			# 	# logger.debug("updating: %r" % self._packet)
			# 		# options length need to be multiple of 4 Bytes
			# 	self.hl = int(self.header_len / 4) & 0xf
			# if self.sum_au_active:
			# 	# length changed so we have to recalculate checksum
			# 	# logger.debug(">>> IP: calculating sum")
			# 	# reset checksum for recalculation,  mark as changed / clear cache
			# 	self.sum = 0
			# 	# logger.debug(">>> IP: bytes for sum: %s" % self.header_bytes)
			# 	self.sum = in_cksum(self._pack_header())
			# 	# logger.debug("IP: new hl: %d / %d" % (self._packet.hdr_len, hdr_len_off))
			# 	# logger.debug("new sum: %0X" % self.sum)

		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


pypacker.Packet.load_handler(COPE_packet,
	{
		ETH_TYPE_IP: ip.IP
	}
)


# Full Ethernet Test packet
#ff ff ff ff ff ff 00 00 ff 00 00 01 71 23 00 02 11 29 8e 0d 3e 0d 3e 0d 00 00 00 00 00 02 11 2b 5e 0d 3e 0d 3e 0d 00 00 00 00 00 01 00 02 0a 00 00 02 00 00 00 01 01 0a 00 00 01 00 00 00 01 01 00 02 00 00 00 00 00 00 00 00 00 02 00 00 00 01 01 00 00 00 00 00 01 00 00 00 01 01 38 95 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# COPE Test packets
# 00 02 11 29 8e 0d 3e 0d 3e 0d 00 00 00 00 00 02 11 2b 5e 0d 3e 0d 3e 0d 00 00 00 00 00 01 00 02 0a 00 00 02 00 00 00 01 01 0a 00 00 01 00 00 00 01 01 00 02 00 00 00 00 00 00 00 00 00 02 00 00 00 01 01 00 00 00 00 00 01 00 00 00 01 01 38 95
# b'\x00\x02\x11\x29\x8e\x0d\x3e\x0d\x3e\x0d\x00\x00\x00\x00\x00\x02\x11\x2b\x5e\x0d\x3e\x0d\x3e\x0d\x00\x00\x00\x00\x00\x01\x00\x02\x0a\x00\x00\x02\x00\x00\x00\x01\x01\x0a\x00\x00\x01\x00\x00\x00\x01\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x01\x38\x95'

# 2 Encoded packets test packet
# 00 02 11 29 8E 0D 3E 0D 3E 0D 00 00 00 00 00 02 11 2B 5E 0D 3E 0D 3E 0D 00 00 00 00 00 01 00 00 00 00 00 00 00 00 E6 E1
# b'\x00\x02\x11\x29\x8E\x0D\x3E\x0D\x3E\x0D\x00\x00\x00\x00\x00\x02\x11\x2B\x5E\x0D\x3E\x0D\x3E\x0D\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xE6\xE1'