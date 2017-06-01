from pypacker import pypacker, triggerlist, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.layer3 import ip, ip6, ipx
import struct

class EncodedHeader(pypacker.Packet):
	__hdr__ = (
		("pkt_id", "Q", 0),
		("nexthop", "6s", b"\xff" * 6)
	)

	_size = 14

class ReportHeader(pypacker.Packet):
	__hdr__ = (
		("src_ip", "4s", b"\x00" * 4),
		("last_pkt", "I", 0),
		("bitmap", "B", 0)
	)

	_size = 9

class ACKHeader(pypacker.Packet):
	__hdr__ = (
		("neighbour", "6s", b"\xff" * 6),
		("last_ack", "I", 0),
		("ackmap", "B", 0)
	)

	_size = 11

ETH_TYPE_IP		= 0x0800		# IPv4 protocol

ENCODED_NUM_SIZE = 2
ENCODEDHEADER_SIZE = EncodedHeader._size
REPORT_NUM_SIZE = 2
REPORTHEADER_SIZE = ReportHeader._size
ACK_NUM_SIZE = 2
ACKHEADER_SIZE = ACKHeader._size
LOCAL_PKT_SEQ_NO_SIZE = 4
CHECKSUM_SIZE = 2

class COPE_packet(pypacker.Packet):
	__hdr__ = (
		("encoded_num", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("encoded_pkts", None, triggerlist.TriggerList),
		("report_num", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("reports", None, triggerlist.TriggerList),
		("ack_num", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("local_pkt_seq_no", "I", 0),
		("acks", None, triggerlist.TriggerList),
		("checksum", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)

	# dst_s = pypacker.get_property_mac("dst")
	# src_s = pypacker.get_property_mac("src")

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
		checksum_offset = ack_offset + ACK_NUM_SIZE + LOCAL_PKT_SEQ_NO_SIZE + ack_num * ACKHEADER_SIZE
		self._init_triggerlist("acks", buf[ack_offset+ACK_NUM_SIZE+LOCAL_PKT_SEQ_NO_SIZE:checksum_offset], self.__parseACKs)
		
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
		i = 0
		while i < len(buf):
			pkt = EncodedHeader(buf[i*ENCODEDHEADER_SIZE:i*ENCODEDHEADER_SIZE+ENCODEDHEADER_SIZE])
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
			pkt = ReportHeader(buf[i*REPORTHEADER_SIZE:i*REPORTHEADER_SIZE+REPORTHEADER_SIZE])
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
			pkt = ACKHeader(buf[i*ACKHEADER_SIZE:i*ACKHEADER_SIZE+ACKHEADER_SIZE])
			# print(pkt)
			i += ACKHEADER_SIZE
			acks.append(pkt)
		
		return acks

	def bin(self, update_auto_fields=True):
		if update_auto_fields:
			self._update_bodyhandler_id()


			# Do packet field updates here


		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)

pypacker.Packet.load_handler(COPE_packet,
	{
		ETH_TYPE_IP: ip.IP
	}
)