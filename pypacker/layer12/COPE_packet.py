from pypacker import pypacker

class EncodedHeader(pypacker.Packet):
	__hdr__ = (
		("pkt_id", "Q", 0),
		("nexthop", "6s", b"\xff" * 6)
	)

class ReportHeader(pypacker.Packet):
	__hdr__ = (
		("src_ip", "4s", b"\x00" * 4),
		("last_pkt", "I", 0),
		("bitmap", "B", 0)
	)

class ACKHeader(pypacker.Packet):
	__hdr__ = (
		("neighbour", "6s", b"\xff" * 6),
		("last_ack", "I", 0),
		("ackmap", "B", 0)
	)

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

	def __init__(self):
		pypacker.Packet.__init__()


	def _dissect(self, buf):
		total_header_length = ((buf[0] & 0xf) << 2)
		options_length = total_header_length - 20		# total IHL - standard IP-len = options length

		if options_length < 0:
			# invalid header length: assume no options at all
			raise Exception("invalid header length: %d" % options_length)
		elif options_length > 0:
			# logger.debug("got some IP options: %s" % tl_opts)
			self._init_triggerlist("opts", buf[20: 20 + options_length], self.__parse_opts)

		self._init_handler(buf[9], buf[total_header_length:])
		return total_header_length

	__IP_OPT_SINGLE = {IP_OPT_EOOL, IP_OPT_NOP}

	def bin(self):
		pass

	def direction(self):
		pass

	def reverse_address(self):
		pass

	def 