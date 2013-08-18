from .. import pypacker
from pypacker.layer12 import ethernet, stp

import struct

class LLC(pypacker.Packet):
	_typesw = {}

	def _unpack_data(self, buf):
		if self.type == ethernet.ETH_TYPE_8021Q:
			self.tag, self.type = struct.unpack('>HH', buf[:4])
			buf = buf[4:]
		elif self.type == ethernet.ETH_TYPE_MPLS or \
			 self.type == ethernet.ETH_TYPE_MPLS_MCAST:
			# XXX - skip labels
			for i in range(24):
				if struct.unpack('>I', buf[i:i+4])[0] & 0x0100: # MPLS_STACK_BOTTOM
					break
			self.type = ethernet.ETH_TYPE_IP
			buf = buf[(i + 1) * 4:]
		try:
			self.data = self._typesw[self.type](buf)
			setattr(self, self.data.__class__.__name__.lower(), self.data)
		except (KeyError, pypacker.UnpackError):
			self.data = buf

	def _dissect(self, buf):
		self.data = buf
		if self.data.startswith('\xaa\xaa'):
			# SNAP
			self.type = struct.unpack('>H', self.data[6:8])[0]
			self._unpack_data(self.data[8:])
		else:
			# non-SNAP
			dsap = ord(self.data[0])
			if dsap == 0x06: # SAP_IP
				self.data = self.ip = self._typesw[ethernet.ETH_TYPE_IP](self.data[3:])
			elif dsap == 0x10 or dsap == 0xe0: # SAP_NETWARE{1,2}
				self.data = self.ipx = self._typesw[ethernet.ETH_TYPE_IPX](self.data[3:])
			elif dsap == 0x42: # SAP_STP
				self.data = self.stp = stp.STP(self.data[3:])
