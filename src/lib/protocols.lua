module(...,package.seeall)

local ffi = require("ffi")

local C = ffi.C
local sizeof = ffi.sizeof

ffi.cdef([[
   uint16_t ntohs(uint16_t n);
]])

-- Ethernet

Ethernet = {}

local ethernet_t = ffi.typeof[[
   struct {
      uint8_t  ether_dhost[6];
      uint8_t  ether_shost[6];
      uint16_t ether_type;
   } __attribute__((packed))
]]

Ethernet.ctype = ethernet_t

function Ethernet:new(p)
   local o = {
      data = ffi.new(ethernet_t)
   }
   ffi.copy(o.data, p, sizeof(Ethernet.ctype))
   return setmetatable(o, { __index = Ethernet })
end

function Ethernet:src_mac()
   local result = {}
   local ether_shost = self.data.ether_shost
   for i=0,6 do
      result[i] = ("%x"):format(ether_shost[i])
   end
   return table.concat(result, ":")
end

function Ethernet:dst_mac(p)
   local result = {}
   local ether_dhost = self.data.ether_dhost
   for i=0,6 do
      result[i] = ("%x"):format(ether_dhost[i])
   end
   return table.concat(result, ":")
end

function Ethernet:ethertype (p)
   return C.ntohs(self.data.ether_type)
end

-- IPv4

IPv4 = {}

local ipv4_t = ffi.typeof[[
   struct {
      uint16_t ihl_v_tos;
      uint16_t total_length;
      uint16_t id;
      uint16_t frag_off;
      uint8_t  ttl;
      uint8_t  protocol;
      uint16_t checksum;
      uint8_t  src_ip[4];
      uint8_t  dst_ip[4];
   } __attribute__((packed))
]]

IPv4.ctype = ipv4_t

function IPv4:new(p)
   local o = {
      data = ffi.new(ipv4_t)
   }
   ffi.copy(o.data, p + sizeof(Ethernet.ctype), sizeof(IPv4.ctype))
   return setmetatable(o, { __index = IPv4 })
end

function IPv4:src_ip()
   local result = {}
   local src_ip = self.data.src_ip
   for i=0,4 do
      result[i] = ("%d"):format(src_ip[i])
   end
   return table.concat(result, ".")
end

function IPv4:dst_ip()
   local result = {}
   local dst_ip = self.data.dst_ip
   for i=0,4 do
      result[i] = ("%d"):format(dst_ip[i])
   end
   return table.concat(result, ".")
end

function IPv4:checksum ()
   return C.ntohs(self.data.checksum)
end

function IPv4:proto ()
   return self.data.protocol
end

-- TCP

TCP = {}

local tcp_t = ffi.typeof[[ struct { uint16_t    src_port;
   uint16_t    dst_port;
   uint32_t    seq;
   uint32_t    ack;
   uint16_t    off_flags;
   uint16_t    window_size;
   uint16_t    checksum;
   uint16_t    pad;
} __attribute__((packed))
]]

TCP.ctype = tcp_t

function TCP:new (p)
   local o = {
      data = ffi.new(tcp_t)
   }
   local offset = sizeof(Ethernet.ctype) + sizeof(IPv4.ctype)
   ffi.copy(o.data, p + offset, sizeof(tcp_t))
   return setmetatable(o, { __index = TCP })
end

function TCP:src_port ()
   return C.ntohs(self.data.src_port)
end

function TCP:dst_port ()
   return C.ntohs(self.data.dst_port)
end

function TCP:checksum ()
   return C.ntohs(self.data.checksum)
end
