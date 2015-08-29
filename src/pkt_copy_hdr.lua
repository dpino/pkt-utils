#!/usr/bin/env luajit

-- TODO: Better way to be able to access lib modules from any location?
local DIR = ("%s/workspace/pkt-utils/src/?.lua"):format(os.getenv("HOME"))
package.path = package.path..";"..DIR

local ffi       = require("ffi")
local pcap      = require("lib.pcap")
local protocols = require("lib.protocols")
local utils     = require("lib.utils")

local C = ffi.C
local format = utils.format
local sizeof = ffi.sizeof

local Ethernet, IPv4, TCP = protocols.Ethernet, protocols.IPv4, protocols.TCP

local function usage ()
   print([[
Usage: pkt-copy-hdr <source.pcap> <template.pcap> <destination.pcap>

Makes a copy of <template.pcap> into <destination.pcap>, substituting its header 
by the header in <source.pcap>. Either <source.pcap> and <template.pcap> should
contain exactly one packet and should be of the same ethertype.
   ]])
   os.exit()
end

if #arg < 3 then
   usage()
end

local function check_same_ethertype (p_src, p_dst)
   local eth_src = Ethernet:new(p_src.data)
   local eth_dst = Ethernet:new(p_dst.data)
   assert(eth_src:ethertype() == eth_dst:ethertype())
end

local function copy_eth_hdr (p_dst, p_src)
   local size = sizeof(Ethernet.ctype)
   ffi.copy(ffi.cast("uint8_t*", p_dst), p_src, size)
end

local function copy_ipv4_hdr (p_dst, p_src)
   local offset, size = sizeof(Ethernet.ctype), sizeof(IPv4.ctype)
   ffi.copy(ffi.cast("uint8_t*", p_dst) + offset, p_src + offset, size)
end

local function copy_tcp_hdr (p_dst, p_src)
   local offset, size = sizeof(Ethernet.ctype) + sizeof(IPv4.ctype), sizeof(TCP.ctype)
   ffi.copy(ffi.cast("uint8_t*", p_dst) + offset, p_src + offset, size)
end

local function assert_copy_is_correct (dst, src)
   local dst_ptr = ffi.cast("uint8_t*", dst.data)
   local src_ptr = ffi.cast("uint8_t*", src.data)
   local size = sizeof(Ethernet.ctype) + sizeof(IPv4.ctype) + sizeof(TCP.ctype) - 1
   for i=0, size do
      assert(dst_ptr[i] == src_ptr[i], "Not exact copy")
   end
end

local function copy_headers (p_dst, p_src)
   copy_eth_hdr(p_dst.data, p_src.data)
   copy_ipv4_hdr(p_dst.data, p_src.data)
   copy_tcp_hdr(p_dst.data, p_src.data)
   assert_copy_is_correct(p_dst, p_src)
end

local function main ()
   local source, destination, output = unpack(arg)
   local packet = {
      src = pcap.read_packet(source),
      dst = pcap.read_packet(destination),
   }
   check_same_ethertype(packet.dst, packet.src)
   copy_headers(packet.dst, packet.src)
   pcap.write_packet(output, packet.dst)
end

main()
