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

local PROTO_ICMP  = 1
local PROTO_ICMP6 = 58
local PROTO_IPv4  = 0x800
local PROTO_IPv6  = 0x86DD
local PROTO_TCP   = 6
local PROTO_UDP   = 17

local function usage ()
   print([[
Usage: pkt-info <file.pcap>

Prints out basic information about packets in <file.pcap>
   ]])
   os.exit()
end

if #arg < 1 then
   usage()
end

local function print_info (info)
   io.write(format("Eth:\t{src_mac} > {dst_mac}; type: {ethertype}\n", info))
   if info.flags.ipv4 then
      io.write(format("IP:\t{src_ip} > {dst_ip}; csum: {ipv4_csum}\n", info))
   end
   if info.flags.tcp then
      io.write(format("TCP:\t{src_port} > {dst_port}; csum: {tcp_csum}\n", info))
   end
end

local function main ()
   local source, template, out = unpack(arg)

   -- Read all packets in source
   local handle = pcap.open_offline(source)
   pcap.for_each_packet(handle, function(p)
      local ether, ipv4, tcp
      local info = { flags = {} }

      ether = Ethernet:new(p)
      info.src_mac = ether:src_mac()
      info.dst_mac = ether:dst_mac()
      info.ethertype = ("0x%x"):format(ether:ethertype())
      if ether:ethertype() == PROTO_IPv4 then
         ipv4 = IPv4:new(p)
         info.src_ip = ipv4:src_ip()
         info.dst_ip = ipv4:dst_ip()
         info.ipv4_csum = ("0x%x"):format(ipv4:checksum())
         info.flags.ipv4 = true
      end
      if ipv4:proto() == PROTO_TCP then
         local tcp = TCP:new(p)
         info.src_port = tcp:src_port()
         info.dst_port = tcp:dst_port()
         info.tcp_csum = ("0x%x"):format(tcp:checksum())
         info.flags.tcp = true
      end
      print_info(info)
   end)
end

main()
