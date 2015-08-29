module(...,package.seeall)

local ffi = require("ffi")

local pcap = ffi.load("pcap")

ffi.cdef([[
   typedef struct pcap pcap_t;
   struct pcap_pkthdr {
     uint64_t ts_sec;         /* timestamp seconds */
     uint64_t ts_usec;        /* timestamp microseconds */
     uint32_t cap_len;        /* number of octets of packet saved in file */
     uint32_t len;            /* actual length of packet */
   };
   int printf(const char *format, ...);
   pcap_t *pcap_open_offline(const char *fname, char *errbuf);
   void pcap_close(pcap_t *p);
   const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

   typedef struct pcap_dumper pcap_dumper_t;
   pcap_t *pcap_open_dead(int linktype, int snaplen);
   pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
   void pcap_dump(uint8_t *user, struct pcap_pkthdr *h, uint8_t *sp);
   void pcap_dump_close(pcap_dumper_t *p);
]])

function open_offline(pcap_file)
   local pcap_file = ffi.new("char[?]", #pcap_file, pcap_file)
   local errbuf = ffi.new("char[?]", 512)

   -- Read all packets in source
   local handle = pcap.pcap_open_offline(pcap_file, errbuf);
   if handle == nil then
      print(("error reading pcap file: %s"):format(errbuf))
      os.exit();
   end
   return handle
end

function read_packet (pcap_file)
   local handle = open_offline(pcap_file)
   local header = ffi.new("struct pcap_pkthdr")
   local count = 0
   local result, len
   while true do
      local packet = pcap.pcap_next(handle, header)
      if packet == nil then break end
      result = {data = ffi.cast("uint8_t*", packet), len = tonumber(header.len)}
      count = count + 1
   end
   assert(count == 1, ("%s contains more than one packet"):format(pcap_file))
   return result
end

function for_each_packet (handle, f)
   local header = ffi.new("struct pcap_pkthdr")
   while true do
      local packet = pcap.pcap_next(handle, header)
      if packet == nil then break end
      f(packet)
   end
   pcap.pcap_close(handle)
end

function write_packet (pcap_file, p)
   local DLT_EN10MB = 1
   local errbuf = ffi.new("char[?]", 512)
   local handle = pcap.pcap_open_dead(DLT_EN10MB, 2^16);
   local dumper = pcap.pcap_dump_open(handle, pcap_file);

   local pcap_hdr = ffi.new("struct pcap_pkthdr")
   pcap_hdr.cap_len = p.len
   pcap_hdr.len = p.len

   pcap.pcap_dump(ffi.cast("uint8_t*", dumper), pcap_hdr,
      ffi.cast("uint8_t*", p.data))
   pcap.pcap_dump_close(dumper);
end
