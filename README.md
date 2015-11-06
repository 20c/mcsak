
# MultiCast Swiss Army Knife

mcsak is a utility to join multicast groups and capture messages sent.
It does simple decoding and gap alerting for message formats that contain
sequence numbers.


## Decoding

Multiple decoders are supported, both cme and ice have sequence numbers so
gaps will also be tracked, otherwise decoding is just done if packets are
output.  No decoder results in the raw binary stream being output.

cme: decode Chicago Mercantile Exchange's FAST 2.0 or MDP 3.0 feeds
hex: decode to hex
ice: decode IntercontinentalExchange's iMpact
text: decode to ascii


## Alerts

If the format contains a sequence number, mcsak will decode it and monitor for
gaps, if a gap is found, it will send an alert.

It currently sends errors and alerts to the same place, to tie into a
monitoring system, set the quiet option (or send a patch).

To test on linux, you can simulate gaps with:

    iptables -A INPUT -i $INTF -m limit —limit 1/m —limit-burst 5 -j DROP

## Capturing

To capture packets to a file, use -F or capture_file in the config file.


## Emitting

To emit packets either from a file or address, use emit_* functions.


## Usage


## Config file

Config file is INI format.  The section name mcsak is reserved for global
options, any other section names can be used to specify multicast groups.
Config file will overwrite command line options.

See `example.ini` for details.

