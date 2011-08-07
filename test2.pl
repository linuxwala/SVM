use Net::Pcap;

    my $err = '';
    my $dev = pcap_lookupdev(\$err);  # find a device

    # open the device for live listening
    my $pcap = pcap_open_live($dev, 1024, 1, 0, \$err);

    # loop over next 10 packets
    pcap_loop($pcap, 10, \&process_packet, "just for the demo");

    # close the device
    pcap_close($pcap);

    sub process_packet {
        my($user_data, $header, $packet) = @_;
        # do something ...
    }
