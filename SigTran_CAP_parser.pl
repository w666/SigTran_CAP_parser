#! /usr/bin/perl 

################################################
#
# SigTran_CAP parser v. 20120803
# implemented SCTP/M3UA/SCCP/TCAP/CAP
# 
# tested on RHEL 5 only
#
# Copyright (C) 2012 Vasily Martynov vasily.martynov[at]gmail.com
#
# SigTran_CAP parser is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# SigTran_CAP parser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Yamsort.  If not, see <http://www.gnu.org/licenses/>.
#
# code based on http://frox25.no-ip.org/~mtve/wiki/SigTran.html
#
# usage: SigTran_CAP_parser.pl dev
# example: SigTran_CAP_parser.pl eth1
#
# Additional feature:
# Parser has built-in tcp server, it means that you can request some statistics through telnet or simple tcp client
# example: telnet 127.0.0.1 30001
# available commands: begin|end|abort|continue|InitialDP
#
################################################

use strict;
no warnings 'regexp';
use Net::Pcap;
use threads;
use threads::shared;
use IO::Socket;

my $debug_mode = 1; # 1 - on, 0 - off
my $sigtran_debug_level = 4; # 1 - m3ua, 2 - sccp, 3 - tcap, 4 - cap

my $sctp_tag = 0;
my $sctp_itsn;
my $sctp_si = 0;
my $m3ua_rc;

my %TCAP_CAP_STAT : shared;

#
# constants
#
my %SCTP = 
(
	DATA		=> 0,
	INIT		=> 1,
	INIT_ACK	=> 2,
	SACK		=> 3,
	HEARTBEAT	=> 4,
	HEARTBEAT_ACK	=> 5,
	ABORT		=> 6,
	SHUTDOWN	=> 7,
	SHUTDOWN_ACK	=> 8,
	ERROR		=> 9,
	COOKIE_ECHO	=> 10,
	COOKIE_ACK	=> 11,
	ECNE		=> 12,
	CWR		=> 13,
	SHUTDOWN_COMPLETE	=> 14,
);

my %SCTP_PAYLOAD = 
(
	IUA		=> 1,
	M2UA		=> 2,
	M3UA		=> 3,
	SUA		=> 4,
	M2PA		=> 5,
	V5UA		=> 6,
);

my %SCCP_TYPE = 
(
	CR	=> 1,
	CC	=> 2,
	CREF	=> 3,
	RLSD	=> 4,
	RLC	=> 5,
	AK	=> 8,
	UDT	=> 9,
	UDTS	=> 10,
	ED	=> 11,
	EA	=> 12,
	RSR	=> 13,
	RSC	=> 14,
	ERR	=> 15,
	IT	=> 16,
	XUDT	=> 17,
	XUDS	=> 18,
);

my %M3UA_SSNM = 
(
	DUNA	=> 1,
	DAVA	=> 2,
	DAUD	=> 3,
	SCON	=> 4,
	DUPU	=> 5,
	DRST	=> 6,
);

my %ASN1_UNIVERSAL = 
(
	boolean		=> 1,
	integer		=> 2,
	bitStr		=> 3,
	octetStr	=> 4,
	null		=> 5,
	objectId	=> 6,
	real		=> 9,
	enumerated	=> 10,
	relative_oid	=> 13,
	sequence	=> 16,
	set		=> 17,
	printStr	=> 19,
	ia5Str		=> 22,
	utcTime		=> 23,
	generalTime	=> 24,
);

my %TCAP_TYPE = reverse 
(
	unidirectional	=> 1,
	begin		=> 2,
	end		=> 4,
	continue	=> 5,
	abort		=> 7,
);

my %TCAP_COMPONENT = reverse 
(
	invoke			=> 1,
	returnResultLast	=> 2,
	returnError		=> 3,
	reject			=> 4,
	returnResultNotLast	=> 7,
);

my %CAP_APP = reverse 
(
	CAP_GSMSSF_to_GSMSCF		=> 50,
);

my %CAP_OP = reverse 
(
	InitialDP			=> 0,
	AssistRequestInstructions	=> 16,
	EstablishTemporaryConnection	=> 17,
	DisconnectForwardConnection	=> 18,
	ConnectToResource		=> 19,
	Connect				=> 20,
	ReleaseCall			=> 22,
	RequestReportBCSMEvent		=> 23,
	EventReportBCSM			=> 24,
	CollectInformation		=> 27,
	Continue			=> 31,
	InitiateCallAttempt		=> 32,
	ResetTimer			=> 33,
	FurnishChargingInformation	=> 34,
	ApplyCharging			=> 35,
	ApplyChargingReport		=> 36,
	CallGap				=> 41,
	CallInformationReport		=> 44,
	CallInformationRequest		=> 45,
	SendChargingInformation		=> 46,
	PlayAnnouncement		=> 47,
	PromptAndCollectUserInformation	=> 48,
	SpecializedResourceReport	=> 49,
	Cancel				=> 53,
	ActivityTest			=> 55,
	InitialDPSMS			=> 60,
	FurnishChargingInformationSMS	=> 61,
	ConnectSMS			=> 62,
	RequestReportSMSEvent		=> 63,
	EventReportSMS			=> 64,
	ContinueSMS			=> 65,
	ReleaseSMS			=> 66,
	ResetTimerSMS			=> 67,
	ActivityTestGPRS		=> 70,
	ApplyChargingGPRS		=> 71,
	ApplyChargingReportGPRS		=> 72,
	CancelGPRS			=> 73,
	ConnectGPRS			=> 74,
	ContinueGPRS			=> 75,
	EntityReleasedGPRS		=> 76,
	FurnishChargingInformationGPRS	=> 77,
	InitialDPGPRS			=> 78,
	ReleaseGPRS			=> 79,
	EventReportGPRS			=> 80,
	RequestReportGPRSEvent		=> 81,
	ResetTimerGPRS			=> 82,
	SendChargingInformationGPRS	=> 83,
	DFCWithArgument			=> 86,
	ContinueWithArgument		=> 88,
	DisconnectLeg			=> 90,
	MoveLeg				=> 93,
	SplitLeg			=> 95,
	EntityReleased			=> 96,
	PlayTone			=> 97,
);


sub debug
{
	my $message = shift;
        if ($debug_mode)
        {
		print "$message";
	}
}

sub output
{
	my(my $level, my $message) = @_;
        if ($level <= $sigtran_debug_level)
        {
		print "$message";
	}
}
         
sub error($$) 
{
	my ($pkt, $msg) = @_;
	use Data::Dumper;
	print STDERR "pkt = ", Dumper ($pkt) if $pkt;
	print STDERR ">>> ", (caller 1)[3], ": $msg\n";
	print "!!! ", (caller 1)[3], ": $msg\n";
	-die "normal error";
}

sub decode_tlv_nn {
	my ($data) = @_;
	my %hash;
	while (length $data) 
	{
		my ($type, $len) = unpack 'nn', $data;
		$len -= 4;
		($hash{$type}, $data) = unpack "x4 a$len x![N] a*", $data;
	}
	return \%hash;
}

sub hlookup 
{
	my ($href, $key) = @_;
	exists $href->{$key} ? $href->{$key} : "$key?";
}

#
# ethernet
#

sub parse_eth 
{
	my ($pkt, $data) = @_;
	$pkt->{eth} = \my %eth;
	@eth{qw/ dst_mac src_mac type data /} = unpack 'H12H12na*', $data;
	if ($eth{type} == 0x0800) 
	{
		parse_ip ($pkt, $eth{data});
	} 
	else 
	{
		#error $pkt, "type $eth{type}";
	}
}

#
# ip
#

sub in_cksum 
{
	my ($packet) = @_;
	my $plen = length $packet;
	my $num = int ($plen / 2);
	my $chk = 0;
	my $count = $plen;
	
	for (unpack "S$num", $packet) 
	{
		$chk += $_;
		$count = $count - 2;
	}
	if ($count == 1) 
	{
		$chk += unpack "C", substr $packet, $plen - 1, 1;
	}

	$chk = ($chk >> 16) + ($chk & 0xffff);
	return pack 'v', ~(($chk >> 16) + $chk) & 0xffff;
}

sub parse_ip 
{
	my ($pkt, $data) = @_;

	$pkt->{ip} = \my %ip;
	$ip{len} = unpack 'x2n', $data;
	($data, $ip{pad}) = unpack "a$ip{len} a*", $data;
	@ip{qw/ hlen tos len id foffset ttl proto cksum src_ip dst_ip options /} = unpack 'CCnnnCCna4a4a*', $data;
	$ip{ver} = ($ip{hlen} & 0xf0) >> 4;
	$ip{hlen} &= 0x0f;
	error $pkt, "ver $ip{ver}" if $ip{ver} != 4;

	$ip{flags} = $ip{foffset} >> 13;
	$ip{foffset} = ($ip{foffset} & 0x1fff) << 3;

	my $olen = ($ip{hlen} - 5) * 4;
	error $pkt, "negative olen $olen" if $olen < 0;

	@ip{qw/ options data /} = unpack "a$olen a*", $ip{options};
	$ip{src_ip} = join '.', unpack 'C4', $ip{src_ip};
	$ip{dst_ip} = join '.', unpack 'C4', $ip{dst_ip};

	if ($ip{proto} == 0x84) 
	{
		parse_sctp ($pkt, $ip{data});
	} 
	else 
	{
		debug ("$pkt, proto $ip{proto}");
	}
}

#
# sctp
#

sub adler32 
{
	my ($data) = @_;

	my $BASE = 65521;
	my $s1 = 1;
	my $s2 = 0;

	for (unpack 'C*', $data) 
	{
		$s1 = ($s1 + $_)  % $BASE;
		$s2 = ($s2 + $s1) % $BASE;
	}
	return pack 'nn', $s2, $s1;
}

adler32 ("Wikipedia") eq pack 'H*', '11E60398' or die "Broken adler32";

my $init_crc32 = oct reverse sprintf "%032bb0", 0x1EDC6F41; # 0x04C11DB7;
my @crc32 = map 
{
	for my $s (0..7) 
	{
		$_ = $_ >> 1 ^ ($_ & 1 && $init_crc32)
	}
	$_
} 0..255;

sub crc32 
{
	my ($data) = @_;

	my $crc = 0xffffffff;
	for (unpack 'C*', $data) 
	{
		$crc = $crc >> 8 ^ $crc32[$crc & 0xff ^ $_];
	}
	return pack 'V', $crc ^ 0xffffffff;
}

crc32 ("mtve") eq pack 'H*', '90583b2e' or die "Broken crc32";

sub parse_sctp 
{
	my ($pkt, $data) = @_;

	$pkt->{sctp} = \my %sctp;

	@sctp{qw/ src_port dst_port sctp_verif chksum chunks /} = unpack "nnNNa*", $data;

	while (length $sctp{chunks}) 
	{
		
		@sctp{qw/ type flags len chunks /} = unpack 'CCna*', $sctp{chunks};
		@sctp{qw/ value chunks /} = unpack 'a' . ($sctp{len}-4) .'x![N] a*', $sctp{chunks};
		debug ("** sctp\n");
		debug ("** sctp{type} = $sctp{type}\n");
		if ($sctp{type} == $SCTP{HEARTBEAT}) 
		{
			debug ("** got HEARTBEAT\n");

		} 
		elsif ($sctp{type} == $SCTP{DATA}) 
		{
			@sctp{qw/ tsn si ssn ppi userdata /} = unpack "NnnNa*", $sctp{value};
			debug ("** sctp{ppi} = $sctp{ppi}\n");
			error $pkt, "DATA flags $sctp{flags}" if ($sctp{flags} & 3) != 3;
			$sctp_si = $sctp{si};
			if ($sctp{ppi} == $SCTP_PAYLOAD{M3UA}) 
			{
				parse_m3ua ($pkt, $sctp{userdata});
			} 
			else 
			{
				error $pkt, "DATA payload " . hlookup ({reverse %SCTP_PAYLOAD}, $sctp{ppi});
			}

		} 
		elsif ($sctp{type} == $SCTP{SACK}) 
		{
			# do nothing
		} 
		elsif ($sctp{type} == $SCTP{INIT_ACK}) 
		{
			debug ("*** got sctp INIT_ACK, sending sctp COOKIE_ECHO\n");

			@sctp{qw/ itag arwc nos nis itsn value /} = unpack "NNnnNa*", $sctp{value};
			$sctp{tlv} = decode_tlv_nn ($sctp{value});

			$sctp_tag = $sctp{itag};
			$sctp_itsn = $sctp{itsn};

			my $cookie = $sctp{tlv}{7} or error $pkt, "COOKIE without cookie";

		} 
		elsif ($sctp{type} == $SCTP{COOKIE_ACK}) 
		{
			debug ("*** got sctp COOKIE_ACK, sending m3ua ASPUP\n");

		}
		elsif ($sctp{type} == $SCTP{ABORT}) 
		{
			debug ("*** got sctp ABORT, exiting\n");

		} 
	}
}

#
# m3ua
#

sub parse_m3ua 
{
	my ($pkt, $data) = @_;
	$pkt->{m3ua} = \my %m3ua;
	@m3ua{qw/ ver class type len tlvs /} = unpack 'CxCCNa*', $data;
	
	debug ("*** m3ua\n");
	debug ("*** m3ua{class} = $m3ua{class}, m3ua{type} = $m3ua{type}\n");
	
	error $pkt, "ver $m3ua{ver}!=1" if $m3ua{ver} != 1;
	$m3ua{param} = decode_tlv_nn ($m3ua{tlvs});

	if ($m3ua{class} == 1 && $m3ua{type} == 1) 
	{ # DATA

		error $pkt, 'no Protocol Data in DATA' if !exists $m3ua{param}{0x0210};
		@m3ua{qw/ opc dpc si ni mp sls userdata /} = unpack 'NNCCCCa*', $m3ua{param}{0x0210};
		debug ("*** m3ua{si} = $m3ua{si}\n");
	
		if ($m3ua{si} == 3) 
		{
			output(1,"*** M3UA\n");
			output(1,"*** OPC = $m3ua{opc}\n");
			output(1,"*** DPC = $m3ua{dpc}\n");
			parse_sccp ($pkt, $m3ua{userdata});
		} 
		else 
		{
			error $pkt, "si $m3ua{si}";
		}

	} 
	elsif ($m3ua{class} == 0 && $m3ua{type} == 1) 
	{
		if ($m3ua_rc) 
		{
			debug ("*** got m3ua NTFY again\n");
			return;
		}

		$m3ua_rc = unpack 'N', $m3ua{param}{6};
		debug ("*** got m3ua NTFY(routing context=$m3ua_rc)\n");

	} 
	elsif ($m3ua{class} == 2) 
	{
		my ($mask, $apc) = exists $m3ua{param}{0x0012} ? unpack 'CXN', $m3ua{param}{0x0012} : ('?', '?');
		debug ("*** got m3ua management " . hlookup ({reverse %M3UA_SSNM}, $m3ua{type}) . " apc=$apc/$mask\n");
	} 
	elsif ($m3ua{class} == 3 && $m3ua{type} == 4) 
	{ 
		debug ("*** got m3ua ASPUP_ACK\n");
	} 
	elsif ($m3ua{class} == 4 && $m3ua{type} == 3) 
        { 
		debug ("*** got m3ua ASPAC_ACK\n");
	} 
}

#
# sccp
#

sub parse_sccp 
{
	my ($pkt, $data) = @_;
	$pkt->{sccp} = \my %sccp;
	$sccp{type} = unpack 'C', $data;

	if ($sccp{type} == $SCCP_TYPE{UDTS}) 
	{
		$sccp{cause} = unpack 'xC', $data;
		if ($sccp{cause} == 1) 
		{
			error $pkt, "UTDS cause: no gtt";
		} 
		else 
		{
			error $pkt, "UTDS cause $sccp{cause}";
		}
		return;
	}

	error $pkt, "type " . hlookup ({reverse %SCCP_TYPE}, $sccp{type}) if $sccp{type} != $SCCP_TYPE{UDT};
	@sccp{qw/ type class ptr1 ptr2 ptr3 cdpabin cgpabin data /} = unpack 'CCCCCC/aC/aC/a', $data;

	for (qw/ cdpa cgpa /) 
	{
		my $a = $sccp{"${_}bin"};
		$sccp{$_} = \my %a;

		(my ($ai), $a) = unpack 'Ca*', $a;

		$a{ri} = $ai & 64;
		$a{gti} = $ai >> 2 & 7;

		($a{pc}, $a) = unpack 'va*', $a if $ai & 1;
		($a{ssn}, $a) = unpack 'Ca*', $a if $ai & 2;

		if ($a{gti} == 0) 
		{
		} 
		elsif ($a{gti} == 2) 
		{
			($a{tt}, $a) = unpack 'Ca*', $a;
		} 
		elsif ($a{gti} == 4) 
		{
			(@a{qw/ tt planenc nai /}, $a) = unpack 'CCCa*', $a;
		} 
		else 
		{
			error $pkt, "gti $a{gti}";
		}

		$a{address} = unpack 'h*', $a;
		#print "$a{address}\n";
		chop $a{address} if ($a{planenc} || 0) & 1;
	}
	debug ("**** sccp\n");
	debug ("**** sccp{type} = $sccp{type}\n");
	output(2,"**** SCCP\n");
	output(2,"**** cgpn GT = $sccp{cgpa}->{address}\n");
	output(2,"**** cdpn GT = $sccp{cdpa}->{address}\n");
	tcap_parse ($pkt, $sccp{data});
}

#
# asn.1
#

sub asn1_decode_pdu 
{
        my ($dataref, $tab) = @_;
        (my ($type), $$dataref) = unpack 'Ca*', $$dataref;
        my $txt = qw/ universal application context private /[$type >> 6];

        my $tag = $type & 0x1f;
        ($tag, $$dataref) = unpack 'wa*', $$dataref if $tag == 0x1f;
        (my ($len), $$dataref) = unpack 'Ca*', $$dataref;
        if ($len & 0x80) 
        {
                $len &= 0x7f;
                die "len is more then 4 bytes" if $len > 4;
                ($len, $$dataref) = unpack "a$len a*", $$dataref;
                $len = unpack 'N', "\0" x (4 - length $len) . $len;
        }
        die "message too short" if length $$dataref < $len;

        (my ($val), $$dataref) = unpack "a$len a*", $$dataref;

        if ($type & 0x20) 
        {
                my $t = '';
                my $ta = "$tab   ";
                $t .= $ta . asn1_decode_pdu (\$val, $ta) . "\n" while length $val;
                $val = "<\n$t$tab>";
        } 
        else 
        {
                $val = '= "' . unpack ('H*', $val) . '"';
        }

        return "${txt}_$tag $val";
}

sub asn1_decode 
{
        my ($data) = @_;

        my $ret = asn1_decode_pdu (\$data, '');
        warn "garbage at the end" if length $data;
        return $ret;
}


#
# tcap
#

my $d_re = qr/[0-9a-f]*/;
my $asn1_re;
{
        use re 'eval';
        $asn1_re = qr/ \w+\d+ = "$d_re" | \w+\d+ < (?:(??{ $asn1_re }))* > /x;
}

sub tcap_fix 
{
	my ($pkt) = @_;
	$pkt->{tcap}{ac} = sprintf '0400000100%02x0%1d', {reverse %CAP_APP}->{ $pkt->{tcap}{application} }, $pkt->{tcap}{ver};
	$pkt->{tcap}{opCode} = sprintf '%02x', {reverse %CAP_OP}->{ $pkt->{tcap}{operation} };
}

sub tcap_parse 
{
	my ($pkt, $data) = @_;
	$pkt->{tcap} = \my %tcap;
	my $in = asn1_decode ($data);
	$tcap{in} = $in;
	$in =~ s/\s+//g;
	#debug ("***** tcap bin1 = $in\n");
	(my $type) = $in =~ /^application_(\d+)</ or error $pkt, 'no match';

	exists $TCAP_TYPE{$type} or error $pkt, "type $type";
	$tcap{type} = $TCAP_TYPE{$type};
	$TCAP_CAP_STAT{$TCAP_TYPE{$type}} = $TCAP_CAP_STAT{$TCAP_TYPE{$type}} + 1;
	$type = "tcap_parse_$TCAP_TYPE{$type}";
	debug ("***** tcap\n");
	debug ("***** tcap{type} = $tcap{type}\n");
	debug ("***** tcap parse func = $type\n");
	output(3,"***** TCAP\n");
	output(3,"***** TCAP type = $tcap{type}\n");
	no strict 'refs';
	exists &$type or debug ("*****$pkt, unimplemented $type\n");
	$type->($pkt, $in);
}

sub tcap_parse_begin 
{
	my ($pkt, $in) = @_;
	my $tcap = $pkt->{tcap};
	@{ $tcap }{qw/ otid oid ac component invokeId opCode cap /} = $in =~ qr!^

application_2 <					# begin
   application_8 = "($d_re)"			# otid			1
   application_11 <				# dialoguePortion
      universal_8 <				# ExternalPDU
         universal_6 = "($d_re)"		# oid			2
         context_0 <				# dialog
            application_0 <			# dialogueRequest
               context_0 = "0780"		# protocol-versionrq
               context_1 <			#
                  universal_6 = "($d_re)"	# application-context-name	3
               >
            >
         >
      >
   >
   application_12 <				# components
      context_(1) <				# invoke
         universal_2 = "($d_re)"		# invokeID		4
         universal_2 = "($d_re)"		# opCode		5
         ($asn1_re*)				# GSM_CAP		6
      >
   >
>
	\z!x or error $pkt, 'no match';
	output(3,"***** TCAP otid = $tcap->{otid}\n");

	tcap_parse_cont ($pkt);
}

sub tcap_parse_continue 
{
	my ($pkt, $in) = @_;
	my $tcap = $pkt->{tcap};

	@{ $tcap }{qw/ otid dtid oid ac component invokeId opCode gsmmap /} = $in =~ qr!^
application_5 <					# begin
   application_8 = "($d_re)"			# otid			1
   application_9 = "($d_re)"			# dtid			1
   application_11 <				# dialoguePortion
      universal_8 <				# ExternalPDU
         universal_6 = "($d_re)"		# oid			2
         context_0 <				# dialog
            application_1 <			# dialogueRequest
               context_0 = "0780"		# protocol-versionrq
               context_1 <			# application-context-name
                  universal_6 = "($d_re)"	#			3
            	>
	    >
	>
    >
>
>
  application_12 <				# components
      context_(1) <				# invoke
         universal_2 = "($d_re)"		# invokeID		4
         universal_2 = "($d_re)"		# opCode		5
         ($asn1_re*)				# GSM_CAP		6
      >
   >
>
	\z!x or debug ("$pkt, no match\n");
	output(3,"***** TCAP otid = $tcap->{otid}\n");
	output(3,"***** TCAP dtid = $tcap->{dtid}\n");
	# There is a problem with tcap_continue matching. It will be implemented later
	#tcap_parse_cont ($pkt);
}

                
                
sub tcap_parse_end 
{
	my ($pkt, $in) = @_;
	my $tcap = $pkt->{tcap};
	@{ $tcap }{qw/ dtid oid ac component invokeId opCode /} = $in =~ qr!^

application_4 < 
    application_9 = "($d_re)" 		# dtid
    application_11 < 
	universal_8 < 
	 universal_6 = "($d_re)"	# oid
	 context_0 < 
	    application_1 < 
		context_0 = "0780"
		context_1 < 
		    universal_6 = "($d_re)" # application context
		    >
		context_2 < 
		    universal_2 = "00" > 
		context_3 < 
		    context_1 < 
			universal_2 = "00"
			>
		    >
		>
	    >
	>
    >
application_12 < 
    context_(1) < 			# component
	universal_2 = "($d_re)"		# invoke id
	universal_2 = "($d_re)">	# OP code
    >
>

    \z!x or

	@{ $tcap }{qw/ dtid oid ac component invokeId opCode /} = $in =~ qr!^
application_4 < 
    application_9 = "($d_re)"           # dtid
    application_11 < 
	universal_8 < 
	    universal_6 = "($d_re)"        # oid
	    context_0 < 
	     application_1 < 
	        context_1 < 
	    	    universal_6 = "($d_re)" # application context
	    	    context_2 < 
	        	universal_2 = "00" > 
	    	    context_3 < 
	    		context_1 < 
	    		    universal_2 = "00">
	    		>
		    >
		>
	    >
	>
    >
application_12 < 
    context_(1) <			# component 
	universal_2 = "($d_re)"         # invoke id
	universal_2 = "($d_re)">        # OP code
    >
>
	
	\z!x or 

	@{ $tcap }{qw/ dtid oid ac component invokeId opCode releaseCause /} = $in =~ qr!^
application_4 < 
    application_9 = "($d_re)"           # dtid
    application_11 < 
	universal_8 < 
	    universal_6 = "($d_re)"        # oid
	    context_0 < 
	     application_1 < 
	        context_1 < 
	    	    universal_6 = "($d_re)" # application context
	    	    context_2 < 
	        	universal_2 = "00" > 
	    	    context_3 < 
	    		context_1 < 
	    		    universal_2 = "00">
	    		>
		    >
		>
	    >
	>
    >
application_12 < 
    context_(1) < 			# component
	universal_2 = "($d_re)"         # invoke id
	universal_2 = "($d_re)"         # OP code
	universal_4="($d_re)">		# Cause IE (Q.850) 1 bit - Extension bit, 2 bits - Coding standart, 1 bit - spare, 4 bits - Location, 1 bit - Extension Bit, 7 bits - Cause Value
    >
>
	\z!x or	debug ("$pkt, no match\n");
	output(1,"***** TCAP dtid = $tcap->{dtid}\n");
	tcap_parse_cont ($pkt);
}

sub tcap_parse_abort 
{
	my ($pkt, $in) = @_;
	my $tcap = $pkt->{tcap};
	@{ $tcap }{qw/ dtid  /} = $in =~ qr!^

application_7 <					# end
   application_9 = "($d_re)"			# dtid			1
   >
	\z!x or error $pkt, 'no match';
	output(3,"***** TCAP dtid = $tcap->{dtid}\n");
	# There is no AC in tcap_abort that's whay no reason to parse it
	#tcap_parse_cont ($pkt);
}

sub tcap_parse_cont 
{
	my ($pkt) = @_;

	my $tcap = $pkt->{tcap};
	debug ("****** tcap{ac} = $tcap->{ac}\n");
	(my ($ac), $tcap->{ver}) = $tcap->{ac} =~ /0400000100(\w\w)0(\d)/ or error $pkt, 'ac';
	$ac = hex $ac;
	debug ("****** tcap ac = $ac\n");
	debug ("****** CAP_APP{ac} = $CAP_APP{$ac}\n");
                                        
	exists $CAP_APP{$ac} or error $pkt, "unknown application $ac";
	$tcap->{application} = $ac = $CAP_APP{$ac};
	my $c = int($tcap->{component});
	exists $TCAP_COMPONENT{$c} or error $pkt, "unknown component type $c";
	$c = $TCAP_COMPONENT{$c};

	error $pkt, 'opcode len is more then byte' if length $tcap->{opCode} > 2;
	my $op = hex $tcap->{opCode}; 
	exists $CAP_OP{$op} or print "$pkt, unknown operator $op\n";

	$tcap->{operation} = $op = $CAP_OP{$op};
	$TCAP_CAP_STAT{$CAP_OP{$op}} = $TCAP_CAP_STAT{$CAP_OP{$op}} + 1;
	output(4,"****** CAP\n");
	output(4,"****** CAP AC = $tcap->{application}\n");
	output(4,"****** CAP OP = $tcap->{operation}\n");
	
	if ($tcap->{releaseCause})
	{
		my %releaseCause;
		@releaseCause{qw/ ext cod spare loc ext2 rc /} = unpack 'aa2aa4aa7', hex2bin($tcap->{releaseCause});
		$releaseCause{rc} = bin2dec($releaseCause{rc});
		output(1,"****** CAP release cause = $releaseCause{rc}\n");
	}

	
	$op = "gsmcap_${c}_$op";

	no strict 'refs';
	if (exists &$op) 
	{
		$op->($pkt, $tcap->{cap});
	} 
	else 
	{
		output(1,"****** CAP operation $op is not implemented\n");
	}
}

sub gsmcap_invoke_InitialDP 
{
	my ($pkt, $in) = @_;
	my $cap = $pkt->{cap};
# Structure of CAP message
#	@{ $cap }{qw/ skey cgpn locationnumber imsi ageoflocation vlr cellid telecode callrefnumber mscaddr cdpn timezone/} = $in =~ qr!^
#universal_16 
#            < 
#            context_0 = "($d_re)"			# Service Key
#            context_3 = "($d_re)"			# cgpn (first 2 octets are odd, nai, complete indicator, npi, address presentation restricted indicator, screening indicator) )
#            context_5 = "0a"				# calling party's category (Q.763)
#            context_8 = "00"				# IPSSP capatible
#            context_10 = "($d_re)"			# Location number (Q.763)
#            context_23 = "9181"			# High layer compatbility (Q.931)
#            context_27 < 			
#                       context_0 = "8090a3"		# Bearer capability (Q.931)
#                       >				
#            context_28 = "02"				# Event type BCSM (2 - collect info)
#            context_50 = "($d_re)"			# IMSI (MCC/MNC/MSIN)
#            context_52 < 				# Location Information
#                       universal_2 = "($d_re)"		# Age of location information (elapsed time in mn) ???
#                       context_1 = "($d_re)"		# VLR number
#                       context_3 < 			
#                                 context_0 = "($d_re)" # Cell Id (2 octets - MCC, 1 octet - MNC, 2 octets - LAC, 2 octets - CI)
#                                 >
#                       >
#            context_53 <
#                       context_3 = "($d_re)" 		# Teleservice code (HEX 11 (DEC 17) telephony)
#                       >
#            context_54 = "($d_re)"			# Call reference number
#            context_55 = "($d_re)"			# MSC Address
#            context_56 = "($d_re)"			# cdpn (Called party BCD number) 2 octets - extension bit, ton, npi 
#            context_57 = "($d_re)"			# Time and timezone (4 octets - YYYY/MM/DD, 3 octets - HH:MN:SS, 1 octet - Timezone)
#            >

@{$cap}{qw/ skey /} = $in =~ /universal_16<context_0="($d_re)"/ or output(4,"****** CAP skey = not found\n");
@{$cap}{qw/ cgpn /} = $in =~ /universal_16<(a-z0-9=)context_3="($d_re)"/ or output(4,"****** CAP cgpn = not found\n");
@{$cap}{qw/ eventtype /} = $in =~ /context_28="($d_re)"/ or error $pkt, 'no match event type';
@{$cap}{qw/ imsi /} = $in =~ /context_50="($d_re)"/ or output(4,"****** CAP imsi = not found\n");
@{$cap}{qw/ callrefnumber /} = $in =~ /context_54="($d_re)"/ or error $pkt, 'no match callrefnumber';
@{$cap}{qw/ mscaddr /} = $in =~ /context_55="($d_re)"/ or error $pkt, 'no match mscaddr';
@{$cap}{qw/ cdpn /} = $in =~ /context_56="($d_re)"/ or error $pkt, 'no match cdpn';
@{$cap}{qw/ timezone /} = $in =~ /context_57="($d_re)"/ or error $pkt, 'no match timezone';

output(4,"****** CAP skey = $cap->{skey}\n") if ($cap->{skey});

my %cgpn_number;
my %cdpn_number;
if ($cap->{cgpn})
{
	@cgpn_number{qw/ prefix address /} = unpack 'A4a*', $cap->{cgpn};
	output(4,"****** CAP cgpn = ".ber_decode($cgpn_number{address})."\n");
}
if ($cap->{cdpn})
{
	@cdpn_number{qw/ prefix address /} = unpack 'A2a*', $cap->{cdpn};
	output(4,"****** CAP cdpn = ".ber_decode($cdpn_number{address})."\n");
}

output(4,"****** CAP event type = ".$cap->{eventtype}."\n");
output(4,"****** CAP imsi = ".ber_decode($cap->{imsi})."\n") if ($cap->{imsi});;

}


sub bin2dec
{
	return unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
}

sub hex2bin
{
	my $h = shift;
        my $hlen = length($h);
	my $blen = $hlen * 4;
	return unpack("B$blen", pack("H$hlen", $h));
}

sub ber_decode
{
my @address = split(//, shift);
my $new_address;
my $length = @address;
for (my $i=0; $i<=$length; $i+=2)
    {
        if (($i+1) <= $length)
        {
	    $new_address = $new_address.$address[$i+1].$address[$i];
	}
    }
return  $new_address;
}

# tcp server thread

our @clients : shared;
@clients = ();
sub tcp_server
{
	my $server = new IO::Socket::INET(
	Timeout   => 7200,
	Proto     => "tcp",
	LocalPort => 30001,
	Reuse     => 1,
	Listen    => 3
	);
	my $num_of_client = -1;

	while (1) 
	{
    		my $client;
		do 
		{
    			$client = $server->accept;
		} 
		until ( defined($client) );

		my $peerhost = $client->peerhost();
	        print "accepted a client $client, $peerhost, id = ", ++$num_of_client, "\n";
		my $fileno = fileno $client;
		push (@clients, $fileno);
		my $thr = threads->new( \&processit, $client, $fileno, $peerhost ) ->detach(); 
	}
}

sub processit 
{
     my ($client,$fileno,$peer) = @_; #local client
        
     if($client->connected){
          print $client "$peer->Welcome to SigTran_CAP parser server\n";  
          while(<$client>)
          {
              foreach my $fn (@clients) 
              { 
                  open my $fh, ">&=$fn" or warn $! and die;
                  if ($_=~m/(InitialDP)/)
                  {
                	print $fh "$TCAP_CAP_STAT{$CAP_OP{$_}}";
                  }
                  elsif ($_=~m/(begin|end|abort|continue)/)
                  {
                  	print $fh  "$TCAP_CAP_STAT{$TCAP_TYPE{$_}}";
                  }
                  else 
                  {
                	print $fh " $TCAP_CAP_STAT{$CAP_OP{InitialDP}}";
                  }
              }
          }
    }
  close( $client);
  @clients = grep {$_ !~ $fileno} @clients;
}

my ($tcp,$ip,$ethernet);
my ($net,$mask,$err);
my $dev = $ARGV[0];

my $tcp_server_thread = threads->new(\&tcp_server) -> detach();

sub capture_packets
{
	my ($user_data, $hdr, $pkt) = @_;
        my $ttt = {};
        parse_eth($ttt, $pkt);
}

if (Net::Pcap::lookupnet($dev, \$net, \$mask, \$err) == -1)
{
	die 'Cannot determine network number and subnet mask - ' , $err;
}

my $pcap_object = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);

if (defined $err)
{
	die 'Failed to create live capture on - ' , $dev , ' - ', $err;
}
Net::Pcap::loop($pcap_object, -1, \&capture_packets, '') || die 'Unable to perform packet capture';
