#!/usr/bin/perl -w
# libcpap library , pcap programming , cpan perl interface
#SIP=Session Initiation Protocol , SDP=Session Description Protocol
# Test open_offline
#
# $Id: 06-offline.t,v 1.7 1999/05/05 02:11:56 tpot Exp $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

use Getopt::Long qw(:config posix_default bundling);

use Net::SIP ':all';



#print "Part 1:printing packets from file \n\n";


my($result,$filter,$mask,$net,$result1);



my($pcap_t, $err);
#my $dumpfile = "/tmp/Net-Pcap-dump.$$";
my $dumpfile= "/home/sarang/libpcap/SIP/dataset_inria/asterisk-traces/asterisk-traces/SPITTER-50-ASTERISK-10/spitter-50-asterisk-10.cap";
#my $dumpfile= "asterisk-1.cap";
#my $dumpfile1="/home/VoIP_Tools/Net-Pcap-0.05/t/dumpfiles/try1";
my $dumpfile1="dumpfiles/try2";

my $dev = Net::Pcap::lookupdev(\$err);
$result=Net::Pcap::lookupnet(\$dev,\$net,\$mask,\$err);

# Must run as root


#print "\nRESULT1 $result\n";


if ($UID != 0 && $^O !~ /cygwin/i)
	{
    		print("1 not ok\n");
    		exit;
	}


#$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);
$pcap_t = Net::Pcap::open_offline($dumpfile, \$err);


if (defined($pcap_t)) 
	{
		#    print("Net::Pcap::open_offline worked for dummy file\n");
		#    print("open_offline: not ok\n");
	} 
else 
	{
		#    print("open_offline: ok\n");
	}

#print "\n\nPcap :$pcap_t\n\n";

$result = Net::Pcap::compile($pcap_t, \$filter, "udp", 0, \$mask);
if ($result == -1) 
	{
    		print("Net::Pcap::compile returned ", Net::Pcap::geterr($pcap_t), "\n");
   		 print("compile: not ok\n");
	} 
	else
	 {
    		print("compile: ok\n");
	}

#print "\nRESULT2 $result\n";


$result = Net::Pcap::setfilter($pcap_t, $filter); #filtering packets
if ($result == -1) 
	{
   		print(Net::Pcap::geterr($pcap_t), "\n");
  		print("setfilter: not ok\n");
	} 
	else 
	{
  		print("setfilter: ok\n");
	}




if (!defined($pcap_t))
 	{
 	   print("Net::Pcap::open_live returned error $err\n");
 	   print("not ok\n");
 	   exit;
	}

if (!-f $dumpfile) 
	{
    		print("No save file created\n");
    		print("not ok\n");
	} 
	else 
	{
    		print("ok\n");
	}

#$pcap_t = Net::Pcap::open_offline($dumpfile, \$err);

if (!defined($pcap_t)) 
	{
    		print("Net::Pcap::open_offline failed: $err\n");
    		print("not ok\n");
    		exit;
	}

my($major, $minor, $swapped);

$major = Net::Pcap::major_version($pcap_t);
$minor = Net::Pcap::minor_version($pcap_t);
$swapped = Net::Pcap::is_swapped($pcap_t);

print("File saved with libpcap version $major.$minor, swap is $swapped\n");

if ($major == 0) 
	{
		print("suspicious libpcap major version\n");
    		print("not ok\n");
	} 
	else 
	{
    		print("ok\n");
	}

my $count = 0;



my $value1;
my $FHANDLE;
my $variable;

print "\n\nPart 3: Printing after header skip and single packet parameters from file\n\n";
my $c=0;	#Total number of SIP packets
my $req=0;	#Total number of request messages
my $resp=0; 	#Total number of response messages
my $sdp=0;	#Total number of SDP messages

#my $pcap = Net::Pcap::open_offline($dumpfile, \$err);
	  
my $reg=0;
my $inv=0;
my $notacall=0;
my $completed=0;
my $incall=0;  #{ack-bye}U{ringing-ok}U{busy}U{temp unavailable}U{Busy everywhere}U{Decline}U{not accepted}
my $incall1=0; #ringing 180-ok 200 
my $rejected=0;
my $callset=0; #{unauthorized}U{ringing-invite}

my $ringing=0;
my $ok=0;
my $busy=0;
my $tempunavail=0; #temporarily unavailable 480
my $busyeverywhere=0; #Busy everywhere 600=callee was contacted successfully but does not want to take the call
my $decline=0; #decline 603
my $notaccepted=0; #user's agent was contact successfully but session not supported by the resources available 606
my $unauthorized=0; #401 unauthorized

my $bye=0;
my $opt=0;
my $can=0;
my $ref=0;
my $sub=0;
my $not=0;
my $info=0;
my $pra=0;
my $mes=0;
my $ack=0;
my $up=0;
my $succ=0;
my $red=0;
my $cfail=0;
my $sfail=0;
my $gfail=0;
my $inf=0;

my $residue=0;      
my $methodflag=0;     

#Time parameters      
   my $win1;
   my $hdr;
   my $temp; 
   my $win2=0;
   
   my $reqtime1;
   my $reqtime2;
   my $interreq;   
   
   my $resptime1;
   my $resptime2;
   my $interresp;  
   
   my $sdptime1;
   my $sdptime2;
   my $intersdp;    
   
   my $calltime1;
   my $calltime2;
   my $intercall;      
         
#Group 1-General Characteristics
my $duration; #total time slice
my $nbreq;    #no.of requests/total no. of msg  	  
my $nbresp;   #no. of responses/total no. of msg
my $nbsdp;    #no. of messages carrying SDP/total no. of msg 
my $avinterreq=0; #avg. interarrival of requests
my $avinterresp=0; #avg. interarrival of responses
my $avintersdp=0;  #avg. interarrival of msg carrying SDP bodies

#Group 2- Call-ID based statistics
#No. of call IDs - ncallid declared below
my $avmsg;   #avg no. of msg per call ID	
my $avduration=0; #avg. duration of a call ID

#Group 3 - Dialogs' Final State Distribution
my $nbcanceled;	 #no.of cancelled/total no. of call ID
my $nbcompleted=0; #no. of completed/total no. of call ID
my $nbnotacall=0; #no.of notacall/total no. of call ID
my $nbincall=0; #no.of completed/total no. of call ID
my $nbrejected=0; #no. of rejected/total no. of call ID
my $nbresidue=0; #no. of residue/total no. of call ID
my $nbcallset=0; #no. of callset/total no. of call ID

#Group 4 - Request Distribution
my $nbreg=0;   #no. of register/total no. of requests
my $nbinv=0;   #no. of invite/total no. of requests
my $nbbye=0;   #no. of bye/total no. of requests
my $nbopt=0;   #no. of options/total no. of requests
my $nbcan=0;   #no. of cancel/total no. of requests
my $nbref=0;   #no. of refer/total no. of requests
my $nbinf=0;   #no. of info/total no. of requests
my $nbsucc=0;  
my $nbsub=0;   #no. of subscribe/total no. of requests
my $nbnot=0;   #no. of notify/total no. of requests

my $nbsenders=0; #no. of different senders/total # of call-IDs
my $nbreceivers=0; #no. of different receivers/total # of call-IDs

my $nbpra=0;   #no. of prack/total no. of requests
my $nbmes=0;   #no. of message/total no. of requests
my $nback=0;   #no. of ack/total no. of requests
my $nbupd=0;   #no. of update/total no. of requests

#Group 5 - Response Distribution
my $nb1xx=0;  #no. of informational resp/total no. of responses
my $nb2xx=0;  #no. of success resp/total no. of responses
my $nb3xx=0;  #no. of redirection resp/total no. of responses
my $nb4xx=0;  #no. of client error msg/total no. of responses
my $nb5xx=0;  #no. of server error msg/total no. of responses
my $nb6xx=0;  #no, of global error resp/total no. of responses


my @allcallid=(0);
my @uncallid=(0);		#Array of unique call-ids
my @ccallid=(0);		#Array of number of messages per call-id
my $ncallid=0; 			#no. of call IDs
my $i;
my $flag=0;
 

my @allsenders=(0);
my @unsenders=(0);
my @allreceivers=(0);
my @unreceivers=(0);
my @features=(0);

my $nsenders;
my $nreceivers;

open (MYFILE,'>vectors.txt');
   Net::Pcap::loop($pcap_t, -1, \&process_pkt3, "123");
   	#Pcap::loop arguments 1. Object returned from Pcap::open_live method
   	# 2. no. of packets to capture
   	# 3. Subroutine reference to callback function
   	#if packets are negative=captures packets indefinitely.
   Net::Pcap::close($pcap_t); #close the packet device
   
   
# my ($reg,$inv,$bye)=0;


#process_pkt3=callback function my($user_data,$header,$packet)
#callback function receives len,caplen,tv_sec arguments when called
sub process_pkt3 
	{
	 	my($out, $hdr, $pkt) = @_;
		       
	        my $hdrskip = 42   ;
	       
  	        my $payload = substr($pkt, $hdrskip);
		if($payload=~ m/SIP/)
		{
		   $c++;
		   print "\n\nPacket $c:-\n\n";  
                   print "------------------------------------------------------\n";
				
	  	   my $pkt1 = Net::SIP::Packet->new_from_string($payload);
		   #	print $pkt1->as_string;
		   if($c==1)
	           	{
				$win1=$hdr->{'tv_sec'}; #tv_sec=seconds value of the packet timestamp
				my $win3=localtime($win1); #converts to localtime
			        print "TV_SEC:$win3";	#tv_sec=seconds since the epoch  
				$reg=0;
				$inv=0;
				$notacall=0;
				$bye=0;
				$opt=0;
				$can=0;
				$ref=0;
				$sub=0;
				$not=0;
				$info=0;
				$pra=0;
				$mes=0;
				$ack=0;
				$up=0;
				$succ=0;
				$red=0;
				$cfail=0;
				$sfail=0;
				$gfail=0;
				$inf=0;
				$win2=$win1+15; #window of size 5 seconds
			}
		  #print $pkt1->as_string;
                  #$win1=$hdr->{'tv_sec'};
		  print "\nTV_SEC:$win1";
				         
					
		  #checking if a packet is SDP
		  if($pkt1->sdp_body())
	         	 {
				$sdp++;
				if($sdp==1)
					{
						$sdptime1=0;
					}
					$sdptime2=$hdr->{'tv_sec'};
					$intersdp=$sdptime2-$sdptime1;
					$avintersdp=$avintersdp+$intersdp;
					$sdptime1=$sdptime2;
					
					##print "\nInterarrival SDP time:$intersdp\nNo.of SDP bodies=$sdp\n";
		  	 }
					
		  my $to1=$pkt1->get_header('to'); #get_header(FIELD) returns the value for the named FIELD. 
		  my $from1=$pkt1->get_header('from');
		  my $callid=$pkt1->get_header('call-id');
		  my $contact=$pkt1->get_header('contact');
		  my $cseq=$pkt1->get_header('cseq');
		  	  
		  print "\n---------------------------------\n";
		  ##print "from\t$to1";
		  ##print "\nto\t$from1";
		  ##print "\ncallid\t$callid";
		  ##print "\nContact\t $contact";
		  ##print "\nCSeq\t $cseq\n";
		  
		  #print "\nCall-ID: $callid\n";
		  $allcallid[$c]=$callid;
		  if($c==1) #c=total no. of SIP messages
		  	{
				$uncallid[$c]=$callid;  #uncallid=unique call IDs - Array
				$ncallid++;
				
				if($ncallid==1)
					{
						$calltime1=0;
					}
					$calltime2=$hdr->{'tv_sec'};
					$intercall=$calltime2-$calltime1;
					$avduration=$avduration+$intercall;
					$calltime1=$calltime2;
					
					##print "\nDuration of the call:$intercall\nNo.of call-IDs=$ncallid\n";
				
				$ccallid[$ncallid]=1;	#ccallid=no. of msg per call ID - Array
			}
					
		if($c>1)
			{	
				for $i (1 .. $ncallid)
				{
					if($uncallid[$i] eq $callid )
						{
		 					$flag=1;
							$ccallid[$i]=$ccallid[$i]+1;							
						}
							
				}
		
						
				if ($flag==0)
					{
						$ncallid++;
						
						$calltime2=$hdr->{'tv_sec'};
						$intercall=$calltime2-$calltime1;
						$avduration=$avduration+$intercall;
						$calltime1=$calltime2;
					
						##print "\nDuration of the call:$intercall\nNo.of call-IDs=$ncallid\n";
							
						if($ncallid==1)
						{
						$calltime1=0;
						}
						
						
						#	$flag=0;
						#			print "New callid $allcallid[$c]";
						$uncallid[$ncallid]=$callid;
						$ccallid[$ncallid]=1;
						
						$unsenders[$ncallid]=$to1;
						$unreceivers[$ncallid]=$from1;
					}
					else
					{
						$flag=0;
					}
			}
					
			#For calculating the number of unique senders 
			#(marks as unique even if tag is different)	
				my $to2=$pkt1->get_header('to');
				print "$to2";
				$allreceivers[$c]=$to2;
				
				for $i (1 .. $c-1)
				{
					if($allreceivers[$i] eq $to2 )
					{
						$flag=1;
					}
				
				}
				
				if ($flag==0)
				{
					$nreceivers++;	
					$unreceivers[$nreceivers]=$to2;
				}
				else
				{
					$flag=0;
				}
				
					
			#For calculating the number of unique receivers 
			#(marks as unique even if tag is different)	
				my $from2=$pkt1->get_header('from');
				$allsenders[$c]=$from1;
			
				for $i (1 .. $c-1)
				{
					if($allsenders[$i] eq $from2 )
					{
						$flag=1;
					}
					
				}
			
				if ($flag==0)
				{
					$nsenders++;	
					##print "New callid $allcallid[$c]";
					$unsenders[$nsenders]=$from2;
				}
				else
				{
					$flag=0;
				}
			#print "\n No. of receivers:$nreceivers";
			#print "\n No. of senders:$nsenders\n";
			#print "------------------------------------------------------\n";
			if($pkt1->is_response())
				{
					$resp++; #total no. of responses
					
					if($resp==1)
					{
						$resptime1=0;
					}
					$resptime2=$hdr->{'tv_sec'};
					$interresp=$resptime2-$resptime1;
					$avinterresp=$avinterresp+$interresp;
					$resptime1=$resptime2;
					
					##print "\nInterarrival response time:$interresp\nNo.of responses=$resp\n";
					
					my $response=Net::SIP::Response->new_from_string($pkt1->as_string);
					#print "\nIts a response:- $response\n\n";
					
					my $code1=$response->code;
					#	print "\nCODE:$code1";
					#	my ($inf_cnt, $succ_cnt, $c_fail_cnt, $s_fail_cnt, $g_fail_cnt); 
						
					# SIP Response Codes refer http://en.wikipedia.org/wiki/List_of_SIP_response_codes
					
					if($code1=~ m/(^1[0-9][0-3])/) #1xx
					   	{
							$inf++; #informational response
						}
					if($code1=~ m/(^20[0|2])/) #2xx
						{
							$succ++; #successful response
						}
					if($code1=~ m/^30([0-2]|5)|380/) #3xx upto 380
 						{
							$red++; #redirection response
							$rejected++; #rejected=for all redirected or errorneous sessions
						}
					if($code1=~ m/^4[0-9][0-9]/) #4xx
						{
							$cfail++; #client failure response
							$rejected++;
						}
					if($code1=~ m/^(50[0-5])|513|580/) #5xx upto 580
						{
							$sfail++; #server failure response
							$rejected++;
						}
					if($code1=~ m/^60[0|3|4|6]/) #6xx
						{
							$gfail++; #global failure response
							$rejected++;
						}
					if($code1=~ m/^70[1-6]/) #7xx
						{
							$rejected++;
						}
					if($code1=~ m/^81[0-5]/) #8xx
						{
							$rejected++;
						}
					if($code1=~ m/^92[2-5]/) #9xx
						{
							$rejected++;
						}
					if($code1=~ m/^180/) #180
						{
							$ringing++;							
						}
					if($code1=~ m/^200/) #200
						{
							$ok++;							
						}
					if($code1=~ m/^486/) #486
						{
							$busy++;							
						}
					if($code1=~ m/^480/) #480
						{
							$tempunavail++;							
						}
					if($code1=~ m/^600/) #600
						{
							$busyeverywhere++; 
							#busy & callee does not want to take up the call						
						}
					if($code1=~ m/^603/) #603
						{
							$decline++; 
							#call decline						
						}
					if($code1=~ m/^606/) #606
						{
							$notaccepted++; 
			#user's agent was contact successfully but session not supported by the resources available 606					
						}
					if($code1=~ m/^401/) #401
						{
							$unauthorized++; 
							#unauthorized 401						
						}
					
					#my $uri1=$response->uri;
					#print "\nURI:$uri1";
				
				}
			else 
				{
					
					$req++;	 #total no. of requests
					if($req==1)
					{
						$reqtime1=0;
					}
					$reqtime2=$hdr->{'tv_sec'};
					$interreq=$reqtime2-$reqtime1;
					$avinterreq=$avinterreq+$interreq;
					$reqtime1=$reqtime2;
					
					##print "\nInterarrival request time:$interreq\nNo.of requests=$req\n";
					#print "\nITs a Request, method:";
					my $request=Net::SIP::Request->new_from_string($pkt1->as_string);
				
					#print $request->as_string;
					my $method1=$request->method;
					#print "$method1\n\n";
				
					my $callid=$pkt1->get_header('call-id');
					print "\nrequest Call-ID: $callid\n";		
				
					my $cseq1=$pkt1->get_header('cseq');
					#print "\nCSeq: $cseq1\n\n\n";
				
					my $to1=$request->get_header('to');
					#print "\nTO:$to1";
				
					my $from1=$request->get_header('from');
					#print "\nFROM:$from1";
				
					my $uri1=$request->uri;
					#print "\nURI:$uri1";
				
					my $via1=$request->get_header('via');
					#print "\nVIA:$via1";
				
					my $useragent1=$request->get_header('user-agent');
					#print "\nUSER-AGENT:$useragent1";
				
					my $contact1=$request->get_header('contact');
					#print "\nCONTACT:$contact1";			
				
					my $expires1=$request->get_header('expires');
					
					#SIP Request methods http://en.wikipedia.org/wiki/List_of_SIP_request_methods
					$methodflag=0;
					if ($method1 eq "INVITE")
						{
							$inv++; #Indicates a client is being invited to participate in a call session.
							$methodflag=1;
							
						}
						else
						{
							$notacall++; #notacall=all non-invite dialogs
							$methodflag=1;
						}
					if ($method1 eq "REGISTER")
						{
							$reg++; #Registers the address listed in the To header field with a SIP server.
							#	print "\n\nREGISTER $reg\n\n";
							$methodflag=1;
					
						}
					if ($method1 eq "BYE")
						{
							$bye++; #Terminates a call and can be sent by either the caller or the callee.
							$methodflag=1;
							$completed++; 
							#after a successful call , a bye is sent.
						}
					if ($method1 eq "OPTIONS")
						{
							$opt++; #Queries the capabilities of servers.
							$methodflag=1;
						}
					if ($method1 eq "CANCEL")
						{
							$can++; #Cancels any pending request.
							$methodflag=1;
						}
					if ($method1 eq "REFER")
						{
							$ref++; #Asks recipient to issue SIP request (call transfer)
							$methodflag=1;
						}
					if ($method1 eq "SUBSCRIBE")
						{
							$sub++; #Subscribes for an Event of Notification from the Notifier.
							$methodflag=1;
						}
					if ($method1 eq "NOTIFY")
						{
							$not++; #Notify the subscriber of a new Event
							$methodflag=1;
						}
					if ($method1 eq "INFO")
						{
							$info++; #Sends mid-session information that does not modify the session state.
							$methodflag=1;
						}
					if ($method1 eq "PRACK")
						{
							$pra++; #Provisional acknowledgement.
							$methodflag=1;
						}
					if ($method1 eq "UPDATE")
						{
							$up++; #Modifies the state of a session without changing the state of the dialog.
							$methodflag=1;
						}
					if ($method1 eq "MESSAGE")
						{
							$mes++; #Transports instant messages using SIP.
							$methodflag=1;
						}
					if ($method1 eq "ACK")
						{
							$ack++; #Confirms that the client has received a final response to an INVITE request.
							$methodflag=1;
						}
					if($methodflag==0)
					{
						$residue++;
						$methodflag=0;
					}
			
				}				
			#print "\n\n-------------------------------------------------------------\n";
			$temp=$hdr->{'tv_sec'};
			
			my $win4=localtime($temp);
			print "Temp:$win4 ";
			
			my $win5=localtime($win2);
			print "Win2:$win5 ";
			  
			if($temp >= $win2)
				{
					$duration=$temp-$win1;
				 	print "\n\nTotal number of packets:- $c";
					#print "\n\nTotal number of senders:- $nsenders";
					print "\nThe Senders";
					for $i (1 .. $ncallid)
					{
						print "\n";
						print $i." ".$unsenders[$i] ;
					}
							
					#print "\n\nTotal number of receivers:- $nreceivers";
					print "\nThe Receivers";
					for $i (1 .. $ncallid)
					{
						print "\n";
						print $i." ".$unreceivers[$i] ;
							
					}
							  
					print "\nNumber of requests: $req\n";
					print "\nINVITE: $inv\nNOTACALL: $notacall\nREGISTER: $reg\nBYE: $bye";
					##print "\nCANCEL: $can\nOPTIONS: $opt\nREFER: $ref";
					##print "\nSUBSCRIBE: $sub\nNOTIFY: $not\nINFO: $info";
					##print "\nPRACK: $pra\nUPDATE: $up\nMESSAGE: $mes\nACK: $ack\n";
					##print "\n\nRINGING: $ringing\nOK: $ok\nBUSY: $busy\nTEMP UNAVAILABLE: $tempunavail\nBUSY EVERYWHERE: $busyeverywhere\nDECLINE: $decline \nNOT ACCEPTED:$notaccepted\nUNAUTHORIZED: $unauthorized\n\n";
					##print "\nNumber of responses: $resp\n";
					##print "\nINFORMATIONAL CODE: $inf";
					##print "\nSUCCESS CODE: $succ";
					##print "\nREDIRECTION CODE: $red";
					##print "\nCLIENT FAIL CODE: $cfail";
					##print "\nSERVER FAIL CODE: $sfail";
					##print "\nGLOBAL ERROR CODE: $gfail\n";
					##print "\nNumber of SDP messages: $sdp\n";
					
					#calculating and Printing Features
					#Group 1-General Characteristics
					print "-------------------------------------\n";
					print "\nGroup 1 - General Characteristics\n";
					print "-------------------------------------\n";
					$nbreq=$req/$c;
					$nbresp=$resp/$c;
					$nbsdp=$sdp/$c;
					$avinterreq=$avinterreq/$req;					
									
					print "1.Duration #$duration |";
					print "\n2.NbReq :#$nbreq |";
					print "\n3.NbResp #$nbresp |";
					print "\n4.NbSdp #$nbsdp |";
					print MYFILE $duration." ";
					print MYFILE $nbreq." ";
					print MYFILE $nbresp." ";
					print MYFILE $nbsdp." ";
					print "\n5.Average Interarrival of requests #$avinterreq |\n";
					if($resp!=0)
					{
					$avinterresp=$avinterresp/$resp;
					print "6.Average Interarrival of responses #$avinterresp |\n";
					}
					else
					{ print "6.Average Interarrival of responses #0 |\n"; }
					
					if($sdp!=0)
					{
					$avintersdp=$avintersdp/$sdp;
					print "7.Average Interarrival of messages carrying SDP bodies #$avintersdp |\n";		
					}
					else
					{print "7.Average Interarrival of messages carrying SDP bodies #0 |\n";}			
					print "\n";
							 
					#Group 2 - Call-Id based statistics
					print "-------------------------------------\n";
					print "\nGroup 2 - Call-Id based statistics\n"; 
					print "-------------------------------------\n";
					print "8.NbSess #$ncallid |";
					
					$avduration=$avduration/$ncallid;
					print "\n9.Average duration of a call-ID  #$avduration |\n";
					print "\nThe Call-ids and number of messages per call-id";
					print MYFILE $ncallid." ";
					my $totpac=0;		#Total Number of messages
					for $i (1 .. $ncallid)
						{
							print "\n";
							print $i." ".$uncallid[$i]." ".$ccallid[$i] ;
							$totpac=$totpac+$ccallid[$i];	
						}
					$avmsg=$totpac/$ncallid;
					$nbsenders=$nsenders/$ncallid;
					$nbreceivers=$nreceivers/$ncallid;
					
					print "10.Nbsenders #$nbsenders |\n";
					print "11.Nbreceivers #$nbreceivers |\n";
					print "\n12.AvMsg #$avmsg |";
					print "\n";
					print MYFILE $avmsg." ";
					
												
					#Group 3 - Dialogs' Final State Distribution
					print "-------------------------------------\n";
					print "\nGroup 3 - Dialogs' Final State Distribution\n";
					print "-------------------------------------\n";
					$nbcanceled=$can/$ncallid;
					$nbnotacall=$notacall/$ncallid;
					$nbcompleted=$completed/$ncallid;
					
					$incall1=$ringing-$ok; #ringing 180 - ok 200
					$incall=$ack-$bye; #incalls=calls which are established but not realised.
					$incall=$incall+$incall1+$busy+$tempunavail+$busyeverywhere+$decline+$notaccepted;
					#it does not return bye.We need to check INVITE & ACK.
					$nbincall=$incall/$ncallid;
					$nbrejected=$rejected/$ncallid;
					$nbresidue=$residue/$ncallid;
					
					$callset=$ringing-$inv;
					$callset=$callset+$unauthorized;
					$nbcallset=$callset/$ncallid;
					
					print "13.NbNotacall #$nbnotacall |\n14.NbCallset #$nbcallset |\n15.NbCanceled #$nbcanceled |\n";
					print "16.NbRejected #$nbrejected |\n17.Nbincall #$nbincall |\n18.NbCompleted #$nbcompleted |\n19.NbResidue #$nbresidue\n |";
					print "\n";
					print MYFILE $nbcanceled." ";
												 
					#Group 4 - Request Distribution
					print "-------------------------------------\n";
					print "\nGroup 4 - Request Distribution\n";
					print "-------------------------------------\n";
					$nbreg=$reg/$req; #? RECHECK c or req.
					$nbinv=$inv/$req;
					$nbbye=$bye/$req;
					$nbopt=$opt/$req;
					$nbcan=$can/$req;
					$nbref=$ref/$req;
					$nbinf=$info/$req;
					# $nbsucc=$reg/$c;
					$nbsub=$sub/$req;
					$nbnot=$not/$req;
					$nbinf=$inf/$req;
					$nbpra=$pra/$req;
					$nbmes=$mes/$req;
					$nback=$ack/$req;
					$nbupd=$up/$req;
											
					print "20.NbInv #$nbinv |";
					print "\n21.NbReg #$nbreg |";
					print "\n22.NbBye #$nbbye |";
					print "\n23.NbAck #$nback |";
					print "\n24.NbCan #$nbcan |";
					print "\n25.NbOpt #$nbopt |";
					print "\n26.NbRef #$nbref |";
					print "\n27.NbSub #$nbsub |";
					print "\n28.NbNot #$nbnot |";
					print "\n29.NbMes #$nbmes |";
					print "\n30.NbInf #$nbinf |";
					print "\n31.NbPra #$nbpra |";
					print "\n32.NbUpd #$nbupd |";
					print "\n";
												
					print MYFILE $nbreg." ";
					print MYFILE $nbbye." ";
					print MYFILE $nback." ";
					print MYFILE $nbcan." ";
					print MYFILE $nbopt." ";
					print MYFILE $nbref." ";
					print MYFILE $nbsub." ";
					print MYFILE $nbnot." ";
					print MYFILE $nbmes." ";
					print MYFILE $nbinf." ";
					print MYFILE $nbpra." ";
					print MYFILE $nbupd." ";
											
					#Group 5 - Response Distribution
					print "-------------------------------------\n";
					print "\nGroup 5 - Response Distribution\n";
					print "-------------------------------------\n";
					if($resp>0)
						{
							$nb1xx=$inf/$resp;
							$nb2xx=$succ/$resp;
							$nb3xx=$red/$resp;
							$nb4xx=$cfail/$resp;
							$nb5xx=$sfail/$resp;
							$nb6xx=$gfail/$resp;
						}
					print "33.Nb1xx #$nb1xx |";
					print "\n34.Nb2xx #$nb2xx |";
					print "\n35.Nb3xx #$nb3xx |";
					print "\n36.Nb4xx #$nb4xx |";
					print "\n37.Nb5xx #$nb5xx |";
					print "\n38.Nb6xx #$nb6xx |/";
					print MYFILE $nb1xx." ";
					print MYFILE $nb2xx." ";
					print MYFILE $nb3xx." ";
					print MYFILE $nb4xx." ";
					print MYFILE $nb5xx." ";
					print MYFILE $nb6xx." ";
											
					for $i (1 .. $c-1)
						{
					               $uncallid[$i]=0;
					               $allcallid[$i]=0;
					               $ncallid=0;
					        }
							
					$c=0;
					print MYFILE "\n";
				}
   		}
	}
END 
	{

		#unlink($dumpfile);
	}
	
