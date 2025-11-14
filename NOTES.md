- TSHARK SYNTAX:
- Display all traffic containing a key work in a PCAP file: tshark -r sensoroni_onion-fn2_1023.pcap -Y "frame contains tradetracker"
- Create a targeted PCAP containing only traffic from an IP address: tshark -r sensoroni_onion-fn2_1023.pcap -Y "ip.addr == 104.53.222.103" -w exported_objects/evidence_1.pcap
- Display contents of the 2nd TCP stream in HEX Format tshark -z "follow,tcp,hex,1"
- Applying Display Filters
- In tshark, run the following commands:
- tshark -i eth0 captures traffic on an interface
- tshark -Y tcp filters for tcp
- tshark -i eth0 -Y tcp combines the two
- Run the following to create a new PCAP file limiting to only TCP port 443 and traffic to or from 202.84.73.91:
- tshark -r fullday.pcap -w maliciousip443.pcap -Y "ip.addr == 202.84.73.91 and tcp.port == 443"
- In the above, -r is the file to be read, -w is the file to be written to, -Y is the filter to be applied.
- Adding only traffic to and from a different IP: tshark -r maliciousip443.pcap -w output.pcap -Y "ip.addr == 172.16.3.3"
- To quickly analyze statistics of newly created PCAP: capinfos maliciousip443.pcap

- Arkime:
- Open Arkime
- from the terminal, sudo su into root and run the following to stop Arkime capture and viewer services: systemctl stop molochcapture.service molochviewer.service
- Uncomment out the bpf config line
- Aplly the following BPF to the config file: bpf=not tcp port 502
- Save and exit the file
- Start the Arkime services: systemctl start molochcapture.service molochviewer.service
- Use tcpreplay to ingest the pcap. tcpreplay -t -i ens224 /root/powerplant.pcap
- In Arkime, filter on port.dst == 502 showing 0 results, proving it works.

- Modify PCAP Buffer Configs in Arkime
- Run sudo su to change to root
- RUn the following to view contents of folder where PCAPs are written: ls -la /data/molach/raw/
- Run the following to stop Arkime capture and viewer services: systemctl stop molochcapture.service molochviewer.service
- Open the Arkime config file /data/molach/etc/config.ini
- Locate the config Items maxFileSizeG and maxFileTimeM (lines 79 and 83)
- Set masFileSizeG to 1 and maxFileTimeM to 1
- Locate the freeSpaceG on line 112 and set it to 15%
- Run the following to restart Arkime: systemctl start molochcapture.service molochviewer.service


- Stenographer Capture Optimizations
- SSH onto manager node, and change to root: ssh -l trainee 199.63.64.92 sudo su
- In a new tab, ssh into the forward node and sudo: ssh -l trainee 199.63.664.93 sudo su
- From the forward node, view th config file that controls behavior of stenographer: cat /opt/so/conf/steno/config
- From the forward node, use ps -ef | grep stenotype to view settings applied to running stenotype process
- Switch to Manager node, and view the sensor.sls file, this is the config file to modify and pus hcahnges to forward node: cat /opt/so/saltstack/local/pillar/minions/onion-fn1_sensor.sls
- Open this file in a text editor, and change the steno section to reflect the following: image
- Switch back to forward node, and run so-pcap-restart to force node to get updates.
- View the config file and verify changes are applied: 5ce7b4bd-96a4-4b85-82fc-2bf4edd9304b
- run the ps -ef | grep stenotype to verify visible config options are applied.



- NetFlow (NFDUMP)
- View a summary of a file: nfdump -r netflow_1 -I
- View top 10 IP addresses sending highest number of packets: nfdump -r netflow_1 -s ip/packets -n 10
- View Port information: nfdump -r netflow_1 -s dstport/packets -n 10
- View IP addresses sending most HTTPS traffic: nfdump -r netflow_1 -s srcip/packets 'port 443'
- View IP addresses receiving most IP traffic: nfdump -rnetflow_1 -s dstip/packets 'port 443'


- SURICATA EXAMPLES
- alert tcp $HOME_NET any -> $EXTERNAL_NET 6969 (msg:"ET P2P BitTorrent Announce"; flow: to_server,established; content:"/announce"; 
- reference:url,bitconjurer.org/BitTorrent/protocol.html; reference:url,doc.emergingthreats.net/bin/view/Main/2000369; classtype:policy-violation; 
- sid:2000369; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

- alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; 
- file_data; content:"Warning"; content:"mysql_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020507; 
- rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2015_02_24, deployment Datacenter, signature_severity Major, tag SQL_Injection, updated_at 2016_07_01;)

- Content modifiers go after content. Sticky Buffer modifiers go before content.


- Setting up SPAN Port:
- Configure FE 0/1 as source interface: Catalyst-3550(config)# monitor session 1 source interface fastethernet 0/1
- Configure FE 0/24 as the destination interface: Catalyst-3550(config)# monitor session 1 destination interface fastethernet 0/24
- Verify the SPAN config is set up correctly: show monitor session 1

- Placing SPAN Ports
- Utilize Putty to SSH onto the router
- enter enable then config t to get to the Configuration mode
- Run the following to enter mode to configure ERSPAN session: monitor session 1 type erspan-source
- RUn the following to configure ERSPAN session source interfaces: source interface g3-4
- Run the following commands to specify traffic destination (Using a GRE tunnel): destination, erspan-id 1, ip address 199.63.64.31, origin ip address 75.21.1.2`
- Exit


- Verify ERSPAN with Wireshark
- From Wireshark, specify the port to listen on and filter for GRE protocol using ip proto 0x2f in the ...using this filter: block.
- From a different workstation, ping the device you want to test ping -t 103.28.93.2
- On Wireshark, verify no traffic is captured yet. This shows ERSPAN is not enabled.
- Run the following to enable ERSPAN: no shutdown
- Re-verify that traffic is being captured.


- Implement Port Mirroring
- Use putty to enter into a router putty.exe -ssh trainee@<IP>
- Run configure to enter VyOS config mode
- Run set interfaces ethernet eth2 mirror eth3 to config a local port mirror
- Run sudo tcpdump -i eth3 host not 200.200.200.2 and not arp to confirm it has not been set up yet
- Run commit to set up the port mirror


- Implement Filters
- Run ping -t 103.28.93.2 to verify cmd.exe is still running the ping
- Putty into the router, and enter the config mode putty.exe... 'enable, config t`
- Run the following to define an ACL filter: ip access-list extended no-icmp, deny icmp any any, exit
- Run the following to modify config for ERSPAN monitor session 1 type erspan-source
- Run the following to apply filter and exit editing filter access-group no-icmp exit
- Verify in Wireshark no packets are being captured
- Re-enter the config modification
- Run the following to remove the filter: shutdown, no filter access-group no-icmp, no shutdown, exit
- See that Wireshark has captured packets again




- Parse out only PROTOCOL comms from a specified source IP: `tshark -r OldPcap -w NewPcap.pcap -Y "ip.src == <IP> and <protcol>"`
- BPF Filter for conversations between host <IP> and port <port> and host <ip> and port <port>: tcpdump -r <FilePath> host <ip> and port <port> and host <ip> and port <port> -w <newPcap>`
- 
