# MOD 1
## Protocol Dissection
### Protocol Standards
- A **protocol** is a system of formal rules designed for efficiency that allows two or more entities of a communications system to transmit information via any kind of physical medium.
- These standards or guidelines define the **syntax**, **semantics**, and **synchronization** of communication between devices

### Request for Comments
- Requests for Comments (**RFC**) define **internet specifications**, **procedures**, **events**, and **communication protocols**.
- An **RFC** is a **numbered document** that includes **appraisals**, **methods**, **behaviors**, and **research** as well as **descriptions** and **definitions** of online protocols.
- Administered by the Internet Engineering Task Force (**IETF**), many of the protocol standards used online are published in RFCs.
- The Internet Society, designers, engineers, and computer scientists publish discourses in the form of RFCs to share new concepts, information, etc.
- These internet drafts are peer reviewed before they become RFCs. Then the IETF adopts some of these proposals — published as RFCs — as Internet Standards (**STD**).
- There is a wide range of internet protocol standards, and a complete list of official and up-to-date standards can be found in the RFC Editor documents.
- The official protocol standards are listed in the following categories:
  - **Proposed**: Early stage; proposed protocol.
  - **Draft**: On track; likely a future protocol.
  - **Standard**: Established as a standard protocol.
  - **Historic**: Older protocols; suspended or unused.
  - **Experimental**: Research protocols documented to provide a convenient reference.
- The RFC Editor assigns each RFC a unique serial number.
- Once a document is published and assigned a number, it cannot be modified or rescinded.
- However, a document may require amendments, so authors often publish revised documents.
- Therefore, RFCs may supersede others, which are said to be historic. These serialized documents make up the evolution of the STDs.
- In descending order of priority, each protocol is assigned a status of **Required**, **Recommended**, **Elective**, **Limited Use**, or **Not Recommended**.
- Few protocols are assigned the status of Required, and if they are, they must be complied with immediately.

### Protocols
- The following protocols are some of the most commonly found protocols at Layer 7 of the OSI model within an enterprise network
  <img width="1667" height="589" alt="3c5b6e52-1061-4914-9cb7-12b9cba6d470" src="https://github.com/user-attachments/assets/a022f273-ac87-41f0-8920-b7d969be3d7a" />

### Wireshark and Tshark
- Wireshark has become the tool to use for inspecting and analyzing network packets.
- Wireshark captures — or sniffs — the network to view traffic that goes into and out of the wired or wireless network adapter.
- Network data streams are addressed to specific machines but can be seen by using a packet sniffer on a network interface that is in promiscuous mode, which informs the Network Interface Card (NIC) to accept all traffic on the broadcast domain.
- However, it is important to know that Wireshark does not actually do the sniffing but is enabled by the PCAP kernel-level drivers: **Libpcap** and **WinPcap**.
- These drivers function almost identically once they are enabled, and then Wireshark can dictate to the system to utilize them to enable promiscuous mode.
  ![83c65f1b-bead-4742-8229-673e36c0dc87](https://github.com/user-attachments/assets/f9a748f7-1e8c-4bb9-9187-40329c0d0981)

- Messages interchanged by such protocols as Transmission Control Protocol (TCP), User Datagram Protocol (UDP), and Internet Protocol (IP) are encapsulated in link-layer frames, which are transmitted over physical media like an Ethernet cable.
- The link-layer frames provide all the messages from all protocols sent and received.

#### Libpcap
- An Application Programming Interface (API) that provides a series of services to enable the capture of network packets.
  - Portable open-source C/C++ library for Linux and Mac Operating System (OS) users.
  - Enables administrators to capture and filter packets.
  - Utilized by other tools such as tcpdump.

#### WinPcap
- Windows open-source library for PCAP and network analysis.
- The purpose of WinPcap is to facilitate access to Win32 applications and administer the following:
  - Portable PCAP library for Windows users.
  - Contains the adaptation layer.
  - Captures raw packets; both the packets destined to the machine and the ones exchanged by other hosts.
  - Filters packets according to user-specified rules.
  - Transmits raw packets to the network.
  - Gathers statistical information about the network traffic.
  - Utilized by other tools such as Network Mapper (Nmap) and Snort.

### TShark
- TShark is a powerful and useful CLI-oriented version of Wireshark. It is designed to enable the user to capture packet data from a live network or read packets from a previously saved capture file — either printing a decoded form of those packets to the standard output or writing the packets to a file when a GUI is not available to the user.
- TShark also uses the PCAP library to capture traffic from the network interface.
- Even though a GUI is much easier to manipulate, it is not supported by all environments, and using a CLI without a GUI is inevitable.
- While very similar to tcpdump, TShark is best used when analyzing large PCAP files, and tcpdump is preferred for live PCAPs.
- Even though both tools are basically equivalent in functionality, TShark is a bit more powerful than tcpdump, as it incorporates many of the robust features found within Wireshark.
- One of the big advantages that TShark has over the Wireshark GUI is that stdout gives many options to manipulate and clean up the output.
- Since TShark uses a CLI instead of a GUI, important TShark syntax is seen below or by typing the following in the Terminal Emulator:
  <img width="726" height="315" alt="image" src="https://github.com/user-attachments/assets/142bbf69-5998-4674-9c51-f5e7b5913fc8" />

### Capture Filters
- Capture filters use a different syntax from display filters and keep only packets that match the criteria of the capture filter to be retained in the PCAP.
- Instead of solely using Boolean operators as the main function of the syntax, capture filters can also use **byte offsets**, **hex values**, and **masks** with certain Boolean operators to filter the data.
- Using the BPF syntax to create a filter is also known as forming an expression.
- The syntax uses **primitives**, which consist of a single statement combined with one or more qualifiers followed by a value such as a name or Identifier (ID) number.
- Primitives refer to a section of a protocol header such as port, host, or TCP port.
  ![b9290cd7-e842-40cb-858b-47d054c11e6d](https://github.com/user-attachments/assets/1d8f8b80-1ba6-4cb9-bce1-d99ffe4b0318)
  ![51250261-8767-4eb4-a765-97c27072f9cc](https://github.com/user-attachments/assets/a444e03f-acc4-4a70-a0bf-769bdc3d38a4)

- As noted, BPFs are associated with three qualifier types, which can be used to form an expression.
- Looking at Figure 1.1-2, it is evident that the expression is formed using two primitives and an operator. The first primitive utilizes the value of the port — 80 — and matches any traffic to or from that port using TCP.
- The second primitive utilizes the qualifiers destination (dst), host, and IP address value to match any traffic destined to the host with the given value of the IP address.
- To successfully complete an expression, a logical operator (&&) is needed to conjoin the two primitives to make the expression as one. 
  ![586d03f2-5879-4a1d-b68c-a99195f3548f](https://github.com/user-attachments/assets/518a6e58-e0b1-489f-b51c-1231ea7b0ea4)

#### TShark Syntax
- Capture traffic on an interface: `tshark -i eth0`
- Capture traffic from an interface, filtering on TCP traffic with dst port of 80: `tshark -i eth0 -f 'tcp && dst port 80'`
- Read a PCAP file as input and write captured packets to a different file: `tshark -w name-of-out-file.pcap -r name-of-in-file.pcap`

### Display Filters
- Display filters are applied to a packet while a capture is taking place or after the data has been collected.
- Display filters do not aid to reduce compute resources but do aid in narrowing the amount of data in a set when investigating specific elements
- Protocol dissectors are the elements within Wireshark and TShark that identify and interpret a packet based on the presence or absence of fields or values within those packets.
- It is how these tools are able to determine that a Hypertext Transmission Protocol (HTTP) packet and the associated application layer fields within are what they are and how they are able to recognize which Layer 2 or Layer 3 protocol is in use.
- It is important to note that these attributes also translate to TShark since it is the CLI version of Wireshark.
- Generally, a display filter expression is customized with a **field name**, **value**, and **relational operator**.
  - The field name is simply replaced with a specific protocol or a field that the protocol dissector displays in relation to that specific protocol.
- Wireshark evaluates the display filter based on the relational operators.
- The Display Filter Expression from the Analyze submenu provides visibility into how display filters are created. Wireshark’s database also contains a Display Filter Reference library.
  ![6f48088c-f3f6-405d-850b-cec8c2b83be2](https://github.com/user-attachments/assets/c4527656-f1d6-4a92-b74c-d2362aec3c70)
  ![7b463c0d-b0c5-4603-9350-90707e80d568](https://github.com/user-attachments/assets/b08665fa-0518-443f-ba27-457c185ee7c9)

- The difference between URL and URI is that URL — used to only locate webpages — is a subset of URI and specifies where a resource exists and the mechanism to retrieve that URL.
- URI is a superset of URL that identifies a resource by the URL. All URLs are considered URIs; however, not all URIs are considered URLs, because a URI may be a name instead of a locator.

  ```
  http.host == “www.simcorp.com”
  http.request.full_uri == “http://www.simcorp.com/index.html”
  http.request.uri == “index.html”
  ```

- When dealing with larger PCAPs, a single expression may not be enough to narrow down the desired packets.
  ![89091f62-ebc2-4ac0-bca3-6cbe044d6770](https://github.com/user-attachments/assets/08d38195-3baa-4bf6-9797-24d6986fdfdc)

#### TShark Syntax
- Uthilze TShark with display filters: `tshark [options] -Y "display filter"`
- Provide more verbose output of application layer protocols from specific PCAP file: `tshark -V -r dnscat.pcap`
- Apply absolute timestamp output specific to a PCAP file: `tshark -t ad -r dnscat.pcap`
- Apply HEX and ASCII output of a PCAP file: `tshark -xr dnscat.pcap`
- Protocol statistics such as **http, tree**; **http_req, tree**; **smb**, and **srt** can be generated: `tshark -r dnscat.pcap -z http,tree`

### Applying Filters to Export SMB Objects
#### What is a Trickbot?
- TrickBot, which has been tied to Lazarus Advanced Persistent Threat (APT), is an advanced trojan that specific threat actors utilize.
- Delivery of TrickBot is primarily by spear-phishing campaigns using tailored emails that masquerade malicious attachments or links, which, if enabled, execute malware via exploits such as EternalBlue to move laterally through the network via SMB port 445.
- EternalBlue leverages a buffer overflow attack via SMBv1.
- TrickBot also uses Man-in-the-Browser (MitB) attacks (MITRE Adversarial Tactics, Techniques, and Common Knowledge [ATT&CK®] Technique T1185) to steal user information.
- The malware spans across the entirety of the ATT&CK framework, resulting in actively or passively gathering information to support targeting, or trying to manipulate, interrupt, or destroy the system and or data.
- It is often seen communicating using HTTPS/Secure Sockets Layer (SSL)/Transport Layer Security (TLS) over TCP ports 443, 447, and 449 to retrieve files or using HTTP over 8082 to retrieve tasking or exfil data via Command and Control (C2) channels.
- Trickbot often downloads binary executable files that are masqueraded as another innocuous file type, such as a .png or a .php file.
- Filter to find Trickbot transferred Windows executables over SMB using EternalBlue: `(frame.len==1294) && (smb.fid == 0x4002) && (smb.file.rw.offset == 0)`
- Additional Filter to find the information: `(smb.cmd==0x2f) && (smb.file_data matches "^MZ")`

### Investigating an Attack with Wireshark
#### What is Emotet?
- Emotet is also a trojan that is typically spread through spam emails or malspam.
- The infection may arrive via malicious scripts, files, or links that may look legitimate to the user.
- Emotet uses numerous tricks to evade detection and may persuade users to access malicious links.
- A function of the post-infection Emotet activity can be mapped to Layer 6 of the OSI model, where it uses HTTP traffic and data stored within a cookie to exfiltrate system information back to its command and control server.

#### What is TrickBot?
- As previously mentioned, TrickBot is an advanced trojan that threat actors deliver primarily through spear-phishing campaigns that masquerade malicious attachments or links, which — if enabled —  execute the malware.
- As mentioned in the last section, other malware such as Emotet has also been used to deliver TrickBot to a target network.
- TrickBot has a range of techniques that it uses to move laterally, establish persistence, and steal information, such as using Browser Session Hijacking (MITRE ATT&CK technique T1185) to trick users into entering their logon credentials into a false or modified site.
- It relies on HTTP Secure (HTTPS) traffic over ports **443**, **447**, and **449** for C2 communication but also uses HTTP over port **8082**.
- If vulnerable systems are found, TrickBot can leverage exploits such as **EternalBlue** to move laterally.
- Key indicators of EternalBlue are the use of **SMB version 1** — especially if not seen widely in the network — and the use of **transaction2** secondary requests between the attacking and target systems.
- These secondary requests are required because the total required data for the EternalBlue exploit exceeds what can usually be included in an SMB packet.
- A function of the post-infection TrickBot activity can be mapped to Layer 6 of the OSI model, where it relies on the **HTTPS/SSL/TLS** traffic for C2 communication.

### Detecting Malicious SMTP Traffic
- **SMTP/ESMTP** uses TCP port **25** for unencrypted traffic and ports **587** or **465** for encrypted TLS traffic.
- Current mail implementations tend to use SMTP for outgoing mail from client systems to the client's mail server and use Post Office Protocol 3 (**POP3**) or Internet Message Access Protocol (**IMAP**) to retrieve mail from the mail servers.
- Threat actors leverage SMTP maliciously for a multitude of reasons, including the following:
  - **User/Account Enumeration**
    - Servers running **SMTP** on port **25** may allow unauthenticated access.
    - An attacker can connect to the server and use built-in commands such as **VRFY** to verify if a user exists.
    - If the username is located on the server, it responds in the positive.
    - Attackers automate this process to discover lists of users on a system as a possible precursor to a **brute force login attack**.
  - **C2 and Data Exfiltration**
    - SMTP is a protocol that has a higher probability of being allowed out through a network's security boundary.
    - Threat actors leverage that fact by using SMTP as a means of sending commands and tasking via C2 and to exfiltrate data from a victim network.
    - APT28 has been known to use SMTP to send encoded attachments containing stolen data from a victim's network to a set of hard-coded email addresses.
  - **Spam**
    - An unsecured SMTP server, known as an **Open Relay**, can be leveraged by threat actors to send thousands of emails as part of a spam campaign.
    - This helps to protect those conducting the spam campaign by making it appear the emails are coming from an unwitting third party.
    - Attackers scour the internet looking for open systems with TCP port 25 open.
    - A threat actor exploits systems and installs a program such as Send-Safe that allows the attacker to turn the victim into a spam-generating system.

### Protocol Dissectors
- A dissector is simply a parser used to identify protocol fields within a network packet and filter for specific information regarding those protocols, for example, the FQDN in a DNS query.
- Applications such as Intrusion Detection Systems (**IDS**), Intrusion Prevention Systems (**IPS**), network Application Load Balancers (**ALB**), **next-generation firewalls**, and **protocol analyzers** all employ their own set of protocol dissectors.
- These applications use dissectors, parsing through network data to perform security, monitoring, performance, or traffic analysis tasks.

### Packet Dissection at Work
- Similar to OSI model operation, de-encapsulating a lower-layer protocol and handing the payload to a higher layer for processing, each protocol dissector decodes its part of a protocol and analyzes fields in the header to determine the next dissector, then hands off to that dissector for processing.
- The process repeats itself until all payloads have been processed and there are no additional payloads to be analyzed.
  - The result of this process can be seen looking at each frame analyzed by Wireshark.
  - Every packet analyzed starts with the Frame dissector, which parses the details of the data source itself (e.g., timestamps) — a data source being a capture file or live data.
  - The next step is to hand the data to the lowest-level data dissector; in the case of the file being sampled, the Ethernet dissector parses the Ethernet header.
- Once processed, the payload is handed off to the next dissector; the IP dissector parses the IP header, and so on.
- To visualize protocol dissectors at work, think about a user connected to an Ethernet network and sending an HTTP GET request to a web server from the browser.
- To decode the HTTP request, Wireshark would parse the frame through five different dissectors. 

### Frame Dissector
<img width="889" height="311" alt="3966e7ee-d4ab-4440-804b-948d137ba780" src="https://github.com/user-attachments/assets/a3054f41-bc32-420a-bff1-ca74a513d7d2" />

### Ethernet Dissector
<img width="889" height="311" alt="b47fd729-9a0e-4006-93ee-9cb0dea668f3" src="https://github.com/user-attachments/assets/a5dc61f8-f4b0-4e64-bfb6-3679222f3ffc" />

### Ipv4 Dissector
<img width="889" height="311" alt="eb8c2380-2318-442c-8929-60542b656d01" src="https://github.com/user-attachments/assets/be02e0bf-1b0e-411f-8f3a-f1bd3ebf8d8d" />

### TCP Dissector
<img width="889" height="311" alt="bc7fd139-ec44-402a-8522-cedd1636acba" src="https://github.com/user-attachments/assets/5fa52241-eb50-421d-9738-3df657727b43" />

### HTTP Dissector
<img width="889" height="311" alt="1923f008-2eac-4801-9bd6-336b6aaacad9" src="https://github.com/user-attachments/assets/5c9fd93d-1e18-4d02-be69-96bf45ee2ade" />

### Protocol Dissectors and Non-Standard Ports
- Applications communicating on non-standard ports are always a common cause of concern.
- As a result, they are typically flagged in alerts by security applications actively monitoring network traffic flows and require additional analysis, regardless of the application's intentional configuration to use non-standard ports or an attempt by a threat actor trying to evade detection.
- Network and security personnel might configure applications that monitor network traffic to handle non-standard ports differently based on the environment requirements.
- Some might allow the traffic to flow, monitoring and further investigating alerts; others might decide to drop the traffic altogether.
- Many modern traffic analysis systems — used for security, performance monitoring, or other tasks — employ advanced and complex dissectors to decode payloads transported on non-standard ports; these dissectors are often referred to as Heuristic Dissectors.
- These dissectors use pattern-based matching to identify which protocol or payload is being used in the communication.
- Applications parse network data using multiple Heuristic Dissectors until a match is made and the payload is decoded.
- If all dissectors fail, systems can be configured to only alert operators or alert and drop the packets based on environment and system requirements. 

### Custom Dissectors
- Though beyond the scope of this lesson, writing custom dissectors to extend the functionality of applications that process and analyze network traffic is a great way to adapt to changes in how applications are using networks to communicate and evolving threat actor techniques.
- When it comes to Wireshark, there are two languages the application supports to write or import custom dissectors: C and Lua. 

#### Dissectors Written in C Language
- There are two ways to create a custom protocol dissector within Wireshark: a **plug-in** or a **built-in** standard dissector.
- Analysts typically prefer C to create a custom dissector since C produces shorter code execution times.
- However, it is essential to note the shortcomings of using C to create a custom dissector.
  - First, every time a built-in dissector is added or modified, Wireshark has to recompile itself, which can be a time-consuming task.
  - Second, adding a dissector as a plug-in requires Wireshark to configure and alter new files within the plug-in folder, along with the source file(s) of the protocol dissector. 

#### Dissectors Written in Lua Language
- Lua dissectors are very similar to those written using C.
- Although Lua is a little more dynamic, its use refrains from recompiling Wireshark upon adding a plug-in or a built-in protocol.
- Both Lua and C dissectors must be registered to process a payload or packet that fulfills protocol rules.
- In this sense, Lua is ideal for rapid testing of newly created protocol dissection actors.
- Unlike C, Lua provides automatic memory management, which causes Lua to produce fewer errors.
- For the sake of time, Lua is used to demonstrate extending Wireshark's capabilities through custom dissectors.

### Adding a Custom Dissector to Wireshark
1. Open wireshark
2. Review _Compiled_ section to see if it has _with Lua 4.2.4_
3. Can be done in TShark via: `tshark -v`
4. After verification, you can run `head -30 /ect/wireshark/init.lua` to see if Lua support is enabled.
5. If _init.lua_ is enabled and Lua has loaded, then the submenu is available in Wireshark
6. From a terminal window, edit the _init.lua_ file located in _/etc/wireshark_
7. Add a new line: `dofile("/home/trainee/dissector_test.lua")` and remove the dashes that are created on the new line

### Adding a Custom Protocol Dissector via TShark
- Find the directory where TShark is loading global Lua plugins: `tshark -G folders | grep ^Global.Lua.Plugins | cut -f2`
- Directory where TShar is loading personal lua plugins: `tshark -G folders | grep ^Personal.Lua.Plugins | cut -f2`

### Detecting C2 and Exfil via DNS
- Access is given to a Kali Linux VM as well as a vulnerable Windows client solely to analyze the network's data stemming from a C2 and exfiltration breach of a vulnerable target host within the network.
- Since DNS is typically permitted out of corporate network environments, adversaries may use DNS tunneling to take control and exfiltrate data from a vulnerable system.
- A tool known as **DNScat2** is used to create a communication channel between a vulnerable target host (client) and the C2 server, which enables an adversary to have access to even the most restricted traffic environments since DNS is allowed to transit the network boundaries.

#### DNScat2
- **DNScat2** creates an encrypted C2 tunnel over the DNS protocol.
- **DNScat2**, which operates in two parts as a client and a server, can be difficult to detect because the commands used to exfiltrate data are hidden within DNS queries and responses.

#### Server
- The **DNScat2** server is designed to run on an authoritative DNS server, but requests are sent locally via **UDP/53** for this instance.
- The server has capabilities of tunneling any data from the infected client, such as uploading and downloading files and credentials.
- Most importantly, the server is able to spawn a shell on the client.

#### Client
- The client operates on a vulnerable host.
- When the client is executed, a domain name is specified (server) and all requests are sent to the local DNS server.
- For the server to receive a connection, the client has to successfully run on the target host.

#### Snort 
- Snort is an IDS that provides real-time analysis, data packet logging, and creates a signature or rule that links together a series of specific elements known as rule options.
- These options must be true before the rule is accepted and denotes a system alert.
- Payload rule options or primary rule options are divided into those that identify content elements and non-payload rule options or non-content-related elements.
- Snort rules are composed of two parts:
  - rule header
  - rule options
- Typically, the rule header contains the rule action (an alert), protocol, source/destination IP addresses, and source/destination ports.
- Snort can be essentially used in the same way as a sniffer and network IDS systems to detect and monitor malicious attack vectors traversing across the network.

#### Wireshark Filter Examples
- TXT Queries: `(dns.qry.type == 16) and !(dns.txt)`
  - TXT Responses: `dns.txt`
- CNAME Queries: `(dns.qry.type == 5) and !(dns.cname)`
  - CNAME Response: `dns.cname`
- MX Queries: `(dns.qry.type == 15) and !(dns.mx.mail_exchange)`
  - MX Response: `dns.mx.mail_exchange`
- Additional Filters: `dns and !ip.addr == <IP>` `dns and !(ip.src ==<IP> or ip.dst == <IP>)` `udp.port == 53`

### SNORT
- Capture live traffic on a selected interface: `snort -i "Enter Interface # here" -c C:\Snort\etc\snort.conf -A console`
- example of a snort rule: `alert udp any 53 <> any any (msg: "Possible DNScat activity" ; sid:1000001; rev:1;) `
- Check for activity within a specific PCAP: `snort -A console -K none -q -r C:/Users/trainee/Desktop/DNS/dnscat.pcap -c C:/Snort/rules/local.rules`
