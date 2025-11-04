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

## Common Enterprise Services
### Introduction
- Table 1.2-1 describes seven of the most commonly used application layer protocols (Layer 7) in an enterprise network.
- Although they are not the only protocols used in enterprise networks, they are the staple services used in nearly all networks.
  ![b23a4d8a-c127-484c-aa95-129d1855495b](https://github.com/user-attachments/assets/9605c301-052f-4221-acc2-d8d67e2e647c)

### HTTP Overview
- HTTP is an application-layer protocol used for relaying Internet services, such as handling communications and requests with web servers and resources.
- In its most basic form, HTTP is viewed as a file-sharing protocol. A client requests a resource from the server via HTTP. The server responds with the requested resource, signaling a successful HTTP transaction.
  ![f8b34d19-8b6a-4613-9d6a-d26c1abc64cf](https://github.com/user-attachments/assets/e65ddf7d-ce3a-4d41-a7c6-34dc39846a18)

#### Methods
- The form in which HTTP requests and responses are labeled is through their HTTP methods.
- Common HTTP methods and descriptions of their functions are as follows:
  - **GET**: HTTP request for a resource or copy of a resource, e.g., request index.html file for a specified webpage.
  - **HEAD**: HTTP request for only the header message, with no message body, e.g., request header information about a specified web resource to learn more details without loading the full page.
  - **POST**: HTTP method for submitting an item into a specified resource, e.g., create new user within the website.
  - **PUT**: HTTP method to replace all currently existing specified resources, e.g., update user information of an already created user on the website.
- NOTE: General advice is to use POST when you need the server to be in control of URL generation of your resources.
  - Preferred method is to use PUT over POST in most instances.
  - PUT and POST differ in that PUT is idempotent, meaning no matter how many times you run the command, it always produces the same results.
  - POST would yield different results for each time you run the command.
- HTTP transactions are dictated by status codes, which provide further information on the outcome of each transaction.
- HTTP includes a variety of status codes, which fall into the following groups:
  ![6b18666e-b619-43a2-87bb-ec55996b2b98](https://github.com/user-attachments/assets/1d29deb9-20e5-4a8c-b3eb-6fc9d38c720f)

#### Securing HTTP
- HTTP is powerful and provides many functions. However, HTTP data is transferred in the clear, making it susceptible to sniffing and Man-in-the-Middle (MitM) attacks.
- To combat such susceptibility to attacks, Hypertext Transfer Protocol Secure (HTTPS) was developed as an extension of the base protocol.
- HTTPS allows for secure encryption transmission using Transport Layer Security (TLS).
- Previous versions used Secure Sockets Layer (SSL), but documented vulnerabilities have forced the transition to TLS.
- The base protocol changes to TCP port 443 by default when HTTPS is used. HTTPS also allows for authentication to be handled by the protocol when used in conjunction with digital certificates.
- HTTPS is now commonly accepted as best practice when using HTTP services and is often a requirement of regulations or local policy on organizational networks.

### HTTP Packet Analysis
- Key details in this HTTP stream are provided below. Also, notice how Wireshark differentiates the requests and responses.
  - **RED** (Request): HTTP request GET method is used to request access to the HTTP web resource (/Websidan/index.html).
  - **Host**: 10.1.1.1 (In most cases, there should be a fully qualified domain name or hostname in the Host field. Direct connections to Internet Protocol [IP] addresses are abnormal for legitimate HTTP traffic.)
  - **User-Agent**: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0) Opera 7.11 [en].
  - **BLUE** (Response): HTTP Status Code 200 OK returned, meaning the HTTP request was successful and the requested web resources were properly handed over to the user-agent.
  - **Server**: Apache/2.0.40 (Red Hat Linux).
  - Content of the index.html file at the requested location, which includes the Hypertext Markup Language (HTML) code that designs the layout and content of the webpage.
-
- Using the functions discussed above in Wireshark shows the many important aspects of analyzing HTTP packets in future defensive cyber operations.
- Understanding how to view data in Wireshark and the tool's power to easily view HTTP streams is especially important.
- A wide range of network statistics, such as information about the loaded capture file or specific protocols, may be accessed via the Statistics menu.
- HTTP Statistics contains four analysis windows:
  - **Packet Counter**: Provides statistics for HTTP request types and response codes.
  - **Requests**: Provides HTTP statistics based on the host and URI.
  - **Load Distribution**: Provides HTTP request and response statistics based on the server address and host.
  - **Request Sequences**: Uses HTTP’s Referer and Location headers to sequence a capture's HTTP requests as a tree, which enables viewing of how one HTTP request leads to the next.
<img width="802" height="479" alt="d28e4f8e-37a0-47f9-8977-c6545900d95d" src="https://github.com/user-attachments/assets/1aa199e9-0ef1-4721-ad20-253184271957" />
  - Each field in the table provides valuable insights into different aspects of the network traffic:
    - **Topic/Item**: The type of HTTP packets or specific status codes related to the HTTP responses and requests.
    - **Count**: Number of packets for the HTTP requests or code.
    - **Rate**: Packet frequency over time.
    - **Percent**: Percentage that the particular category of packets constitutes of the total HTTP packets captured.
    - **Burst Rate**: Maximum capacity of transmitting data in a specified time span.
    - **Burst Start**: Time point when a burst starts to identify traffic spikes.

### DNS Overview
- The DNS protocol is responsible for the translation of IP addresses to human-readable Uniform Resource Locators (URL).
- DNS consists of three standard types: DNS queries on User Datagram Protocol (UDP) port 53, DNS responses on UDP port 53, and zone transfers on Transmission Control Protocol (TCP) port 53.
- Learning about the key portions of DNS queries and responses is critical to understanding DNS network communications.
- Zone transfers are a function of DNS servers and can be identified when DNS data is seen traveling across TCP rather than UDP.

#### DNS Queries
- DNS queries — also known as lookups — initiate DNS protocol.
- Reverse lookups provide an IP address to hostname translation, and forward lookups provide a hostname to IP address translation.
- The following DNS query types provide a more specific breakdown of how DNS requests are handled.
  - **Recursive Query**: The DNS client provides a hostname, and the DNS resolver must provide an answer; it responds with either a relevant resource record or, if such a record cannot be found, an error message.
    - The resolver starts a recursive query process, starting from the DNS root server, until it finds the authoritative name server that holds the IP address and other information for the requested hostname.
  - **Iterative Query**: The DNS client provides a hostname, and the DNS resolver returns the best answer it can.
    - If the DNS resolver has the relevant DNS records in its cache, it returns them.
    - If not, it refers the DNS client to the root server or another authoritative name server nearest the required DNS zone.
    - The DNS client must then repeat the query directly against the DNS server to which it was referred.
  - **Non-Recursive Query**: The DNS resolver already knows the answer and either immediately returns a DNS record because the resolver already stores it in a local cache or queries a DNS name server that is authoritative for the record.
    - In either case, there is no need for additional rounds of queries (as in recursive or iterative queries). Rather, a response is immediately returned to the client.

### DNS Record Types
- DNS records are the instructions that authoritative DNS servers provide about a domain.
- Many DNS record types exist, and they all serve a different purpose.
- Some of the most common DNS records and their functions are listed below.
  - **A Record**: Record holding the IP address of a specified host within a domain.
  - **AAAA Record**: Record holding the IPv6 address for a specified host within a domain.
  - **CNAME Record**: Forwarding one domain or subdomain to another domain (no IP provided).
  - **MX Record**: Record that directs mail to an email server.
  - **TXT Record**: Record for keeping administrative notes.
  - **NS Record**: Record holding the name and IP address of the name servers for the requested domain.
  - **SOA Record**: Record holding administrative information for a domain.
  - **SRV Record**: Record showing ports for services.
  - **PTR Record**: Record holding domain name in reverse lookups.
- NOTE: For a full list of DNS records, see the Internet Assigned Numbers Authority (IANA) DNS parameters web page.

#### Additional DNS Functions
- DNS provides a necessary function across the internet as well as within organizational intranets.
- However, these primary functions alone do not encompass all the services provided by DNS.
- Additional functions include:
  - **load balancing** (primarily for global data centers)
  - **multi-path routing** for content delivery networks
  - **physical locations** based on **best match**, **data center/cloud migration**, and **internet traffic management** (congestion avoidance).
- These functions make DNS an extremely powerful and useful tool in all environments, but proper implementation is the key to keeping it secure.

### SMB Overview
- SMB is a staple protocol that allows interconnected and trusted devices to communicate and share resources with one another.
- SMB is the backbone of any Windows Active Directory (AD)–centered enterprise network; it is used when logging into a machine as well as when accessing a Network File Share.
- In addition to internal networks, SMB is sometimes used in larger websites, controlling what certain users can access and view based on settings.
- To summarize, SMB is a file- and resource-sharing protocol.
- SMB uses TCP port 445 to communicate; legacy versions used TCP port 139 (Network Basic Input/Output System [NetBIOS]).
  ![0413a209-fa41-42b7-98ea-a18dad370415](https://github.com/user-attachments/assets/34d96152-43c7-4114-9bc9-394ce255373f)

- SMB uses client-to-server communication, in which, like HTTP, a client makes a specific request and the server responds.
- However, with SMB, not only can files and folders be requested and accessed, but inter-process communication can also occur.
- On a Windows device, there is a default virtual share named ipc$ that handles the inter-process communications within the network, provided the machines are authenticated properly.
- In the context of SMB, a server does not have to be an actual server but, instead, is any responding host in an SMB transaction.
- SMB has different versions called dialects. An SMB dialect is the specific implementation of the protocol that enables the devices to communicate and share resources.
- Some of the most common dialects used in network environments today are listed below.
  - **Common Internet File System**: Provides shared access to such networked resources like files and printers.
    - When using this dialect, an authenticated client can potentially have full access to the responding server. This is mainly found in older Windows networks.
  - **Samba**: The open-source suite of programs that allow non-Windows devices to integrate with Windows Active Directory environments.
  - **SMBv2**: The default lowest version standard in Windows networks, replacing SMBv1. Although SMBv2 offers no form of encryption, it is slightly more secure than SMBv1.
  - **SMBv3**: The newest standard of SMB, shipped by default with Windows 10 and Windows Server 2016; offers default encryption in the form of Advanced Encryption Standard-Galois/Counter Mode (AES-GCM).
- Many different kinds of SMB requests and responses exist, and they vary, depending on the OS and software suite using the protocol as well as the clients.

#### Securing SMB
- As stated earlier, SMBv1, the original version of SMB, is considered a legacy protocol and is not found within modern OSs and software.
- SMBv2 is the minimum accepted version of SMB to be used.
- However, even SMBv2 is not secure by today's standards, and, where possible, SMBv3 should be used throughout any Windows network environment.

### FTP Overview
- File Transfer Protocol (FTP) is a simple yet powerful protocol for transferring files between hosts.
- FTP is used as an internal protocol for resource sharing inside an enterprise network as well as for publicly accessible resources.
- FTP allows the use of access controls and monitoring and can even support anonymous logins.
- Like SMB and HTTP, FTP is another protocol that relies on a client-to-server communication module, and the user (client) typically uses some sort of software, or FTP client, to interact with the FTP server.
- The Control Connection is the connection that is initially established between the FTP client and the FTP server and is used for negotiating the connection, credentials, etc.
- Port **21** is used for the C**ontrol Connection**.
  - Once the Control Connection is established, it is then used to establish the Data Connection.
  - This connection is used to actually transfer files between the client and server.
  - Port 20 is used for the Data Connection.
![d6afe70b-5dfe-4a6c-9759-94fffa95ba49](https://github.com/user-attachments/assets/0e3700a7-b5ea-4236-9330-8f1522425126)

- FTP supports two ways of configuring the connection between client and server:
  - Active Mode: A connection is made both from the client to the server and from the server to the client.
    - First, the FTP client attempts to initiate the connection to the FTP server over port 21 while supplying the server with an ephemeral port (PORT command) to connect back to the client.
    - The server then sends a connection back to the client over the designed ephemeral port.
    - To use this mode, the client needs to be able to accept inbound connections.
    - For obvious security reasons, this is not always possible, which is why Passive Mode exists.
  - Passive Mode: Two outbound connections from the client to the server are made.
    - First, the FTP client attempts to initiate the connection to the FTP server over port 21.
    - Instead of sending a PORT command, it sends a PASV command, which prompts the server to supply an ephemeral port, which the client then uses to connect back to the server to establish the data connection.
    - This is used when the FTP client is unable to accept inbound connections.
- Much like HTTP response codes, FTP uses its own set of response codes called return codes.
- Below is a list of some of the more commonly seen return codes:
  - Return Code **200**: The server accepted the command, and it ran successfully.
  - Return Code **212**: The message attached is referring to the status of the directory.
  - Return Code **213**: The message attached is referring to the status of the file.
  - Return Code **214**: This is a help message for the user interacting with the server.
  - Return Code **221**: This is sent when the server is closing the control connection.
  - Return Code **226**: This is sent when the server is closing the data connection.
  - Return Code **331**: This is sent when the server accepts the supplied user name from the FTP client.

#### Securing FTP
- FTP is susceptible to attacks in its standard form, as authentication and data are sent completely unencrypted.
- This leaves all data vulnerable to theft or alteration during transmission.
- To secure this format, FTP makes use of the Secure Shell (SSH) protocol.
- SSH allows for secure authentication and creates encryption over the FTP protocol, and it is therefore called SSH File Transfer Protocol (SFTP).
- SFTP alters the standard port usage from 20/21 to 22 (SSH).
- However, an even more secure version, File Transfer Protocol Secure (FTPS), is used far more widely.
- FTPS is the process of using TLS (formerly SSL, which is now considered insecure) to secure the transfer of files.
- Using TLS for encryption allows for the use of strong cryptographic ciphers (such as AES) and provides additional options for securing authentication and commanding.

### SMTP Overview
- The widely used SMTP protocol helps to transmit emails across the web.
- SMTP, in modern applications, is primarily only used for sending email messages — but capable of both sending and receiving as illustrated in the traffic flow shown in Figure 1.2-42:
![ab9fa2a2-6cf9-4dbf-a7b6-0855838906e5](https://github.com/user-attachments/assets/ca673186-fe4b-4f05-8d29-3091e34b0f9f)

- A user's message is sent from their email user agent directly to a Message Transfer Agent (MTA) server.
  - Then SMTP is used between MTAs, starting by establishing a three-way handshake over TCP port 25.
  - The MTAs transfer the message to ensure the email message flows to the proper mail transfer agent of the recipient.
  - Often this must jump through far more than two servers, as Figure 1.2-42 suggests.
  - After the message reaches the final MTA, the recipient can access the message through the use of an email user agent.

- An additional device used in SMTP is called an **edge transport server**.
  - **Edge transport servers** reside on the **edge** of a local network, often associated with an organization.
  - These servers are responsible for coordinating any email that travels into or out of the local network.
  - Edge servers provide a means of securing email traffic by providing layers of protection in filters and message flow.
  - Edge servers are commonly responsible for filtering out spam or malicious email traffic.
- Another SMTP device is an **SMTP Open Mail Relay**.
  - These devices are meant to work in forwarding traffic to proper MTAs, or basically routing the mail on to reach its proper destination.
  - These devices used to be a common implementation of SMTP, but are no longer used regularly due to malicious activity like spam being easily sent through them or worms replicating through their services.

- SMTP has become outdated in numerous ways and has been replaced by Extended SMTP (**ESMTP**).
  - ESMTP provides numerous improvements by adding such features as audio, video, images, and multiple languages within the message formats.
  - As mentioned above, **SMTP/ESMTP** are also commonly only used in modern networks only for sending mail (**outgoing**).
  - Protocols such as **POP3** and **IMAP** are primarily used for retrieving mail from mail servers (**incoming**).

#### SMTP Status Codes
![e0be2153-0943-4006-ad44-57c4d02c7b89](https://github.com/user-attachments/assets/7ed7ac04-437c-425f-a12e-2044562e4e98)

#### SMTP Status Subcodes
![f5f87294-ba6f-43b1-8fa2-a090dce5fe43](https://github.com/user-attachments/assets/6fd7caff-7ab6-4adb-b6ff-58f5034451f6)

#### Securing SMTP
- Like many other older protocols, SMTP was not built with many inherent securities.
- However, like many other protocols, the use of TLS can be used to add much-needed encryption to the communications of SMTP.
- Unlike the other protocols, however, SMTP does not get a new protocol for this added security but simply works by ensuring TLS is enabled between all agents and servers using SMTP.

### OT Overview
#### Operational Technology Network Use
- Operational Technology (OT) networks communicate over specialized and often proprietary protocols.
- These networks, while operating by their own standards, are usually closed off and carefully monitored, with any changes in the environment carefully and precisely implemented.
- This is due to the volatile nature of the interoperability between devices.
- Additionally, these networks typically house critical machinery and instruments, such as fuel pumps, valves, and other specialized tools in various environments.
- OT networks are often found in such locations as **power plants**, **water treatment plants**, and **refineries**.
- Each of these networks houses its own unique array of devices and its own communication protocols.
- When analyzing traffic within an OT network, reading the different proprietary protocols and how they interact with one another can be challenging.

#### Common OT Devices
- Various devices are used to **monitor**, **report**, and **control** these systems **remotely**.
- Programmable Logic Controllers (**PLC**) and Remote Terminal Units (**RTU**) serve the same purpose.
  - This purpose is to **remotely communicate** with the physical devices that are being controlled and monitored.
  - This can include such items as valves or pumps. Human Machine Interfaces (**HMI**) are what plant operators interact with.
    - Various devices that are collecting and interfacing with physical devices report back to the HMI as a central location that operations can interact with to operate and monitor the machine.

#### Common Protocols in OT Networks
- Although many proprietary protocols are used in OT networks, some protocols exist to attempt to standardize the communications between these devices.
- Table 1.2-5 provides a brief overview of the commonly shared protocols among OT networks, along with links to more details for each.
  ![f7c52056-1db6-46d4-a923-5ea90d20da28](https://github.com/user-attachments/assets/ee4dfd09-855c-4cc4-850d-ca162754e042)

#### Additional Protocols in OT
- Many OT protocols besides those in the table above exist, and proprietary protocols are still commonly used within OT networks.
- Many of these protocols are unique to the device manufacturer and are created that way to keep the protocol unique, obscure, and capable of safely and securely transmitting data.
- Some standard IT network protocols, such as DNS, are now being used in OT networks.
  - Such IT protocols provide the same unique functions while used on these networks and provide key functions for OT network expansion.
  - However, these protocols are still altered in scope to not provide services outside of the OT network environment.
  - Due to the nature of these protocols being widely used and commonly the focus of cyber attacks, many OT implementations avoid them if possible.
  - Securing OT networks is a challenge, in that many of the systems are built without security in mind or have very outdated implementations.
  - This insecurity is combatted by ensuring most OT networks are completely closed or have strictly limited and controlled access to external networks or devices.
  - Access to the network is protected through logical and often physical separation (air gap) with physical security controls.

#### Overview of Differences between OT and IT Networks
- OT and IT networks differ in protocols and devices.
- In addition, OT networks are generally in a static state.
  - This means even the smallest variations and deviations from the baseline should be considered threats and require investigation.
  - IT networks tend to be more malleable, allowing for more variations and the network’s ability to compensate for those variations without cause for alarm.
- Many protocols and unique devices of an OT network are provided in Figure 1.2-50.
- The network is segmented by device types, and a modbus-gateway handles the routing of traffic from each of these unique network segments.
- Modbus is used as the protocol which is capable of handling the different types of network traffic from each segment.
- The Master Terminal Unit network houses all the HMI devices which are the primary access point for interaction within the OT network.
- The PLC network is home to the PLCs, which operate much of the industrial equipment.
- This segment makes use of the Profinet protocol to communicate with the other devices.
- Finally, the OT-Services network has backend services and Industry Control System (ICS) data and also houses the administration devices for providing maintenance on the other segments.
- This example is a great highlight of the unique nature of OT networks.
  ![74e39f9b-b9f7-4d6b-8e13-d7c2432d1313](https://github.com/user-attachments/assets/16211444-a6df-4026-8627-2e619d4e454a)

## Split OSI Model
### Communications Reference Models
- Two primary reference models are used today to provide a framework for network communications:
  - Transmission Control Protocol/Internet Protocol (**TCP/IP**) model
    - The TCP/IP reference model (referred to as the TCP/IP suite, known as the [DoD] model when it was under development) was conceptualized and brought to life by the United States DoD Advanced Research Projects Agency (**DARPA**) in the early 1970s.
    - DARPA used the knowledge acquired in researching reliable data communications over packet radio networks, as well as lessons learned from the Networking Control Protocol (NCP), to develop the TCP/IP model and protocol.
    - In 1983, the TCP/IP suite became the standard protocol for the Advanced Research Projects Agency Network (**ARPANET**).
  - Open Systems Interconnection (**OSI**) model.
    - The OSI reference model was also born in **1983** with the combination of two competing projects that started in the late 1970s.
    - The International Organization for Standards (**ISO**) directed one project, and the French organization International Telegraph and Telephone Consultative Committee (**CCITT**; later renamed the International Telecommunication Union Telecommunication Standardization Sector [**ITU-T**]) directed the other.
    - The two projects' merged documents created The Basic Reference Model for Open Systems Interconnection standard, commonly referred to as the **OSI** model. This standard was published in **1984**. 

#### Suite, Stack, and Model
- As described in Walter Goralksi's The Illustrated Network: _How TCP/IP Works in a Modern Network, the term protocol stack is often used synonymously with protocol suite as an implementation of a reference model_.
- However, protocol suite actually refers to a collection of all the protocols that can make up a layer in the reference model.
- The IP suite is an example of the internet or TCP/IP reference model protocol, and a TCP/IP protocol stack implements one or more of these protocols at each layer.

#### OSI Model
- The most referenced and used model today is the OSI model, a technology- and vendor-agnostic model that divides communications processing into seven different and distinct entities, or layers.
- Each layer provides a critical function to the communications process while supporting the existing layer directly above or below it.
- Table 1.3-1 provides a description of each layer of the OSI model, along with its associated Protocol Data Unit (PDU), common malicious activity, and mitigating control samples.
  ![876bdb63-7465-4cd2-81c3-84f9f224d1c8](https://github.com/user-attachments/assets/c6489329-c08b-49a6-a359-aeb68e85e576)

- *The Session layer is implemented explicitly in environments that use remote procedure calls. Therefore, Remote Procedure Call (RPC)–based attacks are directly related to the operations of the OSI model's Session layer. 
- Figure 1.3-1 provides an analogy of how data progresses through the OSI model by demonstrating communication between two Chief Executive Officers (CEO).
  ![bb4d260f-9f17-467f-954a-259fd2a97314](https://github.com/user-attachments/assets/39d801f8-1b26-41e4-975f-60bab4570f0a)

#### TCP/IP Model
- The original TCP/IP model (also called the TCP/IP suite) was named by combining its two main protocols, TCP and IP.
- The original TCP/IP model specified four distinct layers, and, like the OSI model that followed, each TCP/IP layer provided a critical function to the communications process, supporting the existing layer directly above or below it.
- After the OSI model was published, several authors (including James F. Kurose, Behrouz A. Forouzan, and Andrew S. Tanenbaum) introduced OSI Layers 1 and 2 into the TCP/IP model in their publications.
- The result was an updated TCP/IP model that was more aligned with the OSI model by splitting the original Network Interface layer into two layers — the Physical and Data Link layers — and renaming the Internet layer the Network layer.
- Table 1.3-2 provides a representation of the original and updated TCP/IP models in comparison to the OSI model and displays how the TCP/IP model consolidates OSI model Layers 5, 6, and 7 into the Application layer.
  ![4c261645-629d-4071-89ce-066e9ee79f31](https://github.com/user-attachments/assets/4e3ee0cd-2850-4350-9d36-9d4b663646c5)

#### Differences and Similarities
- Figure 1.3-2 compares the individual layers of the TCP/IP model and OSI model.
- Each model separates specific functions of preparing and processing data for transmission and reception into layers.
- The OSI model provides a conceptual framework, whereas the TCP/IP model is aligned with real-world applications.
- Notice that services or protocols are not used to name or describe layers of the OSI model.
- This is to ensure that the model is completely agnostic and can be applied to any network with any combination of services, protocols, and hardware vendors.
  ![4f002032-173b-4491-9a0f-fe1c6b4733cc](https://github.com/user-attachments/assets/80f99186-d3df-4b94-bd31-ae2cac40b452)

#### Network Analyst Data Domain
- Figure 1.3-3 highlights the data domain of a Network Analyst.
- The lower layers of the OSI model — Layers 1 through 4 — make up the dataset that Network Analysts spend the most time analyzing, identifying malicious activity, and advising on mitigating controls.
- Datasets associated with the upper layers of the OSI model — Layers 5 through 7 — are more the domain of Host Analysts.
- This does not mean that Network or Host Analysts do not venture into analyzing all layers of the OSI model.
- However, understanding the interactions and delineation between the layers of the OSI model provides opportunities for Network Analysts and Host Analysts to collaborate and identify MCA occurring on a network. 
  ![31457f43-fa82-4bdb-b257-f28447a18ed6](https://github.com/user-attachments/assets/514fd3e6-cc23-4f40-a3d9-e2a535131d95)

### Lower Layers of the OSI Model
![f42a4941-f4f6-47a3-93d1-2156f3827493](https://github.com/user-attachments/assets/74992d2d-ab85-4ae2-832b-b980948ec104)

- Understanding key elements of these layers can assist a Network Analyst in supporting a team configuring the network for packet captures, determining the optimal tools to analyze the data collected, and extracting interesting artifacts for further analysis.
- Command-line tools such as **tcpdump** and **TShark** are efficient tools for quickly triaging packet capture files.
- The ability to assess statistical information without having to transfer files across a network when data is captured and stored on a remote system or open the files with more computer-intensive programs can expedite identifying interesting data. To display **statistical** information, **TShark provides the -z parameter**. 

### Triaging Packet Captures | Layer 2
- From CLI, run the following to analyze Layer 2 statistics from a packet capture: `tshark -nn -r ~/pcap/smallFlows.pcap -q -z conv,eth.addr`
  <img width="751" height="612" alt="image" src="https://github.com/user-attachments/assets/30f5c31f-ab61-451e-ae63-04c4d567ee24" />

### Triaging Packet Captures | Layer 3
- From CLI, run following to analyze Layer 3 Statistics: `tshark -nn -r ~/pcap/smallFlows.pcap -q -z conv,ip`
  <img width="759" height="239" alt="image" src="https://github.com/user-attachments/assets/8e4b3d5a-554a-4473-89b0-739a81b0bfd2" />

### Triaging Packet Captures | Layer 4
- From CLi, rin following to analyze Layer 4 Statistics: `tshark -r ~/pcap/smallFlows.pcap -q -z io,phs`
  <img width="752" height="255" alt="image" src="https://github.com/user-attachments/assets/3610befc-11af-40b2-a17b-5c7ff69a9dc5" />

### Upper Layers of the OSI Model
- Network Analysts can quickly create a raw picture of communications occurring on a network with the initial triage of packet captures using command-line tools and pivot to more feature-rich applications for deeper packet analysis once interesting traffic or anomalies have been identified.
- Host Analysts can then leverage the IP addresses and port information acquired, which, paired with additional payload analysis, can potentially tie the communication back to services running on client computers or servers.
- Ultimately, this is used in attempting to pinpoint active malicious code.
- In the OSI model's Layers 5, 6, and 7 or the TCP/IP model's Application layer, payloads can be reassembled from TCP or UDP streams back into files.
- No encryption should have taken place at Layer 6 of the OSI model for this process to be successful.
- If encryption were applied at Layer 6, the analyst would need the encryption keys to process the payload. 
  ![a9f127e3-9b97-4723-9f20-b3b28bbcd49e](https://github.com/user-attachments/assets/97208d31-f0e9-492a-a2cf-9e57789a4279)

- Everyday tasks when analyzing the upper layers of the OSI model include determining applications being used for communications, identifying encryption, and payload reassembly.
  - These tasks benefit from the use of tools with extended capabilities.
    - Some command-line tools might still complete tasks like the ones described, but such applications as **Wireshark**, **Suricata**, and **Zeek** are better suited.
  
### Triaging Packet Captures | Layers 6 and 7
1. Open Wireshark and use the following filter: `ip.addr==209.17.73.30 && ip.addr==192.168.3.131`
2. Expand the info to display info about the TCP/IP Application Layer
<img width="768" height="541" alt="image" src="https://github.com/user-attachments/assets/233cd1fa-72f1-4da6-9db9-9ec088eeeda4" />

<img width="826" height="595" alt="image" src="https://github.com/user-attachments/assets/0d527de1-bb58-4367-8c24-243df5b046f1" />

### Mapping Suspicious Activity
1. run the following to see applications on a specific IP: `tshark -nn -r ~/pcap/bigFlows.pcap -Y 'ip.addr==172.16.133.27' -q -z io,phs`
2. Export the data into a PCAP: `tshark -q -r ~/pcap/bigFlows.pcap -Y 'ip.addr == 172.16.133.27' -w host01.pcap`
3. copy the pcap to your system: `scp trainee@199.63.64.110:~/host01.pcap .`
4. Open in Wireshark and use the following filter to isolate the POP3 traffic from the IP address in question: `ip.addr==172.16.133.27 && tcp.port == 110`
5. 


  
