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

<img width="822" height="595" alt="image" src="https://github.com/user-attachments/assets/3dbf4ad8-fe19-4ca9-a797-7dc9013a3155" />

## Traffic Analysis
### Network Traffic Analysis
- Monitoring, baselining, triaging, and assessing network communications occurring on partner networks are critical tasks required for practical Network Traffic Analysis (NTA).
- NTA aims to identify baseline deviations, classify the anomaly source as operational or malicious, and further triage and investigate any hostile activity.
- Any engagement on a partner network most likely requires analyzing network traffic.
- Some use cases are as follows:
  - Establishing a baseline of regular communications if one does not exist.
  - Comparing real-time traffic against an established baseline.
  - Capturing network traffic for offline analysis.
  - Identifying anomalies that can present themselves as an increase in chatter from a host, the use of uncommon ports, protocols or ciphers.
  - Identifying the use of protocols with known vulnerabilities.
  - Unauthorized communications, for example, an Industrial Control System (ICS) Programmable Logic Controller (PLC) opening a connection to the internet (this could be an operational requirement, but it is unlikely).
- With the network providing the highway for all data communications, the network becomes a broad attack surface.
- A critical step for practical NTA is identifying key cyber elements of an organization and collecting data at the correct intersections of the data highway.
- Network data can also be collected in different formats for analysis.
- Flow data provides a practical insight into high-level communications: where the packets originate from, where they are going, and the traffic volume.
- Even though this level of information would be helpful to detect some unauthorized or malicious activity, it would lack the details of packet data.
- Packet data can provide insight into how threat actors are leveraging authorized communications to achieve their objectives.

- Effective NTA can be a daunting task. Understanding how hosts process traffic on a network and their relation to the Open Systems Interconnection (OSI) model with their capabilities can expedite and facilitate meeting task objectives.
- When assessing a network for NTA, consider the following:
  - **Network Assets**: What are the asset capabilities to support NTA? Do the assets on the network have packet capture capabilities? Do the assets support flow data?
  - **Data Source**: Use filters to capture relevant data and strategically identify where to collect the data, such as gateways or switches connecting critical assets or crown jewels.
  - **Collection Source**: Not all assets can collect data compatible with the toolset being used for analysis. Ensure that compatibility exists with tools being used.
  - **Collection Time**: Historical data is key to building baselines and analyzing past events, though some tools lack the compute resources to store large amounts of data. Real-time collection can be used to identify anomalies. It is more effective if a reliable baseline exists.
  - **Full Packet Captures**: Full packet captures are resource intensive and demand ample storage space if a mission requires analysis for an extended period of time. Applying filters and prioritizing data sources are key to minimizing storage impact.
- The task of NTA falls under the Discover and Counter Infiltration function of a Cyber Protection Team (CPT) operation, as described in the United States Cyber Command (USCYBERCOM) Cyber Warfare Publication (CWP) 3-33.4:
Discovery and Counter Infiltration (D&CI) by detecting, illuminating, and defeating discovered or previously unknown threats within a secured network or system.

#### OSI Model Layers 3 and 4
- The OSI Network and Transport Layers, at a high level, are responsible for routing data between different networks (Network Layer) and providing reliable end-to-end data delivery (Transport Layer).
- The Network Layer provides the logical addressing to route data packets across wide-area networks such as the internet.
- Similar to a frame switched to a Media Access Control (MAC) address at the Data Link Layer, a packet is routed from a source Internet Protocol (IP) address to a destination IP address.
- Finally, the Transport Layer, also at a high level, is responsible for how data is transferred from point A to point B.
- The Transport Layer manages splitting data into smaller segments when necessary, transfer rates, and error control using checksum, acknowledgments, and retransmissions. 
  ![a4b6104c-346d-40bd-8b1f-71b36f201574](https://github.com/user-attachments/assets/cfd01ee2-fb8c-423a-803b-46217cab652c)

### Layer 3: Network
- The OSI model's Network Layer uses logical addressing to transmit data from one host to another located on a remote network.
- The two primary functions of the Network Layer of the OSI model are as follows:
  - **Routing**: The Network Layer protocols determine which route is suitable from source to destination.
  - **Logical Addressing**: Logical addressing is used to uniquely identify hosts across networks. The Network Layer defines a logical addressing scheme. 
![362b6f3e-6981-4eaf-8b23-59c0f9f09a26](https://github.com/user-attachments/assets/25819b75-1930-4fa9-96e5-061ca1cf3da2)

#### IP Header Fields
- Version Number
  - These four bits specify the IP version of the datagram.
  - By looking at the version number, the router can determine how to interpret the remainder of the IP datagram.
  - Different IP versions use different datagram formats.
  - The datagram format for the current version of IP, IPv4, is shown in Figure 1.4-2 above.
  - The datagram format for the new version of IP, IPv6, will be discussed later.
- Header Length
  - Because an IPv4 datagram can contain a variable number of options (which are included in the IPv4 datagram header), these four bits are needed to determine where in the IP datagram the data actually begins.
  - Most IP datagrams do not contain options, so the typical IP datagram has a 20-byte header.
- Type of Service
  - The Type of Service (TOS) bits were included in the IPv4 header to allow different types of IP datagrams (e.g., datagrams particularly requiring low delay, high throughput, or reliability) to be distinguished from each other.
  - For example, it might be useful to distinguish real-time datagrams (such as those used by an IP telephony application) from non-real-time traffic (e.g., File Transfer Protocol [FTP]).
  - The specific level of service to be provided is a policy issue determined by the network administrator.
- Datagram Length
  - The datagram length is the total length of the IP datagram (header plus data), measured in bytes.
  - Because this field is 16 bits long, the theoretical maximum size of the IP datagram is 65,535 bytes.
  - However, in practice, datagrams are rarely larger than 1,500 bytes due to 1,500 being a common default Maximum Transmission Unit (MTU) value, which governs the maximum size of a single packet traversing that network.
- Identifier, Flags, Fragmentation Offset
  - These three fields have to do with so-called IP fragmentation, which allows a single packet sent by a host to be split up into multiple, smaller packets.
  - This allows Layer 3 devices to transmit to networks with smaller MTU values.
  - IPv6 does not allow fragmentation during routing, and all IPv6 networks must support a minimum MTU of 1,280.
- Time-to-Live
  - The Time-to-Live (TTL) field is included to ensure that datagrams do not circulate forever (due to, for example, a long-lived routing loop) in the network.
  - This field is decremented by 1 each time the datagram is processed by a router.
  - If the TTL field reaches 0, the datagram must be dropped.
- Protocol
  - This field is used only when an IP datagram reaches its final destination.
  - The value of this field indicates the specific Transport Layer protocol to which the data portion of this IP datagram should be passed.
  - For example, a value of 6 indicates that the data portion is passed to Transmission Control Protocol (TCP), and a value of 17 indicates that the data is passed to User Datagram Protocol (UDP).
  - The protocol number in the IP datagram has a role that is analogous to the role of the port number filed in the Transport Layer segment.
  - The protocol number is the glue that binds the Network and Transport and Application Layers together.
- Header Checksum
  - The header checksum aids a router in detecting bit errors in a received IP datagram.
  - The header checksum is computed by treating every two bytes in the header as a number and summing these numbers using 1s and complement arithmetic.
- Source and Destination IP Addresses
  - When a source creates a datagram, it inserts its IP address into the source IP address field and inserts the address of the ultimate destination into the destination IP address field.
  - Often, the source host determines the destination address via a Domain Name Service (DNS) lookup.
- Options
  - Options extend the IP protocol functionality to support features not commonly used, such as timestamp, record route, and strict route mode.
  - For security reasons, network devices will generally be configured from the factory to ignore or drop packets with these fields set.
  - In addition, packets transmitted with these options should be further investigated because threat actors can use them to manipulate how packets route through a network or collect network intelligence. 
- Data (Payload)
  - Arguably the most important field in most circumstances, the data field of the IP datagram contains the Transport Layer segment (TCP) or UDP to be delivered to the destination.
  - However, the data field can carry other types of data, such as Internet Control Message Protocol (ICMP) messages.
  - Note that an IP datagram has a total of 20 bytes of header (assuming no options).
  - If the datagram carries a TCP segment, then each (non-fragmented) datagram carries a total of 40 bytes of header (20 bytes of IP header plus 20 bytes of TCP header) along with the Application Layer message.

### Layer 4: Transport
#### Overview
- Several implementations of the OSI model exist that handle Layer 4, the most common of which is the TCP/IP model.
- The TCP/IP model has two primary protocols that are carried over it: TCP and UDP.
- As discussed in previous lessons as well as in Joint Cyber Analysis Course (JCAC) materials, UDP is a stateless protocol, whereas TCP maintains connection states.

#### TCP Metadata
- TCP sessions are established by using a three-way handshake: Synchronize (SYN), SYN-ACK, and Acknowledge (ACK).
- The client sends a SYN packet to the server, receives a SYN-ACK response, and then sends an ACK response back to the server.
- Once a session is established, the metadata available in a TCP payload can be used to track the session.
- Routers performing Network Address Translation (NAT) track open sessions to determine which IP address to forward traffic to.
- Figure 1.4-3 illustrates a typical TCP segment header:
  ![4ebbb460-fbf1-45e3-acf4-d9970321dbf3](https://github.com/user-attachments/assets/78b5a086-5ad0-4745-877e-7ff365f96b09)

- From Figure 1.4-3, the following segments can be used to track a TCP session:
  - Source IP (from IP Header)
  - Destination IP (from IP Header)
  - Source Port
  - Destination Port
  - Sequence Number

##### TCP Header Fields
- The TCP header is 20 bytes long 
  - Source Port: The source port is a 16-bit number.
  - Destination Port: The destination port is a 16-bit number.
  - Sequence Number: The sequence number is a 32-bit number used by hosts on each end of a TCP session to track segments of how much data has been transmitted.
    - The sequence number is added to each transmitted packet.
    - When a host initiates a TCP session, the initial sequence number is a random value between 0 and 4,294,967,295.
    - However, to facilitate keeping track of sequence and acknowledgment numbers, Wireshark and other protocol analyzers display sequence numbers relative to the initial sequence of that stream.
    - At each packet transmission, the sequence number will be incremented by the size of the data field plus 1.
    - TCP packets with a SYN, FIN, or RST flag are only incremented by +1 because they do not carry payloads.  
  - Acknowledgment Number: The acknowledgment number is a 32-bit number field indicating the next sequence number that the sending device is expecting from the other device.
  - Header Length: The header length is also referred to as the Data Offset field, a four-bit field showing the number of 32-bit words in the header.
    - The minimum-size header is five words (and the binary pattern is 0101).
  - Reserved: The Reserved field is always set to 0 (size 6 bits).
  - Control Bit Flags: TCP is a connection-oriented protocol.
    - Before any data can be transmitted, a reliable connection must be initiated and acknowledged.
    - Control bits govern the entire process of connection establishment, data transmissions, and connection termination.
    - The following control bits are assigned to the TCP header:
      - **URG**: Urgent Pointer.
      - **ACK**: Acknowledgment.
      - **PSH**: This flag means Push function. Using this flag, TCP allows a sending application to specify that the data must be pushed immediately.
        - When an application requests the TCP to push data, the TCP should send the data that has accumulated without waiting to fill the segment.
      - **RST**: Reset the connection. The RST bit is used to RESET the TCP connection due to unrecoverable errors.
        - When an RST is received in a TCP segment, the receiver must respond by immediately terminating the connection.
        - A RESET causes both sides immediately to release the connection and all its resources.
        - As a result, transfer of data ceases in both directions, which can result in loss of data that is in transit.
        - A TCP RST indicates a connection that was terminated for an unknown reason.
      - **SYN**: This flag means synchronize sequence numbers. The source is beginning a new counting sequence. In other words, the TCP segment contains the sequence number of the first sent byte (ISN).
      - **FIN**: This flag means no more data from the sender.
        - Receiving a TCP segment with the FIN flag does not mean that transferring data in the opposite direction is not possible.
        - Because TCP is a fully duplex connection, the FIN flag will cause the closing of connection only in one direction.
        - To close a TCP connection gracefully, applications use the FIN flag.
  - Window Size: This field indicates the size of the receive window, which specifies the number of bytes beyond the sequence number in the acknowledgment field that the receiver is currently willing to receive.
  - Checksum: The 16-bit checksum field is used for error-checking of the header and data.
  - Urgent Pointer: The urgent pointer shows the end of the urgent data so that interrupted data streams can continue.
    - When the URG bit is set, the data is given priority over other data streams (size 16 bits).

#### UDP Metadata
- UDP, being stateless, does not have sessions implemented at the Transport Layer (although applications can, and often do, implement their own logic).
- However, routers performing NAT can be configured to allow for return traffic whenever a device behind the NAT sends a packet for a specific amount of time.
- The metadata available in UDP is similar to what is found in TCP, as shown in Figure 1.4-4:
  ![e491f228-1c79-403d-980b-384172e8dd6e](https://github.com/user-attachments/assets/3627ed02-01ce-4ba0-83cd-c2eed6c872fa)

##### UDP Header Fields
- Source Port Number: The first 16 bits of the UDP header contain the port number of the sending application.
- Destination Port Number: The next 16 bits contain the port number of the receiving application.
- Length: The next 16 bits identify the datagram size in bits.
- Checksum: The checksum field of the UDP header contains a checksum value.
  - This pseudo header helps to find transfer bit errors and also to protect against other types of network errors like the possibility of the IP datagram reaching a wrong destination.
- Example protocols that are built upon UDP include Trivial File Transfer Protocol (**TFTP**), DNS, Remote Procedure Call (**RPC**) used by the Network File System (**NFS**), Simple Network Management Protocol (**SNMP**), and Lightweight Directory Access Protocol (**LDAP**).

### Traffic Flow
- When analyzing traffic flow, following the metadata available in packets is a good place to start to map out which hosts are communicating with each other and to determine what services appear to be active and reachable on the network.
- This can be combined with existing documentation or with previous mapping efforts to give a clearer picture of actual traffic that occurs on a network.
- Although this cannot encompass all possible network traffic typical to a network without having extensive logs over an extended period of time, this traffic flow analysis is still useful for enhancing maps and determining normal vs. abnormal traffic flow patterns.
- Sensor placement or tap points can greatly affect the usefulness of metadata when determining traffic flow patterns.
- Taps placed at network edges do not receive internal traffic, but they can be useful for determining traffic flow between networks.

#### Tools
- Although some tools can perform some traffic flow analysis automatically, other tools can provide a more methodical or programmatic analysis of a network.
- These tools may not replace automated tools but can provide additional useful information during the course of a mission.
  - **Wireshark** has tools and analyzers that can help, such as the **Endpoint analyzer**, available via menus.
    - Analysis using Wireshark typically involves getting a list of endpoints and then performing analysis on each endpoint to determine traffic flowing to and from that endpoint.
    - Combined with other tools, Wireshark can be used to give more granular views to the underlying data.
  - **Security Onion** and other solutions using Kibana as the presentation layer can be queried via the search bar or via predeveloped dashboards and visualizations.
    - When using **Kibana** in a methodical manner, query to determine active hosts, and then perform queries for each host, and document the services these machines communicate to.
- Manual, methodical methods might require summarization of traffic to generate a consumable, usable report if exporting data from queries is not an option.

### Baselining
- Baselining is critical to establishing the pattern of acceptable and normal communications on a network.
- From an operational standpoint, baselining is conducted to confirm that the applications, systems, and hosts connected to the network are operating and behaving per configuration requirements.
- For example, the baseline will validate that the volume of data transmitted on the network is within the expected and acceptable range, that the protocols and ports used for communications are aligned with documentation and best practices, and that only authorized hosts are communicated as expected.
- In addition, working with a certified baseline allows security analysts to identify anomalies by comparing real-time traffic to that of the baseline.
- Any deviation from the baseline should trigger further investigation to identify operational errors or malicious intent.
- This can be done by additional traffic monitoring and analyzing the packet payloads of the anomalous traffic.

# MOD 2
## Operational Standards
### Standards overview and Applications
#### Information Technology Best Practices
- The Information Technology (IT) industry has standards and best practices that function similarly to the ones in our daily lives.
- For example, using comments and avoiding the usage of hard-coded variables in programming are widely accepted best practices.
- There are also reference documents called enterprise architecture frameworks.
  - These frameworks bring standardization and organization to large and extremely complex IT networks.
  - Not only do standardized networks allow newcomers to learn the systems with greater ease, but they also simplify maintenance and expansion.
  - One example of a standards framework is The Open Group Architecture Framework (**TOGAF**), a common framework used today that provides a method for **designing**, **planning**, **implementing**, and **governing** an enterprise IT architecture.

- The Health Insurance Portability and Accountability Act (**HIPAA**) of 1996 is a law that created a national framework that aims to protect a patient’s health information from being disclosed without their knowledge.
  - By conforming to HIPAA, medical organizations (and those who process patient information) can protect patients’ privacy more effectively.
  - A simple example of a provision created by HIPAA is the requirement for a HIPAA release form, which must be signed by patients before any of their protected health information can be disclosed to a third party.
  - The form contains several components, including, but not limited to, a description of the information being disclosed, the purpose of disclosing the information, the entities to whom the information is disclosed, the expiration date/event that causes the patient’s information to be withdrawn, and the signature of the patient. 

- The North American Electric Reliability Corporation (**NERC**) Critical Infrastructure Protection (**CIP**) framework deals with aspects of the Bulk Electrical System (power grid).
  - NERC CIP defines a framework for planning, operating, and protecting the electrical system.
  - Each of the requirements defined in the CIP provides information and direction for compliance, acting as a guidebook.
  - Adherence to these requirements ensures that systems are adequately prepared for issues rather than being caught off guard in the event of an incident. 

## Common Industry Standards
### Intro to Common Industry Standards
- Common industry standards are the foundation for understanding operations for each specific industry.
- These common standards and regulations further provide documentation and unique industry requirements that drive the way cyberspace operations are conducted within those industries.
- Network Analysts need to understand the unique standards and regulations that impact each industry.
- Applying this knowledge can identify areas of focus for protecting industry-specific environments and providing recommendations for mitigation strategies to meet compliance with industry standards and regulations.
- Although many industries possess such standards and regulations, this lesson focuses on four sectors: **military**, **health**, **finance**, and **energy**.

### Military Sector
#### US Code Title 10
- U.S. Code Title 10 outlines the U.S. Armed Forces governing bodies, oversight, and laws.
- U.S. Code Title 10 defines the formation of the Armed Forces and their reserve components and sets forth regulations for how operations are conducted by the branches of the Armed Forces.
- Subsections include the following:
  - A: General Military Law
  - B: Army
  - C: Navy and Marine Corps
  - D: Air Force
  - E: Reserve Components

- Chapter 19, Cyber and Information Operations Matters, is from Subsection A: General Military Law and therefore applies to all military branches.
- It contains the following sections:
  - § 391. Reporting on cyber incidents with respect to networks and information systems of operationally critical contractors and certain other contractors.
  - § 392. Executive agents for cyber test and training ranges.
  - § 393. Reporting on penetrations of networks and information systems of certain contractors.
  - § 394. Authorities concerning military cyber operations.
  - § 395. Notification requirements for sensitive military cyber operations.
  - § 396. Notification requirements for cyber weapons.
  - § 397. Principal Information Operations Advisor.
- Simplified, Chapter 19 outlines cyber incident reporting requirements, penetration and cyber testing requirements, operational requirements, and authorities within cyber and information operations.

- Attachments are provided for two areas of U.S. Code Title 10, Chapter 19, that have the greatest observable impact for Defensive Cyberspace Operations (DCO).
- Briefly review the sections:
  - § 394. Authorities concerning military cyber operations.
  - § 395. Notification requirements for sensitive military cyber operations.

#### U.S. Code Title 50
- U.S. Code Title 50 provides the legal enactment for U.S. national defense and the establishment of the Council of National Defense.
- This document outlines the power enacted to coordinate industries and resources to ensure national security.
- U.S. Code Title 50 includes 58 chapters that outline various industries, war and defense efforts, and other areas that regulate all U.S. operations in regard to war and national defense.

- The original chapter in U.S. Code Title 50 discussing national security was Chapter 15.
- The chapter "National Security" is now Chapter 44 and provides more detail and information than was present in the previous version.
- The chapter provides sections on accessing and use of classified information as well as control of intelligence information.
- Chapter 44 contains the following subchapters:
  - Subchapter I: Coordination for National Security
  - Subchapter II: Miscellaneous Provisions
  - Subchapter III: Accountability for Intelligence Activities
  - Subchapter IV: Protection of Certain National Security Information
  - Subchapter V: Protection of Operational Files
  - Subchapter VI: Access to Classified Information
  - Subchapter VII: Application of Sanctions Laws to Intelligence Activities
  - Subchapter VIII: Education in Support of National Intelligence
  - Subchapter IX: Additional Miscellaneous Provisions
- These sections provide an outline for safeguarding controlled information, which can be implemented and monitored as controls when conducting DCO.

- Two attachments from U.S. Code Title 50, Chapter 44, provide key insights into areas that are the focus of DCO within military environments.
  - Briefly review the sections:
    - Subchapter I: Cyber Threat Intelligence Integration Center
    - Subchapter VI § 3161: Executive Order 10865

#### Military Publications
- Military publications are internal military regulations that further define how operations must be conducted.
- Many publications relating to cyberspace operations exist that affect analysts conducting DCO.
- The following two publications are specific to conducting cyberspace operations.

##### Joint Publication 3-12, Cyberspace Operations (JP 3-12)
- JP 3-12 establishes the responsibilities and relationships assigned to military commands that operate within cyberspace operations.
- US Cyber Command (**USCYBERCOM**) is defined as the entity that controls all military cyberspace operations. All Department of Defense (DoD) components that conduct cyberspace operations are commanded by USCYBERCOM.
- Additionally, USCYBERCOM works in tandem with combatant commands to create mission-oriented tasking for cyberspace units.
- This chain of command is illustrated in the attachment Routine Cyberspace Command and Control.
- JP 3-12 further defines the unique missions relevant to the DoD.
- These missions include Offensive Cyber Operations (OCO), DCO, and DoD Information Networks (DODIN) Operations.
- Joint Publication 3-12, Figure II-1, Cyberspace Operations Missions, Actions, and Forces (attached) shows the shared functions of certain missions and the different operating spaces for each mission:
  - Responsibilities of a Cyber Defense Analyst (CDA) fall directly within the alignment of USCYBERCOM Command and Control (C2) and act within the missions of DCO.
  - Additionally, certain missions include collaborative efforts within OCO missions or DODIN Operations.
- JP 3-12 also outlines the key responsibilities and functions when conducting operations within the defensive cyberspace.
- Briefly review the sections DCO Core Activities and DCO Planning and Coordination (attached) to become acquainted with these responsibilities.

##### (CUI) Cyber Warfare Publication 3-33.4, Cyber Protection Team (CPT) Organization, Functions, and Employment (CWP 3-33.4)
- This article defines key responsibilities and the organizational hierarchy of CPT teams.
- Although no specific requirements from this document exist, the document provides an outline to meet compliance with higher-level standards and regulations.
  - Appendix A: CPT Operations Process (attached) outlines a recommended operations process that applies to commonly accepted practices used across cyberspace operations. 

### Health Sector
- The healthcare industry is highly regulated due to the critical nature of the functions it provides.
- The U.S. government enacted the Health Insurance Portability and Accountability Act (HIPAA) so healthcare workers can maintain patients' health information and provide it to them in a secure and accessible manner.

#### HIPAA
- HIPAA is a federal law that lays the requirements for the protection of sensitive patient records and all electronic communications associated with sensitive patient healthcare information.
- HIPAA comprises five sections:
  - Title I: Healthcare access, portability, and renewability.
  - Title II: Preventing health care fraud and abuse, administrative simplification, medical liability reform.
  - Title III: Tax-related health provisions governing medical savings accounts.
  - Title IV: Application and enforcement of group health insurance requirements.
  - Title V: Revenue offset governing medical savings accounts.
- From the perspective of cyber operations, Title II is the most relevant.
- Title II defines ways in which healthcare information must be protected.
- Among these protections, two established rules directly correlate to DCO: **HIPAA's Privacy Rule** and **Security Rule**.

##### The Privacy Rule
- Officially titled Standards for Privacy of Individually Identifiable Health Information, the Privacy Rule identifies what information is considered protected and the restrictions upon use and disclosure of that information.
- All protected information under this rule is referred to as Protected Health Information (PHI).
  - PHI is considered to be any information that can be used to identify the patient, specifically the following:
    - Any individual's physical or mental health from past, present, or future.
    - Any information about the provisioning of healthcare to an individual.
    - Payment information about past, present, or future healthcare provisioning.
    - Information that establishes reason to believe it could be used to identify the individual (for example, address, name, date of birth).

###### Privacy Rule Exceptions
- The primary principle of the Privacy Rule is that all PHI is not allowed to be used or disclosed.
- Exceptions to this rule are defined and privacy rule protections can be avoided with written authorization from the patient.
- The following is a list of all the reasons defined within this rule that allow PHI to be used or disclosed:
  - Permitted Use and Disclosure.
    - To allow individuals access to their own PHI.
    - Treatment, payment, healthcare operations (at the entity that provides healthcare).
  - Uses and Disclosures with Opportunity to Agree or Object.
    - Facility directories.
    - For notification to identified individuals or entities.
  - Incidental Use and Disclosure (as long as reasonable safeguards are adopted).
  - Public Interest and Benefit Activities.
    - By law.
    - Public health activities.
    - Victims of abuse, neglect, or domestic violence.
    - Judicial and administrative proceedings.
    - Law enforcement purposes.
    - Decedents.
    - Cadaveric organ, eye, or tissue donation.
    - Research.
    - Serious threat to health or safety.
    - Essential government functions.
    - Workers compensation.
- Additionally, the following are reasons an individual can grant authorization to their healthcare information:
  - Psychotherapy Notes
  - Marketing

###### Privacy Rule Use
- The above section defines all the allowed uses of PHI, which primarily include some form of legal requirement, healthcare necessity, or individual agreement.
- Understanding these caveats to the rule is a primary concern for DCO, especially because these are pathways that must be allowed to access the data and need to be monitored closely.
- Although there are many reasons this information can be used, there are also many protections to ensure personal information is not misused or disclosed without permission.
- One protection is minimum necessary use and disclosure.
  - Organizations must adopt policies and procedures that restrict access to PHI and allow it to be used the absolute minimum amount possible for its intended purpose.
  - The minimum necessary protection further expands, stating that all personnel or entities with access to this information are identified and recorded.
  - A CDA monitoring these records needs to ensure this protection is properly enforced, which can be accomplished by comparing access to a known access list.
- Another primary protection from the DCO perspective is data safeguards.
  - The Privacy Rule identifies the requirement that appropriate administrative, technical, and physical safeguards are used to prevent intentional or unintentional use or disclosure of PHI that would violate the Privacy Rule.
  - Although no specifics are mentioned, this means CDAs should ensure safeguards on data are implemented, monitored, and tested to guarantee protection within these environments.

##### The Security Rule
- The Security Rule continues where the Privacy Rule leaves off by adding additional measures for the security of healthcare information.
- Following along with the concept of safeguards mentioned in the Privacy Rule, the Security Rule requires its own data safeguards.
- Specifically, the Security Rule states that it is required to implement appropriate administrative, physical, and technical safeguards to ensure the confidentiality, integrity, and security of electronic PHI.
- Whereas the Privacy Rule enforced protections concerning the use and disclosure of PHI, the Security Rule focuses primarily on the security, confidentiality, and integrity of electronic information.
- Accomplishing the Security Rule relies heavily on the use of technical controls such as encryption, access control, network segregation, and monitoring.
- Among technical controls, there is also the requirement for risk analysis of all entities that create or use PHI.
- Guidance has been developed to help security personnel meet compliance with the stringent requirements for this analysis, but most agencies now depend on tools developed by security agencies.
- The two tools commonly noted are the U.S. Department of Health and Human Services (HHS) Security Risk Assessment Tool and the National Institute of Standards and Technology (NIST) HIPAA Security Rule Toolkit.
- **NOTE**: The NIST HIPAA Security Rule Toolkit is no longer supported but is still commonly noted.
- As an addition to the above requirements, the Security Rule outlines the requirement for notification of security data breaches.
- This rule brings another point of accountability within the healthcare industry.
- It falls upon the cyber enterprise within the organization to gather all the details of the security breach to properly disclose the information to federal agencies.
- These requirements set forth numerous direct technical requirements that must be met, such as encryption, authentication, and incident response procedures.
- Review the Security Standards Matrix (attached) developed by the Centers for Medicare and Medicaid Services (CMS) and shared as an industry standard for evaluating compliance with the HIPAA Security Rule.

### Finance Sector
- The financial industry is another highly regulated industry due to the cataclysmic events that have occurred or could occur without proper law and doctrine forcing strict balances upon the finance industry.
- Many financial regulations have come from legal action taken against entities that have abused the system for financial gain, as pointed out in the Gramm-Leach-Bliley Act (**GLBA**) and Sarbanes-Oxley Act (**SOX**), described below.

#### Gramm-Leach-Bliley Act (GLBA)
- The GLBA is a law that requires financial institutions to outline their security measures for how consumer information is handled and shared while also ensuring measures are incorporated to safeguard sensitive information.
- Data protection requirements are outlined within the GLBA’s Safeguards Rule, which defines organizational requirements necessary to maintain compliance with GLBA.
- The Safeguards Rule is defined in the GLBA's Part 314, Standards for Safeguarding Customer Information.
- The primary takeaway is the requirement to implement an information security program.
- This program must include administrative, technical, and physical safeguards for the access, collection, distribution, processing, protection, storage, usage, transmission, handling, and disposal of customer information.
- Further requirements include the following:
  - Security and confidentiality of customer information.
  - Protection measures for threats to security or integrity of customer information.
  - Protection from unauthorized disclosure of customer information.

#### Sarbanes-Oxley Act (SOX)
- SOX is a law that mandates practices and protections in financial records and reporting requirements for all U.S. public companies.
- The following sections of SOX outline the law's primary cybersecurity requirements that briefly include data integrity requirements, internal security control management, incident disclosure, and reporting requirements.
  - **Section 302**: Requires accuracy, documentation, and submission of all financial reports.
    - Safeguard Control: Data integrity requirements.
  - **Section 404**: Requires reporting of internal controls and the formation of an internal control structure.
    - Safeguard Control: Internal security control management.
  - **Section 409**: Requires the near-real-time disclosure of any financial condition or operations changes.
    - Safeguard Control: Incident disclosure.
  - **Section 802**: Defines penalties for the alteration, concealment, falsification, or destruction of records held by financial institutions.
    - Safeguard Control: Data integrity requirements.
  - **Section 906**: Requires accurate and true financial reports to be submitted by financial institutions, and defines penalties for falsifying or misleading these reports.
    - Safeguard Control: Reporting requirements and data integrity requirements.

### Energy Sector
- Critical infrastructure comprises areas whose assets, systems, and networks are so essential that destroying them would severely damage the country's security or safety.
- The energy sector is one sector within the country's critical infrastructure.
- The critical services in the energy sector house massive networks that need to be used to provide power to citizens throughout the countries that control them.
- Therefore, the energy sector provides a unique service that needs to ensure protection of this vital service.

#### U.S. PDD-63: Cirtical Infrastructure Protection
- To create protections to all critical infrastructure, President Bill Clinton enacted U.S. Presidential Decision Directive 63 (PDD-63) in 1998.
- PDD-63 highlights industries that are considered critical infrastructure and strict outlines of how to protect them.
- The primary takeaways from this directive are the following:
  - Assessing the vulnerabilities of the sector to cyber or physical attacks.
  - Recommending a plan to eliminate significant vulnerabilities.
  - Proposing a system for identifying and preventing attempted major attacks.
  - Developing a plan for alerting, containing, and rebuffing an attack in progress and then, in coordination with the Federal Emergency Management Agency (FEMA) as appropriate, rapidly reconstituting minimum essential capabilities in the aftermath of an attack.

- To meet these requirements for the energy sector, the North American Energy Reliability Corporation (**NERC**) was established.
- **NERC** provides and enforces recommendations for the key protection measurements outlined within CIP for the energy sector.
- Below are the areas where controls are subject to enforcement under CIP:
  - CIP-002-5.1a: Bulk Electric System (BES) Cyber System Categorization
  - CIP-003-8: Security Management Control
  - CIP-004-6: Personnel and Training
  - CIP-005-6: Electronic Security Perimeter
  - CIP-006-6: Physical Security of BES Cyber Systems
  - CIP-007-6: System Security Management
  - CIP-008-6: Incident Reporting and Response Planning
  - CIP-009-6: Recovery Plans for BES Cyber Systems
  - CIP-010-3: Configuration Change Management and Vulnerability Assessments
  - CIP-011-2: Information Protection
  - CIP-013-1: Supply Chain Risk Management
  - CIP-014-2: Physical Security
- Each of the above sections includes numerous security controls that are requirements within the energy sector.
- This is one of the hundreds of controls outlined within the CIP standards.

### Other Standards and Regulations
#### General Data Protection Regulation (GDPR)
- The GDPR is a European Union (EU) regulation that requires the acknowledgment, fair use, and protection of private information collected by organizations.
- This law is specific to the EU but incorporates any entities that may collect the information of people who live within the EU.
- Therefore, the GDPR applies to almost any web-related resource that collects personal data because those within the EU may have access to it.
- This regulation has international implications and should be remembered for any operations that might include members of the EU.

#### U.S. Federal Privacy Act of 1974
- The U.S. Federal Privacy Act of 1974 is a law that establishes the Code of Fair Information Practice, which governs how federal agencies must handle the collection, maintenance, use, and dissemination of personally identifiable information.
- This law defines certain privacy rights for U.S. citizens and forces all federal agencies to be aware of their use of private information of U.S. citizens.
- In cyber operations conducted by federal agencies, this law defines regulations for the use of any data that includes information from private U.S. citizens.

#### Local Organizational Policy
- Local organizational policy and Standard Operating Procedures (SOP) should reinforce and maintain adherence to all industry standards and regulations that apply to the field of work.
- From the team perspective, this changes based on service and unit.
- Not all organizations share common policies.
- Additionally, these policies should strive to make adherence to these standards and regulations easier by creating processes that benefit compliance or reporting requirements with applicable standards and regulations.
- Local organizational policies that impact cyberspace operations typically include, among others, one or more of the following:
  - Incident Response Plan (IRP)
  - Business Continuity Plan/Disaster Recovery Plan (BCP/DRP)
  - Acceptable Use Policy
  - Security Awareness Training
  - Identity Management Policy
  - Change/Configuration Management Policy

#### Special Cases and Programs
- Some systems have unique requirements outside industry standards and regulations.
- The U.S. military has such specialized systems, called programs of record.
- Programs of record have unique requirements that may cause difficulty enforcing certain policies, depending on how the programs are managed.
- Generally, these systems within these programs fall under different restrictions that are laid out by the organization that administers or governs the program of record, and the providers dictate the policies that manage these programs.

### Cyber Threat Intelligence for Commmon Industries
- All industries possess unique cyber threats that should be acknowledged when working within those environments.
- Before delving into some real-world examples, it helps to understand the primary concerns of each industry.
- Although all industries consider each portion of the Confidentiality, Integrity, and Availability (CIA) triad to be important, mission-specific functions can cause certain functions to be prioritized.
- The priorities of each industry discussed in this lesson are as follows:
  - **Military**: Confidentiality and integrity of controlled information.
  - **Finance**: Confidentiality and integrity of banking and payment card information.
  - **Health**: Confidentiality and integrity of patient records and communications as well as intellectual property.
  - **Energy**: Integrity and availability of infrastructure assets.
- **NOTE**: The standards and regulations that control military, finance, and healthcare industries focus primarily on the confidentiality and integrity of controlled information, financial records, and patient records, respectively.
  - However, the mission of the military, finance, and health sectors prioritize availability to ensure full capability to conduct their operations.
  - Additionally, the energy sector incorporates layers of confidentiality for industry secrets and intellectual property, but confidentiality is not a focus of its regulations.
- Many threats exist throughout these industries, such as malicious insiders, nation-state threat actors, and script kiddies.
- The following provides a brief discussion of specific concerns impacting each industry, along with real-world examples and common threat-mitigation strategies.

#### Military Concerns
- Many nation-state threat actors and private hacker groups, among others, continue to aim to perform malicious activities against military organizations.
- These actors primarily aim to extract classified information but may also hope to disrupt, destroy, or defame the military organizations they threaten.
- One real-world example is Advanced Persistent Threat (APT) 2, also known as the UPS Team, a suspected Chinese group that specializes in intellectual property theft of military and defense organizations.
- Common threat mitigation strategies for military threats include the following:
  - Segregated networks for controlled information (e.g., physically separated networks from common internet).
  - Stringent access control and identity management (e.g., using common access cards/tokens).
  - High-level encryption through specialized cryptographic equipment (e.g., National Security Agency [NSA]–level encryption through devices like KG-252).

#### Finance Concerns
- Nation-state threat actors, as well as individual hackers and private hacking groups, seek to attack the financial industry to conduct cyber heists (electronically stealing money) or to collect and sell private financial information of individuals and organizations.
- A real-world example is APT 38, a suspected North Korean group with a primary focus on cyber heists conducted against global financial institutions.
- Common threat mitigation strategies for finance threats include the following:
  - Strong boundary device security architecture (e.g., proxy servers, Demilitarized Zones [DMZ], firewalls, secure edge routers).
  - Multi-factor authentication scheme (e.g., password with one-time pad or biometrics).
  - Secure communications (e.g., encryption from external connections, internal communications that contain private information, private financial records at rest).

#### Health Concerns
- Nation-state threat actors, private hacking groups, and individual hackers attempt to exfiltrate intellectual property of healthcare developments.
- They may also attempt to damage or disparage organizations by exposing (or threatening to expose) sensitive patient information or through ransomware attacks meant to extort the company for financial gain.
- A real-world example is APT 24, also known as PittyTiger, a suspected Chinese group that focuses on data theft of many common private industries, including healthcare. Common threat mitigation strategies for health threats include the following:
  - Minimized authorized access to information (e.g., strict group policies, least privileges for users, access control lists).
  - Strong security controls on systems that hold or use PHI (e.g., host-based security systems, firewalls, Intrusion Prevention Systems [IPS]).
  - Data security controls (e.g., encryption on all PHI data at rest as well as all communications that contain PHI).

#### Energy Concerns
- Primarily nation-state threat actors, but also such groups as hacktivists, perform actions to defame, disrupt, or destroy energy infrastructure environments, resulting in damage to organizations and national security.
- Additionally, nation-state threat actors may try to exfiltrate intellectual data for their home states.
- A real-world example is APT 34, a suspected Iranian group that focuses on reconnaissance activities associated with long-term cyber espionage, with a primary focus on energy and defense.
- Common threat mitigation strategies for energy threats include the following:
  - Strict network segregation with minimum necessary access to Operational Technology (OT) network (e.g., one-way communications from OT to Information Technology [IT] network).
  - Strong security architecture controlling OT network communications (e.g., firewall and segregated network Virtual Local Area Network [VLAN] communications for internal networks).
  - 24/7 monitoring and alerting for anomalous activity (e.g., Security Information and Event Management [SIEM] or IPS systems).

### Assessing Industry-Standard Network Traffic
- Industry standards and regulations may be further explained through evaluation of industry-specific network traffic.
- Review the four attached network topology examples for the military, health, finance, and energy industries.

#### Military Network Topology
- The military network topology example provided is for a secret classified network, requiring encryption on all communications.
- A crypto device is used to incorporate cryptographic keys from the NSA to encrypt communications leaving the network.
- Tactical systems are isolated and behind their own firewall to ensure the devices have increased security and are less accessible.
- Program-of-record systems are isolated in the same way and may require their own firewall.
- Data storage solutions and servers are shared but require additional security controls to restrict to minimum access.
- Various work groups are divided by subnets to ensure traffic is secure and separate.
- CDAs ensure the security controls are functioning and monitor to verify that only authorized accesses are occurring throughout the network.
- This ensures compliance with the standards and regulations set forth for the military sector.

#### Health Network Topology
- The healthcare network topology example is for a small healthcare facility network.
- There is a separation of the switch that houses the guest, reception, and security camera subnets and the switch that houses the healthcare-specific subnets.
- This is a required separation of the common services from the health subnet to ensure the privacy and security of health records and electronic communications.
- In fact, the firewall is in place to prevent any unauthorized communications to the devices behind it.
- The firewall and DMZ on the initial network provide a layer of security over the network from external attacks.
- This is a huge concern with healthcare networks because penetration from outside entities can result in massive penalties.

#### Finance Network Topology
- The finance network topology example is for a network from a singular branch of a bank.
- Initial firewalls exist between the forward servers.
- Forward servers are primarily such items as proxy and web servers for base web pages not related to e-banking.
- The two firewalls divide the networks.
- The first firewall secures the forward servers, and the second firewall ensures the banking network is secure.
- The primary operations of the bank are divided, ensuring secure and separate traffic.
- These operations include tellers, loans, auditing/Human Resources, and management and also include the typical printer and external connection to other branches.
- Within the loan network, there are many additional securities around the loan server repository, which houses private financial information of loan applicants.
- The e-banking solution and core processing server cluster represents another set of primary concerns.
- These two areas house much of the essential data and processing of all customer financial information.
- The security controls for these areas are heavily mandated by financial standards and regulations.
- However, there is also the need to allow customers access to the e-banking network.
- This means the e-banking network is heavily used but must be monitored with the utmost care.

#### Energy Network Topology
- The energy network topology example is for a power plant network based on the Purdue model.
- The Purdue model is a representative model of an OT network and is used to represent the application of commonly accepted industry practices.
- The mission of the energy network model is the availability of its service to the electrical network.
- Segregation of this mission network must be the primary security focus when dealing with the energy sector and shows how availability is the primary concern in this sector.
- The division between the IT network and the OT network is apparent in this topology.
- The OT network is the mission of the energy sector and is the network that needs to continually provide connectivity to the power network to distribute power.
- However, energy companies in this example also need to have an IT network for operations and to house their online presence.
- As many securities as possible should be in place to ensure no unauthorized access to the OT network from the IT network or internet beyond.
- Typically, this is done through one-way connections using a tool like a digital diode.
- In this example, however, it is done through a firewall that houses routes from the switches using inter-VLAN routing.
- The devices are secured and separated through this technique, and the firewall most likely denies all traffic attempting to communicate back toward the OT network unless explicitly allowed.

## Documentation Process
### Overview
- CPT members' duties include many reporting requirements.
- These reporting requirements may be mandated by the Department of Defense (DoD), CPT teams, and mission partners.
- Although the timing of exact requirements differs from team to team and mission to mission, there are commonalities in the types of data required to be reported on.

#### Common Mission Documentation Requirements
- (CUI) Per Cyber Warfare Publication 3-33.4, Cyber Protection Team (CPT) Organization, Functions, and Employment:
  - (CUI) “All vulnerabilities identified during threat mitigation are documented in the risk mitigation plan, and include recommendations for internal and external mitigation actions to reduce the overall risk to secured networks.”
  - (CUI) “[...] CPT receipt and analysis of the supported organization’s network diagrams, terrain information, and configuration documents [...] If these documents do not exist, basic network maps and terrain information will be gathered in conjunction with the mission partner [...]”
  - (CUI) In addition to being able to reconstruct timelines, CPT members must also document derived information, such as identified vulnerabilities, identified adversarial tactics, techniques, and procedures (TTPs).
    - Additionally, if documentation required to execute a mission, such as network maps, inventory lists, etc. do not exist, CPT members may be required to work with mission partners to generate this documentation.

- Actions must be logged during the execution of some mission tasks.
- The granularity of each log entry can be tricky, but if the activity can potentially impact the team or mission partner in any way, it should be logged in detail.
- However, in some cases where there is minimal risk, the nature of that logging may not need to be exceptionally verbose.
- Take the task of changing a router configuration as an example: depending on the level of risk, logging this activity could just include the requirements for the configuration change, any required approvals, the time the administrator executed the router change, and before and after router configuration files (in case the router needs to be rolled back).
- Non-standard configurations or otherwise out-of-the-ordinary actions or observations should be specifically called out.
- Notable observations, such as identified Tactics, Techniques, and Procedures (TTP), found Indicators of Compromise (IOC), vulnerabilities, and similar observations, must likewise be documented.
- These observations should be recorded in the working log for the mission or in a separate observations log.
- The logged entries are used to create various reports and outputs, such as risk mitigation plans or vulnerability reports.
- In addition to documents for logging each action taken, documents such as network maps, inventory lists, and device configurations may be generated to support missions.
- These documents, often crucial to the execution of a mission, are a mixture of reporting output and documentation and should be preserved in accordance with team and mission partner requirements.
- Any additional documents generated during the course of a mission generally needs to be attached to, or referenced in, the working log for the mission.

### Documentation Standards
#### Overview
- The following output standards illustrate the importance of selecting the correct information to be documented.
- These standards also demonstrate the utility of documentation by showing various outputs.
- Two types of output are demonstrated, including the relatively new Cyber 9-Lines format and an open-source format known as Structured Threat Information eXpression (STIX™).

#### Cyber 9-Lines
- The Cyber 9-Lines format is provided for illustration only and may not represent a format that is used by any particular team in the field.
- The Army National Guard uses the format at time of writing to provide initial reports to US Cyber Command (USCYBERCOM).
- Efforts to ramp up training of this format preceded the 2020 elections to help ensure their security.
  ![4d4c0392-1d08-438f-aaf6-2e28b8a79697](https://github.com/user-attachments/assets/efd992fd-7781-4c6a-89a1-bae83d7dccfe)

- As seen in Figure 2.3-1, the Cyber 9-Lines format gathers intelligence into an easily consumable format for USCYBERCOM.
- Although some of this information comes from higher up the chain than analyst roles, this format is useful to demonstrate how documentation during a mission feeds into intelligence and reporting up to USCYBERCOM.

- Breakdown of each of the nine lines, as well as a description of each line and how it relates to field-gathered information, is as follows:
  - **Incident Date/Time**: This is driven by processing early intelligence and documentation of Malicious Threat Actor (MTA) actions.
  - **Classification (DoD and TLP)**: This is driven by classification requirements that are outside the scope of this lesson.
  - **CI/KR Sector**: Per previous lessons, this refers to critical sectors and infrastructure across various industries.
  - **State of Origin (optional)**: If identifiable, this may be hard to discern, especially early in a mission, and is optional for good reason.
    - Examples of sources of this include determining likely Advanced Persistent Threats (**APT**) involved, **traffic origin**, and **deconstruction of malicious payloads**.
  - **State Severity Rating**: This reflects the expected impact of this incident, based upon several factors, such as impact to business and critical infrastructure. As such, this is a fairly derived value.
  - **Narrative**: This is a description of the event, as perceived by the team generating this report, which requires documentation and reporting, such as timeline reconstruction of MTA actions and TTP mapping.
  - **Request for Support/Escalation**: This is determined by leadership and/or mission partner needs.
  - **Associated Reporting**: This is derived directly from documentation and generated documents. Documentation generated during a mission is the primary source of information here.
  - **IOCs**: These are derived from findings by analysts and directly driven by documentation generated during missions.

#### STIX Reports
- This section covers small portions of the STIX 2.1 format, another example of documentation output.
- The STIX Frequently Asked Questions (FAQ) web page describes STIX as follows:
  - "STIX — the Structured Threat Information eXpression — is a language and serialization format used to exchange cyber threat intelligence (CTI).
  - STIX enables organizations to share CTI with one another in a consistent and machine-readable manner, allowing security communities to better understand what computer-based attacks they are likely to see and to better prepare for and/or respond to those attacks faster and more effectively.
  - STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more."

### Key Information
#### Overview
- Filtering through available information and triaging important data are crucial to the execution of missions.
- Some key areas of information, such as **network assets**, **intelligence sources**, **TTPs**, and **timeline reconstruction** represent **critical pieces of information** that need to be documented whenever that information is available.

#### Network Assets
- Network assets, or inventories of all devices connected to mission partner networks, may require documentation.
- Although initial documentation is typically received early during a mission's lifecycle, such assets may require further enrichment or validation during the execution of a mission.

#### Intelligence Sources
- Any intelligence sources used to generate hunt hypotheses during the execution of a mission should be documented.
- In addition, any derived information from these sources, such as discovered IOCs, must be documented.
- Various agencies may use newly documented IOCs to create new or updated intelligence reports.

#### TTPs
- During the course of a hunt, describing MTA actions may require mapping TTPs.
- These must be documented as pieces of derived information directly relating to reconstructing the timeline of MTA actions.
- In addition, these TTPs may be used to help generate more documentation that feeds into risk mitigation plans, as they are a helpful starting point for research.

#### Timeline Reconstruction
- Each CPT member must be able to describe a timeline of actions taken during a mission.
- The ability to reconstruct tasks executed can help accurately portray the CPT member's activities and be used during After-Action Reports (AAR), also known as post-mortem reports, or analysis to help improve the abilities of CPT teams.

## Reporting
### Reporting Chain
- CPTs must have a high degree of technical understanding in order to find anomalies and potentially Malicious Cyber Activity (MCA) within a network.
- It is very likely the leadership does not have an in-depth understanding or working knowledge, which requires changes in reporting details.
- Upon receiving orders for a mission, the team leadership obtains guidance on the reporting requirements for the specific mission, which should include the audience, periodicity, and intended format.
- As a basic rule, as reporting moves higher up the chain of command, the detail decreases because the amount of time for ingestion and understanding is limited.
- Reporting is tasked from higher headquarters and must be returned through those same chains.
- The flow of tasking from leadership is diagrammed in Figure 2.4-1, which can be used to assess the return path.
  ![cb31f577-707a-4abc-99f9-4df774982729](https://github.com/user-attachments/assets/beec0c86-9d5a-4c67-892d-41d97f0951a7)

### Report Overview
- Throughout a mission, many different types of reports are required from leadership.
- It is vital to document every action as thoroughly as possible during research and event analysis in order to make report creation as smooth as possible.
- Remembering the specific details surrounding an event, the requested changes, or the Requests for Information (RFI) is very difficult days or even weeks after the analysis.
- Incidents from a mission are even more difficult during mission wrap-up or after returning to home stations.
- High-traffic networks often only have enough storage for a certain number of days' worth of logs, which can hamper further research on an incident.
- Cyber Warfare Publication (CWP) 3-33.4 states:
  - _"[US Cyber Command] USCYBERCOM and [Joint Force Headquarters – Department of Defense Information Network] JFHQ-DODIN will maintain situational awareness of all DODIN cyberspace defense actions. CPTs should report defensive cyberspace actions through their [operational control] OPCON chain of command, and organizations delegated [tactical control] TACON of CPTs should in turn report CPT status and defensive cyberspace actions taken to USCYBERCOM, JFHQ-DODIN, and the network-owning commander or director."_

- Reporting types vary based on mission type, but CWP 3-33.4 dictates all reporting should include the following (as applicable):
  - Root cause of the issue.
  - Indicators of Compromise (IOC).
  - Malware observed, identified, or discovered.
  - Detection techniques.
  - Actions taken.
  - Impact to supported mission.
- The following reports have been categorized into Internal and Intelligence and Collaborative to help highlight the similarities. 

#### Internal Reports
- Internal reports are generally used within the mission element — or team — or to provide an update to a chain of command for the task at hand.
- These reports have varying amounts of details associated with them, which is directly linked to the understanding of the intended audience.
  ![63cc2cb6-dde4-43e9-bda5-a346541e7acf](https://github.com/user-attachments/assets/5b62f4c0-7ee7-43f1-bec4-28191ec9abc1)

##### Shift Changeover
- The normal shift changeover procedures are usually in the form of a meeting or a document.
- These changeovers are a way to pass information from one shift to another.
- The meeting or document may not be detailed, but there should be a link to all the analyst's notes for the oncoming shift.
- Details are immensely important here to minimize the amount of time the ongoing shift needs to use to get spun up on the event.
- These may not be considered official reports, but they highlight the need for very detailed notes.
- **Example**: _Continue investigation of User Datagram Protocol (UDP) traffic destined for 104.53.222[.]95 port 34323 from multiple hosts within the network 172.16.4.0/24 subnet. Notes are under the 10152021-anom-udp-outbound directory on the team share. The notes contain what prompted the investigation, timestamps of connections, snippets of payloads, and as much information as possible for follow-up research. It is possible that logs rotate or turnover and data could be lost if not fully documented._

##### Daily Situation Reports
- Daily Situation Reports (**SITREP**) are end-of-day reports that leads send up the chain on current mission status.
- These reports may be informal from the analyst's point of view but should give a high level of what is being worked on.
- **Example**: _Investigating high-bandwidth UDP traffic from security subnet destined for 104.53.222[.]95._
  - **NOTE**: This level of report often gives a generalized summary of what is being investigated but may not give any specifics. This report is for leadership that does not have time to read notes on an investigation (unless they ask, of course).

##### Weekly Activity Reports
- Weekly Activity Reports (**WAR**) include the previous week's accomplishments.
- These reports are often requested from leadership to help keep them apprised of the team's progress and ongoing actions.
- These reports are often at a high level similar to SITREPs but combine linked events across the team.
- **Example**: _Three shifts researched anomalous UDP traffic destined for a North American Internet Protocol (IP) address from multiple IP cameras throughout the security subnets. The IP address is associated with the Consolidated Operations and Utilization Plan (COUP) site, which had not been listed on the network diagram. The mission partner is aware of the traffic but thought it was within an IP Security (IPsec) tunnel. The team provided further guidance about properly securing traffic leaving the network._
  - **NOTE**: This update is important because multiple shift personnel spent a lot of time on it and found an underlying security issue for the mission partner. If the traffic was within an IPsec tunnel, the information is important enough to discuss adding to the WAR.

##### Lessons Learned and After Action Reports
- Lessons learned and After Action Reports (AAR) allow recent events, investigations, troubleshooting, etc. to feed back into internal processes and methodologies.
- Finding a new way to complete an action that saves time is a great addition to the processes employed by the team.
- These lessons learned do not have to be specific to a mission.
- They could be as simple as a new website that provides information about IP addresses on the internet.
- **Example 1**: _The camera UDP traffic was investigated for three shifts before coordinating with the mission partner. The lesson learned would be to reach out to the mission partner with indications of large outbound unencrypted traffic before the end of a shift or follow-on shift._
- **Example 2**: _UDP traffic with a prefix of 0x7100e0000100f800 followed by 10 digits is likely a camera stream from an IP camera designed by Imaging Development Systems._

#### Intelligence and Collaboration Report
- The following reports are used for collaboration and for requesting support from other agencies or higher headquarters.
- These reports have varying amounts of detail that are defined within each section.
- These reports may be authored by the intelligence members in the support cell or by the mission partner.
- As a CPT member, there may be no requirement to create these reports, but there are many occasions where the input from CPT members is the primary source for reporting.

##### USCYBERCOM Cyber 9-Line
- USCYBERCOM's Cyber 9-Line is a template of nine questions that helps communicate cyber incidents to USCYBERCOM.
- Even if the incident is not reported to USCYBERCOM, the questions are excellent for conveying high-level details.
  - Incident date/time
  - Classification
  - Critical Infrastructure and Key Resources (CI/KR) sector
  - State of origin
  - State severity rating
  - Narrative
  - Request for support/escalation
  - Associated reporting
  - IOCs
- **Example**: _A real-world example of a Cyber 9-Line in use occurred in June 2020 when the Dorchester County government in Maryland was hit by a ransomware attack. Dorchester County reported the incident to USCYBERCOM via a Cyber 9-Line in order to request support. Within 48 hours, the Maryland Air National Guard arrived at county offices ready to assist. The data within the report also provided USCYBERCOM's Cyber National Mission Force (CNMF) with the necessary information to diagnose and assist where appropriate._

##### Joint Incident Management System Records
- Joint Incident Management System (**JIMS**) records are defined in **Chairman of the Joint Chief of Staff Manual (CJCSM) 6510.01B** as _"a timely technical summary of an event supplemented with intelligence analysis that is entered into the JIMS."_
- Technical specificity in initial JIMS reports is vital to establishing and ruling out correlations between events during follow-on analysis.
- Mission element members may not directly create JIMS records, but supporting intel analysts or mission partners may require input. 
  - **Example**: _A report about an IP address from Malaysia continuously scanning internet-accessible IP addresses on the network. Intel sources have seen the IP address associated with various cyber attacks over the past three months. The report contains specific times, protocols, ports, IP addresses, and application layer information about connections after the scanning (like User Agent Strings when scanning web servers), which could help develop IOCs._

##### Network Intelligence Report
- A Network Intelligence Report (NIR) is an all-source intelligence report focused on an activity or event — a composition of JIMS records — reporting on a person or organization.
- As with JIMS, these may not be directly created by the element or team, but supporting intelligence analysts may need input provided from team members on the ground.
- When authoring NIRs, an analyst may request additional information associated with a JIMS — the detail associated with these reports is less specific to a single event but more specific to the linking of multiple events.
  - **Example**: _A report discussing Advanced Persistent Threat (APT) 29 traffic from a specific mission partner. These incidents are a combination of multiple JIMS records, which may or may not be within a mission execution or across multiple months._ 

##### Strategic Intelligence Report
- Strategic Intelligence Reports (SIR) are similar to NIRs but developed from a broader point of view. As noted in the CJCSM 6510.01B, these reports should attempt to capture the full military and/or political significance of network activity.
- SIRs are normally generated in response to intelligence consumer production requirements based on organization production priorities and focus.
- They likely cover multiple JIMS records and NIRs.
- Again, these reports generally do not need additional details, but it is good to have an understanding of where an event found by a CPT may be referenced in the broader picture of the intelligence community.
  - **Example**: _A report discussing recent cyber attacks across the Central Command Area of Responsibility (AOR). The report speaks at a high level about documented cyber attacks, which may include events like spear-phishing, attacks by APTs, and other cyber events._

##### Joint Malware Catalog
- In the event malware is found or suspected within a mission partner network, it is important to research the Joint Malware Catalog (JMC) for other instances of the malware across the DoD.
- The repository provides malware that can be viewed, analyzed, correlated, and further shared with DoD organizations.
  - **NOTE**: _The JMC is currently under active development under USCYBERCOM's purview._

![1e786762-5837-4f08-b0e9-ec235788eb0a](https://github.com/user-attachments/assets/db23c8f1-3e05-486a-9d70-147c6eb85cc2)

#### Report Routing
- Automated messaging systems allow entities across dispersed areas and systems to have a centralized reporting mechanism.
- The following are a few of the larger systems within DoD.
  - Automated Message Handling System (**AMHS**) is used across the DoD and external agencies to route messages.
    - This capability is **available on** Joint Worldwide Intelligence Communication System (**JWICS**) and Secure Internet Protocol Router (**SIPR**) networks.
    - **AMHS** provides a way to **route messages securely between users** with a rapid search and retrieval capability.
    - **AMHS** messages can be in **free form and cover endless subjects** to include all **NIRs** and **strategic-level reports** created during a mission.
  - **JIMS** is the mandated (**CJCSM 6510.01B**) **incident-handling program** for all **USCYBERCOM** and **Tier 2** Computer Network Defense Service Providers (**CNDSP**).
    - JIMS must be used to report all Information Assurance/Computer Network Defense (IA/CND) incidents across the DoD.
    - The system is **only accessible on SIPRNet**.
    - **JIMS** provides users with the ability to **create**, **edit**, **search**, **move**, **assign**, **link**, **comment**, **add/delete attachments**, **subscribe**, and **close tickets**.
    - The search capability is **helpful in finding actionable information** from **completed** or **ongoing missions**.

### Final Reporting
- During a mission, a litany of reports and documentation is completed, but the final summation of a mission execution often requires a Risk Mitigation Plan (RMP).
- The RMP provides the mission partner with documentation on what was found during the mission execution as well as any guidance to help further secure the network.
- The RMP is broken down into the following structure:
  - Introduction
    - Mission Description
    - System Description
    - Mission Relevant Terrain (MRT)
  - Mission Survey Results
    - Threat Assessment
    - Events/Anomalies
    - Risk Mitigations
      - Top 3
  - Defensive Assessment
  - Risk Determination
  - Vulnerability Assessment Summary
  - Overall Recommendations
  - Conclusion
- The RMP should highlight the most important events and findings, which is where the analyst comes in.
- The leads combine inputs from the analysts to create the report, but analysts must be cognizant that their input is prioritized.
- All events, anomalies, findings, and corrective actions are part of the report, but only the most important are summed up in the main verbiage of the report at a higher level.
- Higher-fidelity information on the most important events, anomalies, findings, and corrective actions are documented within the appendices.
- All less important items should also be documented within the appendices in order to provide a full picture of the mission. 

### Prioritizing Events, Anomalies, Findings, and Corrective Actions
#### Mission Background
- The team was requested to provide security analysis and RMP for an air-gapped development network in order to receive certification for sensitive development work.
- The mission partner has a network with a VMware ESXi deployment that hosts multiple Virtual Machines (VM) to administer the network as well as monitor for external linkages.
  - The VMs include Security Onion for Network Intrusion Detection Systems (NIDS), Windows Server for Active Directory (AD) services, Rocket Chat for internal messaging, and GitLab for a code repository.
  - VMs for Windows XP, 7, 10, and 11 are available for code testing.Security also authorized a Kali VM for testing and development.
- The users' workstations are all Windows 10 systems that are fully patched monthly via a Digital Video Disk-Recordable (DVD-R) update process.
- The DVD-R update process uses Windows Server Update Services (WSUS) Offline Update tool to download the most recent updates and write them to a DVD or multiple DVDs, as needed.
- The air-gapped network is physically disconnected from any other network, and all Bluetooth and Wireless Fidelity (Wi-Fi) adapters are disabled/removed.

#### Mission Time Frame Events and Anomalies
- While using the on-premises NIDS, analysts noted the traffic was minimal.
- Because the Security Onion sensors were misconfigured, there are no historical logs for a baseline.
- Patches on the ESXi VMs are a gradient from completely unpatched to fully patched for unit testing.
- Windows 10 hosts were utilizing Server Message Block version 1 (SMBv1) for backward compatibility to the Windows XP hosts for testing.
- Microsoft strongly recommends disabling SMBv1 because of known vulnerabilities.
- Traffic during the mission time frame showed users:
  - Connecting with VMs using vSphere web client over Hypertext Transfer Protocol Secure (HTTPS).
  - Transferring files over SMBv1 using ad hoc file shares — workstations sharing folders with other workstations.
  - Connecting with GitLab for code pushes/pulls using HTTPS.
  - Connecting with the Domain Controller (DC) for user authentication.
  - Using separate laptops with a Wi-Fi hotspot for internet research — outside the scope of the mission.
- Universal Serial Bus (USB) adapters are often used for development and testing with Internet of Things (IoT) devices.

#### Findings and Corrective Actions
- After further review, the analysts working with the mission partner realized the sensor was connected to a normal port on the switch using a physical Network Interface Card (NIC).
  - The mirror interface had inadvertently been configured on the wrong interface.
- Host Analysts noticed a few USB drives around the office, which spawned a check to see if the Windows event logging was configured to log USB devices.
  - Logging had not been enabled, and the analyst worked with the mission partner to create a Group Policy Object (GPO) to apply to the entire domain
  - Develop a baseline for the network.
- When prioritizing Events and Anomalies, it is important to properly calculate impact.
  - CJCSM 6510.01B says to "consider the current and potential impact of the incident or event on the confidentiality, availability, and integrity of the organizational operations, organizational assets, or individuals."
  - Confidentiality, integrity, and availability are often referred to as the CIA triad (or AIC triad in order to avoid confusion with the Central Intelligence Agency).
    - Confidentiality is a measure of how damaging the loss of data is.
      - Example: Username and password of a bank account are highly confidential.
    - Integrity refers to the consistency or trustworthiness of the data.
      - Example: It is highly important that the data presented to bank customers matches their accounts. If they lack trust, customers may close accounts and tell their friends.
    - Availability refers to the accessibility of data when it is necessary.
      - Example: If a bank account is not accessible for some reason, availability suffers and customers leave.

#### Prioritize
- The highest-priority corrective action has already been completed but should be noted in reporting.
- Finding the NIDS was improperly configured is a two-fold issue.
- The first issue is that it was not tested after implementation in order to confirm adequate visibility.
- The second — and likely more important issue — is the amount of time the NIDS was online and not attracting attention because an analyst should have noticed the error very quickly.
- A **NIDS** is a window into the network that provides insight into the entire CIA triad.
- Having vulnerable Windows XP hosts and utilizing SMBv1 on Windows 10 hosts for compatibility is a risk, but the mission partner has deemed that risk acceptable since the network is completely air gapped and the SMBv1 is needed for communication testing.
- The lack of USB device logging is paramount in this network because USB devices could be used to take data in and out of the network or introduce malware, which causes concern for the confidentiality of the data within the network.
- The mission partner has worked tirelessly to acquire well-vetted employees to increase the integrity level and decrease the possible loss of availability based on a worm.
- This network's priorities are very specific — any two networks typically have different priorities.
- It is important to look at the whole picture and make sure the priorities match with the specific mission partner's needs.
- There may be priorities required by higher headquarters that need adherence by the mission partners, so it is important to research the requirements prior to the mission execution, if at all possible.

### Prioritizing Mitigation Plans
- For each finding found during mission execution, there should be an RMP developed for the mission partner.
- Working with the mission partner to develop RMPs is a great option, which enhances the working relationship with the mission partner and the CPT.
- During the final report, it is important to prioritize based on the assessed risk.
- Risk is based on two factors: likelihood and impact.
  - Likelihood relates to the adversary's perceived capability (knowledge, tools, infrastructure, etc.) to exploit a vulnerability.
  - Impact deals with the issues that may arise from a successful exploitation.

- Look back at the development network in the previous task.
- While the SMBv1 vulnerability is common knowledge and the tools are open source, there is not a direct connection to the network from the outside, which breaks the accessibility/infrastructure portion of likelihood.
- The impact is still high because an SMBv1 exploit within this network would give access to just about everything as the users are sharing files ad hoc.
- The impact for this vulnerability is high but the opportunity is low, which makes the likelihood low.
- Because of the ease of exploitation of this vulnerability and the impact, this vulnerability may still be medium or high; however, the mitigation strategy cannot be to patch the systems because of the mission requirements.
- The best option, in this case, would be to work with the mission partner to find a way to minimize the impact of a potential exploitation, which could entail moving shared files from workstations to a file server that does not support SMBv1 and minimizing the use of SMBv1 wherever possible. 

### Concept Sketch
- Producing an image to depict a chain of events can be much more impactful than a written report.
- A concept sketch can also provide an excellent way to show a linear progression of events if a timeline is required. 
- In the Traffic Analysis lesson, an attack originated from a USB thumb drive being plugged into the system.
  - The user, Janine Ross, inserted the USB removable media, navigated to the drive, and opened invoice.docx.exe.
  - The executable opened a reverse shell to the attacker's machine 103.28.93.102 on port 80.
  - Janine's workstation bp-wkstn-3 began sending TCP Synchronize (SYN) packets to ports 80, 443, 445, 139, 22, and 21 on the entire 172.16.2.0/24 subnet.
  - Janine's host connected to 445 with SMB tree connect requests for the IPC$ share, but none of the connections were successful.

- Adding a timeline can also help relay the information much easier.
- Tools like draw.io or Microsoft Visio are often used to accurately depict an incident, but something as simple as a whiteboard may be sufficient in a pinch.
- Whiteboards are a great option for quick meetings like SITREPs, shift changeovers, or AARs, where a quick illustration is needed to convey an idea.
  ![5de152ac-6d38-44e1-8df8-d2125dbbeeec](https://github.com/user-attachments/assets/709a6a26-e6d9-45e6-9e9c-6a8208a9d1ed)


# MOD 3
## Key Terrain in Cyberspace (KT-C)
### Cyberspace
#### Overview
- Referred to as Intelligence Preparation of the Operational Environment (IPOE), any military operation requires an analysis of the enemy's capabilities and possible courses of action, which, in turn, includes a detailed analysis of key terrain — physical locations that can be easily pointed to on a map that may provide an advantage to an adversary.
- Identifying key terrain provides valuable information on where to focus efforts to defend or attack a physical location.
- Cyberspace is defined as a _"global domain within the information environment consisting of the interdependent network of Information Technology (IT) infrastructures, including the Internet, telecommunications networks, computer systems, and embedded processors and controllers,"_ per Joint Publication 3-12, Cyberspace Operations.
- Cyber terrain is not always directly in relation to a physical location.
  - Instead, cyber terrain may include logical mediums such as software, OSs, network protocols, virtual personas, and other computing devices.
- A KT-C is considered a physical node or data that is essential for mission accomplishment.
- Adversaries may attempt to exploit, compromise, damage, or destroy various elements of KT-C.
- KT-C falls into three tiered categories based on levels of impact to the OE, described later in this lesson.
- If an adversary inflicted damage to a particular area of the network or a particular infrastructure component, the consequences of the damage to the mission execution that the KT-C enables or supports would be dependent upon the function of the network area or component.
- Terrain, which covers all of cyberspace, includes the logical and physical components.
- When defining terrain, DCO team members should use KT-C, Mission Relevant Terrain in Cyberspace (MRT-C), Task Critical Asset (TCA), and Defense Critical Asset (DCA), as outlined in USCYBERCOM Operational Guidance, Identification of Mission Relevant Terrain in Cyberspace.  
  - **KT-C** is any locality or area — physical or logical — where seizure, retention, or other specified degree of control provides a marked advantage in cyberspace to any combatant.
  - **MRT-C** is described as (but is not limited to) all devices, internal/external links, OSs, services, applications, ports, protocols, hardware, and software on servers required to enable the function of a critical asset.
  - **TCA** is an asset that is of such extraordinary importance that its incapacitation or destruction would have a serious, debilitating effect on the ability of one or more Department of Defense (DoD) or Office of the Secretary of Defense (OSD) components to execute the capability or mission-essential task it supports. TCAs are used to identify DCAs.
  - **DCA** is an asset of such extraordinary importance to operations in peace, crisis, and war that its incapacitation or destruction would have a serious, debilitating effect on the ability of the DoD to fulfill its missions.  

- Identifying terrain has a direct impact on a CPT’s mission.
- Once the CPT has an assigned terrain in which to hunt and operate, the threat hunter can filter data based on the types of systems and datasets available.
- Data requirements are driven by the analysis of potential threat actors that can target the mission partners' networks and the Tactics, Techniques, and Procedures (TTP) they employ.
- Identifying terrain, in turn, reduces the number of analytics necessary for the team to execute the mission objectives.
- The threat hunter can also filter for data on the identified MRT-C and KT-C to prioritize the required data collection.
- Understanding KT-C provides a distinct advantage over the adversary by allowing the analyst to focus on defenses for the network.
- For example, a Network Analyst knowledgeable of KT-C would be able to foil an adversary from further penetrating the vulnerable network by providing mitigating controls for identified weak security postures resulting from identified vulnerabilities supporting KT-C.
- CPTs are continually required to adjust and adapt to new adversaries or TTPs as KT-C constantly remains at risk. 

### Tactical and Operational KT-C
- Identifying tactical KT-C provides CPTs, whether assessing or defending a network, a physical location to focus their efforts.
- In reference to tactical KT-C, this is relevant to physical links that allow communications at the local level, firewalls that control incoming and outgoing traffic, or local administrative privileges that can be leveraged to compromise a vulnerable network.
- Knowledge of operational KT-C could provide advantages to an adversary within a specific campaign or operation.
- An Operational Environment (**OE**) is a composite of the **conditions**, **circumstances**, and **influences** that **affect the employment of capabilities** and **bear on the decisions of the commander**.
- Such components as the type of **equipment**, the **size of the network**, **OSs**, **key personnel**, and the **condition of the terrain** all play critical roles in decision-making. These components help to define the OE.
- Defining the OE results in identification of the following:
  - Significant characteristics that can affect friendly and threat operations.
  - Gaps in current intelligence.

- Cyber Threat Hunting (CTH) analysts identify significant relevant characteristics related to the mission variables pertaining to the enemy and terrain.
- The threat operator evaluates significant characteristics to identify gaps and initiate information collection.
- Failure to identify or misidentification of the effect these variables have on the mission at a given time and place can hinder decision-making and result in mission failure.
- The sum of the characteristics identified represents the current OE.
- Defining the OE in an operation is the foundation that enables mission decision-making and guides strategy.
  ![661243cd-64ad-4d5a-a3b6-eed54d65200a](https://github.com/user-attachments/assets/25b34af4-38ee-4cc8-944a-070b7c72977a)

### Cyberspace Planes
- Cyberspace terrain differs from actual physical terrain because the latter is used to describe physical locations instead of logical or virtual locations.
- In cyberspace, there is no physical proximity, and devices can be compromised remotely.
- A router that connects a network to an Internet Service Provider (ISP) is an example of key cyber terrain.
- Even though the router and its administrator are located in the same building, the administrator could be unaware that a threat actor located anywhere in the world has compromised and gained administrative access to the router.
- Additional examples are provided below to better convey how cyberspace terrain traverses the cyberspace planes at various levels while highlighting three important layers that are essential when evaluating the OE for a DCO mission.
  ![c30d9d85-8555-47b5-885c-985165874d15](https://github.com/user-attachments/assets/cf2cdf49-50bf-4949-aaad-5f578eada16a)

#### Supervisory Plane
- The Supervisory Plane consists of cyberspace elements that perform such supervisory functions as start, stop, modify, or redirect. This plane provides a channel for Command and Control (C2).
  - An example of the Supervisory Plane is a botnet C2 attack in which the botnet C2 servers act as key cyber terrain. 

#### Cyber Persona Plane
- The Cyber Persona Plane describes identities in the cyber domain.
- The Cyber Persona Plane consists of user accounts or credentials, whether associated with a human or with an automated process (e.g., service accounts), and their relationship to one another.
- Cyber personas may directly relate to an actual individual or entity, incorporating personal or organizational data (e.g., email and IP addresses, web pages, phone numbers, web forum logins, or financial account passwords).
- Permissions to access physical and logical aspects of the OE are also included. When analyzing the cyber persona layer, identify key characteristics by considering the following:
  - Data and information consumed in the terrain.
  - How local users interrelate with the physical network and logical network layers.
  - Usernames, permission levels, email addresses, chat names, etc.
- An example of the Cyber Persona Plane is a user account in the network that can be used to compromise access to other areas of the network.
  - In this case, the account would be deemed as KT-C because it is a user's account with credentials that is providing access to valuable resources within the network. 

#### Logical Plane
- The Logical Plane comprises a wide range of systems, services, and protocols that maintain the network's availability.
- The Logical Plane consists of all the data, whether resting, in transit, or being used in the physical network layer.
- The logical network layer is based on programming or software that derives network communications, interactions, and connectivity.
- A logical network map is used to close information gaps and enrich data from other cyberspace layers. 

- According to **Joint Publication 3-12**, Cyberspace Operations, **individual links and nodes** are represented in the **logical network layer**, along with various distributed elements of cyberspace, including **data**, **applications**, and **network processes** not tied to a single node.
- When analyzing the logical network layer, identify key characteristics by considering the following:
  - Websites or web pages that influence or have a social impact on the network.
  - Mission partner logical network configurations and vulnerabilities.
  - Mission partner physical network configurations.
  - Software that handles and shares mission partner data.
  - Virtual Private Networks (VPN) or subnets that cross physical boundaries.
- An example of the Logical Plane is the Domain Name System (DNS) that provides logical mappings between domain names and IP addresses.

#### Physical Plane
- The Physical Plane within a cybersecurity context is often described as directly mapping to Layer 1 of the Open Systems Interconnection (OSI) model.
- However, the Physical Plane cannot be constrained within the OSI model layers.
- The Physical Plane consists of the tactile IT devices and infrastructure that provide storage, transport, and processing of information within cyberspace.
- Depicting the Physical Plane within the OE allows analysts to inspect the plane as it relates to friendly and threat operations.
- Analysts derive the Physical Plane depiction from products developed by the network owner and their network validation.
- When analyzing the physical network layer, identify key characteristics by considering the following:
  - Threat C2 systems — physical devices adversaries use to leverage to execute their operations — that traverse the cyberspace domain.
  - Critical nodes that a threat actor can use as a jump point to gain additional access in the OE.
  - Physical network infrastructure in the terrain (additional examples are fiber optic cables, wireless access points, firewalls, and storage arrays).
  - Assets with the ability to access data and information residing on and moving through the network, such as packet capture devices.
  - Physical storage locations with the most critical information and accessibility to that information.
  - Implemented measures that prevent threat actors from accessing the networks.
- An example of a Physical Plane asset is a device that is configured with an obsolete protocol that allows easy access to the network for adversaries.

#### Geographic Plane
- The Geographical Plane defines the physical location of infrastructure supporting cyber operations.
- Some examples of the Geographical Plane are:
  - Physical location of Virtual Private Network (VPN) capable devices connecting two secure facilities over the internet.
  - Power substation servicing power to a high value asset (military base, hospital, government building).
  - Forward operating base conducting intelligence collection. 

### Impact Levels
- When prioritizing procedures and tools, proper calculation of impact is important.
- The Chairman of the Joint Chiefs of Staff Manual, CJCSM 6510.01B, says to "consider the current and potential impact of the incident or event on the confidentiality, availability, and integrity of organizational operations, organizational assets, or individuals."
- Confidentiality, integrity, and availability are often referred to as the CIA triad.
- A network lacking one of these aspects is deemed to have a deficiency in its security posture.

#### Confidentiality
- Confidentiality is a measure of how damaging the loss of data is.
- Classify and encrypt data to ensure confidentiality.
- As an example, the username and password of a bank account are highly confidential.

#### Integrity
- Integrity refers to the consistency or trustworthiness of the data.
- To ensure integrity of valuable data, use hashing, encryption, or digital certificates.
- As an example, it is essential that data presented to bank customers match their accounts.
- If customers lack trust, they may close accounts and spread the word that the bank is not to be trusted.
- **Non-repudiation**: the inability to dispute or deny something is a concept associated with Integrity.
- To enforce secure email transactions, digital signatures ensure the sender can not deny having sent the email and the recipient can not assert receipt from a different user, thus ensuring integrity in the transaction.

#### Availability
- Availability ensures that authorized personnel are granted access to data or system resources in a timely and consistent matter.
- For availability to be enforced and maintained systems must be designed with redundancies, processes and controls that ensure authorized access to data and systems is provided at acceptable performance levels (i.e. accurately sizing compute resources), that the system can automatically absorb minor outages while maintaining uptime (i.e. redundant network link) and that larger outages are quickly mitigated through manual processes (i.e. restore data from backups).

### Terrain Tiers
- A network, its supporting infrastructure, and the various integrated applications can be prioritized into three tiers of KT-C, with respect to potential loss or damage severity.
- If an adversary inflicted damage to a particular area of the network or a particular infrastructure component, the consequences of the damage to the mission execution that the KT-C enables or supports would be dependent upon the function of the network area or component.
- Adversaries attempt to compromise various elements of KT-C to exploit, compromise, damage, or destroy.
  ![58e975b5-1c5e-468f-a85a-8e55ca08b19d](https://github.com/user-attachments/assets/12e31780-6c14-4992-9eb5-ea589d61e0e7)

#### Tier 3
- Tier 3 key terrain covers **general data and applications**.
- Compromise of such assets or information makes the organization subject to periods of **degraded performance**, but it **does not destroy or corrupt data** or **halt business processes**.
- Examples of Tier 3 key terrain include data or services that, if **lost**, **corrupted**, or **destroyed**, can be **recovered or restored with minimal impact** on business processes.

#### Tier 2
- Tier 2 key terrain covers **important data and applications**.
- Compromise of such assets or information makes the organization subject to **serious damage** and **interrupts** or **degrades** business processes.
- Examples of Tier 2 key terrain include data that, if **lost**, **corrupted**, or **destroyed**, would have a **serious impact on the organization** or the **essential applications or servers critical** to those data.

#### Tier 1
- Tier 1 key terrain covers **top value, critical and essential data**, **applications**, **network services**, and **information processing**.
- Compromise of such assets or information makes the organization subject to **exceptionally grave damage and prevents critical business processes**.
- Examples of Tier 1 key terrain include any asset whose data **compromise**, **corruption**, or **destruction** has a **devastating impact on the organization’s applications, critical network infrastructure, or data systems**.

### Terrain Identification and Prioritization
- Terrain identification and prioritization for a CPT define the mission scope as it pertains to **initial objectives**, **intended effects**, and **commander's guidance**.
- Analysts must have an understanding of the detailed network terrain. A prerequisite to successful missions is the ability to verify mission owners' identification, enumeration, and characterization of the protected networks, systems, or assets to ensure an accurate OS and identify specific key terrain in cyberspace.
- A site survey is the close examination and analysis of a given location or customer site in order to obtain mission-relevant data or requirements.
  - The information obtained during a site survey helps determine the mission terrain, gathers critical data, and defines the network owner’s needs.
  - Information that can be collected during a site survey includes access to the site and necessary equipment, network topology, OSs, and critical onsite personnel to assist with the operation (such as security and IT personnel).
  - During the site survey, a DCO team supporting threat hunting develops relationships with the network owner, finalizes the Operation Order (OPORD), develops the tactical plan, and collects the crucial mission data necessary to build a hunt plan.
  - The site survey allows for time to come to an agreement with the network owner and Operational Control (OPCON) chain in regard to tactical plan execution. During this time a team arrives, requests a work location, gains access to personnel/systems, and integrates its equipment and tools into the network.
  - Site surveys may not be required for each operation (for example, if the mission is returning to a previously visited site), but when they are conducted, site surveys should be at the network administrator's or local defender's location of the designated terrain.

- To develop the fundamental understanding of the terrain, a DCO team must collect data before the site survey occurs.
  - Data to collect prior to the site survey includes, but is not limited to, **policy documents**, **briefings**, **log samples**, **network maps**, and **vulnerability scans**.
  - Collecting required data is mission and team dependent and often requires connecting equipment to the mission partners' network.
  - Once KT-C assets are identified and optimal points to collect data are selected, proper authorization by the mission partner must be in place for the process to proceed.
  - This should be precoordinated with the OPCON chain and the network owner before the onsite portion of the survey.
  - Collaborate with the assigned DCO team to obtain the latest site survey.
  - Discuss fundamentals of the network with the DCO team personnel and local defenders to identify all relevant information about the network.



### Threat Hunting Methodologies
- Cyberspace Threat Hunting (CTH) is the process of actively searching information systems to identify and stop malicious cyberspace activity.
- CTH can be carried out at all network tiers to meet DCO requirements.
- Three unique core CTH methodologies exist: **driven by analytics**, **situational awareness**, and **intelligence**.

#### Analytics-Driven CTH Methodology
- Analytics-driven methodology leverages **data** and **analytics**.
- This methodology uses **complex queries and algorithms** to apply to data sets.
- Often the queries are applied using automation in software.
- A key distinction with the analytics methodology is that **no physical access to local machines, networks, or systems is required**.
- **Data artifacts** consisting of **sensor alerts**, **system logs**, and **network traffic** are **vital** to the analytics-driven methodology.
- CTH analysts **combine knowledge of data artifacts** with **knowledge of automated analysis capabilities** to develop a **picture** of the **network** terrain.

#### Situational Awareness–Driven CTH Methodology
- Situational awareness–driven methodology leverages an **advanced understanding of a particular cyberspace terrain** in order to detect anomalous activity.
- Much like analytics-driven CTH, situational awareness–driven methodology **does not require physical access** to local systems.
- **Data artifacts** pertaining to the **Operating Environment (OE) are critical** to this methodology.
- CTH analysts examine **data artifacts over time** in order to understand **system normality** and **detect outliers** in behavior, which often lead to discovering potentially Malicious Cyberspace Activity (MCA).

#### Intelligence-Driven CTH Methodology
- The intelligence-driven methodology leverages **timely**, **accurate**, and **mature Cyberspace Threat Intelligence (CTI)** to detect advanced cyberspace threats.
- While employing the intelligence-driven method, cyber defense analysts utilize **mission-strategic**, **actionable insights** provided by CTI on adversaries and malicious activities, allowing CPT teams to make highly informed decisions when creating and executing developed hunt hypotheses.

### Leveraging KT-C
- KT-C must be identified and analyzed in the context of what is believed to be "**successful**" defense architecture and identify key assets that provide advantages over a potential attacker of the network environment.
- A general framework for identifying KT-C as a defender is provided in the subsections below.
- Similar to identifying actual physical terrain, the approach is altered to mirror terrain in cyberspace. 

#### Identify Potentially Targeted Assets
- Analysts should identify different threat actors and their **motivations**, **capabilities**, and **tactics** to identify the **assets they may target** in a breach of the network environment.
- What may be key terrain for the organization may not be key terrain for the adversary.
- An essential question is "**What may motivate the adversary to attack the network?**" 

#### Enumerate Avenues of Approach
- Analysts should associate vectors that may be used to access a potentially targeted asset. All interfaces that can be leveraged should be considered. 

#### Consider Observation and Vantage Points
- Analysts should observe and map key terrain that can be leveraged from vantage points within the network environment.
- Such infrastructure components as **core firewalls**, **network backup systems**, **identity and access management systems**, and **endpoint management systems** may provide an adversary with **deeper access** into the network.
- **Avoid limiting key terrain to only controlled territory**, as an adversary **may target a secondary organization** to gain an avenue of approach. 

#### Concealment
- Analysts should engage in the **constant reassessment** process of key terrain adversaries take to progress deeper into a network environment to limit avenues of approach to the network environment.
- Known vulnerabilities must be patched, and weak passwords must be identified and optimized.
- The following are basic steps to take in this regard:
  - Apply network access controls.
  - Deactivate unnecessary interfaces.
  - Construct a functional honeypot.

## Identifying Unknown Assets
### Network Documentation Overview
- Network documentation is a broad term used to describe the documents and other information that support an IT network.
- Whether in paper or electronic format, network documentation keeps and maintains records of the key aspects of the network for use by users and managers.
- Although each network has different documentation based on its relevant information, the following elements commonly appear.
  - Network topology map/diagram; specifically, an Open Systems Interconnection (OSI) Model Layer 1 and 2 diagram for physical systems and connections and a separate Layer 3 diagram that depicts Internet Protocol (IP) segments, such as subnets and Virtual Local Area Network (VLAN) numbers.
  - Documentation of the **names**, **roles**, **IP addresses**, and **pertinent information** for network and security **equipment**, **servers**, **hosts**, and other relevant IT assets.
  - Circuit information, such as circuit type. ID, bandwidth, and carrier.
  - IP address allocation.
  - Network and general IT hardware (manufacturers, models, serial numbers, locations, components, configurations, firmware version, end-of-support, and end-of-life dates).
  - Software installations (approved application list, versions, licensing, support, end-of-support, and end-of-life dates).
  - Vendors and service agreements.
  - Change logs.
  - Backup information and procedures.
  - Disaster recovery procedures.  

- What makes a good set of network documentation? When documents contain clear and concise wording and layouts, the reader can more effectively understand the material, including detailed diagrams.
- Additionally, when an organization adheres to a standardized format for documentation, the process is simplified and easier to communicate between teams. 
- The benefits of proper network documentation to users and organizations are numerous and include the following:
  - Increased comprehension of network among users.
  - Preparation for future incidents.
  - Easier upgrade planning.
  - Simplified cost planning.
  - Effective and expeditious recovery in the event of a catastrophic system failure.  

- Unclear, inconsistent, or incorrect documentation may have a negative impact on the quality of services, the network, and the personnel who maintain operational status.
- Poor-quality documentation adds unnecessary difficulty to tasks involving the network, which slows operations progress.
- Factors that negatively impact the quality of network documentation include the following:
  - Incomplete diagrams (for example, missing systems, connections, names).
  - Descriptions lacking detail (for example, missing IP addresses, names, functions, dates, times, version numbers).
  - Irrelevant information (unnecessary information that drowns out the critical parts).
  - Inconsistent formatting (differing fonts, oversized or undersized images, low-contrast fonts).
- Having high-quality documentation is critical for keeping a network functioning to its fullest.
- In addition, when documentation supports the network, the people who work on, and with, the network are better equipped.

### Enterprise Visibility Gaps
- The modern IT organization faces a variety of challenges, especially in security.
- Traditional security measures address most internal vulnerabilities and threats, but areas may be overlooked.
- These fringe operational areas with their associated vulnerabilities are known as enterprise visibility gaps.
- Some of the most common enterprise visibility gaps facing organizations today include the following:
  - Supply chain attacks
  - Shadow IT
  - Mobile applications
  - Social engineering

- The vast majority of organizations use devices manufactured by other companies.
- For example, a technology company may use several different manufacturers for routers, switches, laptops, and servers.
- Despite thorough planning and execution of security measures to protect the network, the supply chain that produces the network devices may create a gap if not held to the same security standards as the network.
- This issue is especially challenging due to the reliance on the security practices of manufacturers, which is out of the control of end users.
- A recent notorious attack, known commonly as the SolarWinds hack, exemplifies the damage that can occur from a supply chain attack.
  - Orion, which is an IT monitoring system, is a SolarWinds product.
  - Orion uses privileged access to monitor performance data and logs on hosts.
  - However, in September 2019, threat actors gained access to the SolarWinds network, avoiding detection.
  - Then, through the use of malicious code injection, the attackers distributed their malware via updates to Orion.
  - This distribution affected over 18,000 customers using Orion.
  - As a result, the malware allowed the threat actors to gain access to systems and networks that had the malicious update. 
- This attack is a perfect example of the threat posed by a supply chain attack.
- By leveraging the trust between the supplier (SolarWinds) and the customers (users of Orion), the attacker can utilize the privileges that exist between them.
- Events similar to the SolarWinds breach highlight the critical damage that can result from the trust relationship between client and supplier.
- Even if a client has perfect security on its own networks, a slight vulnerability in the supplier may undermine the security efforts entirely.

#### Shadow IT
- Shadow IT is the use of devices in an organization’s network without the knowledge or consent of the IT department.
- Examples include connection of a personal smartphone to a workplace network without permission or the installation and use of a software application not explicitly permitted by the IT department.
- The most common reason for employee use of shadow IT is convenience.
- By nature, most (but not all) security controls reduce the speed of tasks because they add more steps and increase the complexity of operations.
- However, such security controls have the benefit of protecting the organization from security incidents, which carry a substantially higher time and monetary burden.

- Adhering to security controls outweighs the drawbacks, but human nature tends to seek the path of least resistance.
- For example, an employee at a company that handles sensitive Personal Health Information (PHI) may need to reduce the file size of a batch of Electronic Medical Records (EMR).
  - Rather than use the company’s approved but time-consuming method of file compression that processes one file at a time, the employee downloads an open-source file compressor from GitHub that is not compliant with the HIPAA. The software may make the work easier but also subjects the organization to security issues.
- Shadow IT is a common visibility gap in organizations due to the inconvenient nature of security protocols.
- However, by circumventing the rules, unauthorized devices and software can create unexpected vulnerabilities in a network.

#### Mobile Applications
- Applications for mobile devices are another example of an enterprise visibility gap.
- Whereas desktop security is widely accepted and prolific, mobile security is generally less understood.
- App stores, such as Google Play, GetJar, and Aptoide, have millions of available applications.
- However, like desktop software, they may contain malicious code.
- By placing too much trust in the legitimacy of applications from app stores, users may inadvertently infect their device with malware. 
- The enterprise visibility gaps of shadow IT and mobile applications may combine to cause issues if, for example, an employee connects a compromised mobile device to a work network, allowing mobile malware to infect other devices in the network.
- Malicious mobile applications create enterprise visibility gaps due to reliance on employees' knowledge of mobile device security. 

#### Social Engineering
- Social engineering is a blanket term for the practice of manipulating people into performing unwanted actions.
- As security methods, technologies, and standards become stronger and more complex, the human component of security becomes a greater threat.
- For example, if a system uses an advanced antivirus, is up to date on patches, employs advanced encryption, and is hardened to security standards, an attacker may be thwarted from gaining access to the system.
- However, if the attacker can coax an employee to disclose credentials via a scam email, all these security measures may be bypassed.

- The following are common examples of social engineering attacks:
  - **Phishing**: This is the most prolific type of social engineering attack, in which an attacker uses email or another messaging method to obtain personal or other sensitive information.
    - The attacker often poses as a reputable or legitimate company.
    - Through use of clever wording or enticing rewards, the attacker tricks the victim into disclosing information, clicking on a malicious link, or downloading a malicious attachment.
  - **Spear-phishing**: Spear-phishing attacks are highly customized phishing attacks, using information obtained from social media, public records, or other sources to target specific individuals.
  - **Shoulder-surfing**: This is a physical act of an unauthorized user peeking over a victim’s shoulder to see passwords being typed or read sensitive information.
  - **Tailgating/piggybacking**: This is the act of an unauthorized user following an authorized employee into a restricted area.
    - An example of tailgating is when an employee scans a badge to enter a restricted office space and holds the door open for a stranger.
  - **Dumpster diving**: If attackers cannot access an area physically, they may resort to sifting through the trash for documents. Any information not shredded or otherwise properly disposed of may be subject to theft. 
- While social engineering is not a traditional visibility gap, it is an often-overlooked vulnerability, as it takes advantage of the human element of security. 

#### Network and Log Visibility Gaps
- In addition to the enterprise visibility gaps mentioned, network visibility gaps may exist.
- Properly placed sensors in a network are critical to collecting logs and other information.
- For example, having a firewall without a sensor behind it may lead to incidents not being properly captured for analysis.
  - To solve this, certain considerations are needed to strategically place network Test Access Points (TAP) or configure Switched Port Analyzers (SPAN, which is also known as port mirroring) to most effectively capture information. 
- The intended purpose of a sensor determines where it will be placed.
- For example, if a sensor is needed to gather general traffic on the network, it will be placed at a major network intersection, such as a core router or switch.
  - If an administrator wants to ensure that a firewall is functioning properly, a sensor may be placed before (facing external traffic) and after (facing the internal network) the firewall.
  - Additionally, some networks may not allow placement of sensors in certain sections, such as Operational Environments (OE) of power plants or water treatment facilities.
  - To provide visibility of traffic, sensors may be placed at the gateway of the network instead of inside it.  
- Finally, log gaps are another type of enterprise visibility gap. Logs are critical in determining the past activity of a system.
- When (or after) an attack takes place, a threat actor may manipulate the system’s logs to cover their tracks.
- The intruder may wipe logs completely, or perform more stealthy actions such as inserting or removing specific sections of the log that documents their actions. 

### Shadow IT
- As discussed in the previous section, shadow IT is one of multiple enterprise visibility gaps in a modern IT network.
- Shadow IT constitutes the unauthorized use of hardware or software in an environment to evade the scrutiny of the IT department.
- Typically, the use of shadow IT is not malicious but, instead, for the sake of convenience.
- Instead of dealing with information systems that are in place but inconvenient in the organization, employees may choose to bring their own devices or software that accomplish tasks more rapidly or easily.
- Examples of shadow IT include the following:
  - An employee uses an online Portable Document Format (PDF) editor to modify work documents.
  - A department purchases a printer from a retail store and then connects it to the network to print documents.
  - An employee connects a personal smartphone to the internal Wi-Fi network without approval.
  - An accountant downloads an Excel macro from an online forum post and uses it in a spreadsheet.
- Although the use of shadow IT usually alleviates some difficulty or inconvenience, it also creates security risks.
- By introducing devices and software not properly vetted for vulnerabilities, shadow IT can create unexpected challenges.

### Undocumented Assets
- Undocumented assets are a common issue in larger and older networks.
- As a network is used for projects, personnel who work on it may change over time.
- For example, a Linux system might be used as a small web server for a year, then repurposed into a File Transfer Protocol (FTP) server for 2 years, and then repurposed as an email server.
- The machine will likely contain many artifacts and old software installations (such as web server and FTP server) from its previous jobs.
- When this situation is scaled to include many machines in a network, a larger problem develops.
- Aside from undocumented software, the systems and devices themselves may become lost or undocumented.
- The term system sprawl refers to when devices and networks expand over time but the documentation and understanding of them do not keep up at the same pace.
- This can slowly become an issue, as these unaccounted systems use resources in the network.
- Additionally, the lack of maintenance and usage of these older systems can make them outdated (missing patches, using outdated virus definitions), which creates vulnerabilities.
- If attackers can leverage these vulnerabilities, they can compromise the network. 

## Establish Analysis Priorities
### Priority Assets
- Networks have relatively standard hardware and software configured for each entity's specific needs.
- These systems are configured based on organizationally assessed risk and priority calculations.
- Therefore, working with mission partners to understand their internal priorities, and then directly influencing and prioritizing analysis and logging, is essential.
- The CDA-N lesson Key Terrain in Cyberspace (KT-C) discussed collecting and addressing the mission partner’s high-priority assets to prioritize collection and analysis posture.
- Working directly with the mission partner enables the CDA to better understand assessed priority assets, as an asset may have been improperly categorized or updates to the documentation provided prior to the mission execution might exist.
- Priority assets may be buried deep within a network, but they may also exist within the Demilitarized Zone (DMZ).
- It is important to review the mission partner's assessed priority assets to provide input to possible changes and understand what is deemed important on the network.
- Mission partners may document how assets in their environments are prioritized using different formats.
- In Figure 3.3-1, the mission partner City Power Plant has elected to use a network diagram to record and prioritize KT-C assets.
- Other mission partners might provide a document in a spreadsheet format.
- In some cases, mission partners might lack documentation altogether.
- In such a case, it is important to engage the mission partner to understand the Operational Environment (OE) and define the KT-C and its priorities together.
  <img width="2383" height="1957" alt="ff9d2a78-ff21-40de-b7af-0257659ba3d5" src="https://github.com/user-attachments/assets/032fb545-45b7-4076-b7bb-b30c1bbeb5cc" />

### Prioritized Log Collection and Vulnerable Locations
- Aside from priority adjustments for reporting, factoring in priorities when configuring log collection, especially in identified vulnerable locations, is pertinent.
- A host or area of a network may be classified as vulnerable based on numerous aspects, including, but not limited to, external access or unpatched areas of the network.
- Any access from the external networks or users should be prioritized because this is the easiest entry point for an attacker.
- Such areas may be a subnet, such as a DMZ, or a physical space like a cyber café, kiosk, or Bring Your Own Device (BYOD) area of a network.
- Physical access to a network may also be a key entry point if such technologies as port security have not been enabled to lock out unused ports.
- Network segments may not allow immediate patching, placing them in the vulnerable area category as well.
- Additionally, all devices along the external perimeter should be prioritized to see any attempted access from external sources.
- If a priority host exists within the DMZ, it should be monitored more aggressively than a priority host that is four routers deep into the network.
- Review of logs that can be collected from each host in the network, especially the priority ones, is also important.
- As an example, if a database server is hosting the customer data for a company within the DMZ, the analyst should address the reason the host was located within the DMZ subnet and then find all possible ways to log the interactions with this server.
- It may be that only the web server has access to the database server for customer login, which would decrease the overall threat landscape.
- However, if an attacker were able to gain access to the web server, the database server would be the next likely target.
- Logging all interactions with the database may be resource intensive, but having a way to investigate any attacks on the database server is key to determining the depth of a breach.
- Relying on the log files on the database server is also counterproductive because attackers would likely prioritize cleaning their tracks after a compromise.
- Offloading logs to a remote server like Remote Syslog or a Security Information and Event Management (SIEM) system decreases the likelihood that attackers would be able to clean their tracks, which would allow the analyst a way to quickly assess the overall impact of a breach.
- In this example, it is important to review the rationale for putting a database server within the DMZ, prioritize database log collection, and find a way to offload the database server logs onto another host for analysis.
- CDAs should consider the following during prioritization of log collection and vulnerable locations:
  - What applications create logs on the asset?
  - Where does the application save the logs?
  - Can the logs be forwarded to another host within the application? Does another application (for example, Filebeat or Splunk Universal Forwarder) need to be installed to push the logs?
  - Are the logs in a format that are easily ingested in the mission partner's security architecture?
  - Who will be dealing with the asset: a customer-facing web portal, lobby kiosk, or developer workstations?

### Prioritized Log Retention
- Once priority assets are realized and logs are collected, addressing log retention issues should occur.
- It is never good when a hard drive fills up with logs because someone forgot to purge logs on a reoccurring basis, causing unscheduled down time.
- Even greater headaches are likely when someone misconfigures log rotation on a sensor platform like Security Onion, crippling the entire team until the device can be cleaned.
- Keep the following in mind with regard to prioritizing log retention:
  - Logs eventually fill up a storage device if not kept in check.
  - If at all possible, write logs to a drive that is not required for boot in case the log rotation breaks.
  - Save logs on a host without general user access (for example, a syslog server or Security Onion).
  - If an application is writing its own logs, ensure no disconnect exists with multiple applications writing logs to the same disk and filling up storage inadvertently.

- Because intrusions are often hidden for multiple months, logs should be saved for as long as possible.
- However, data storage is a finite resource and at some point can reach capacity, and prioritization must be considered for cleanup.
- Keeping full packet captures for 6 months at a time may not be an option, but keeping NetFlow or Zeek connection logs may be an acceptable alternative.
- If packet captures are absolutely necessary, offsite cloud storage may be an option.
- However, securing that storage would be essential, and a ledger of the files that were offloaded would be needed for adequate record-keeping.
- Filtering out the traversal of such packet capture transfers to the cloud is also necessary.
- Otherwise, there would be a problematic inception issue in which the encrypted file transfer of the pcap file to cloud storage would be included in the pcap file scheduled for upload from the network at a later time, increasing the requirements on local and cloud storage.
- Log retention policies and regulations may be imposed on the mission partner by different organizational bodies.
- For example, (HIPAA) requires that activity associated with health information be logged for at least 6 years, and the Sarbanes-Oxley (SOX) Act specifies retention up to 7 years, depending on the document type.
- The HIPAA Administrative Simplification Regulation Text provides additional details regarding data retention.
- The Sarbanes-Oxley Act, Section 802, describes retention policies for data that can be audited, which includes access logs to relevant digital information.  

## Outlining Defensive Perimeters
### Defining Defensive Area of Operations
- Combat operations provide great insight into understanding cyber warfare.
- As in combat operations, one of the keys to success in DCO is understanding the AoO and defensive perimeters.
- The first step in defining defensive perimeters is to gather a firm picture of the organizational AoO.
- Organizational mission and policies dictate the network environment that requires protection.
- This environment may be used to define the foundation of the defensive AoO and begins the map of the defensive perimeters.
- Using the aforementioned documentation combined with a thorough network map, CDAs can build an in-depth topology of the network as shown in previous lessons.
- Within this topology, Key Terrain in Cyberspace (KT-C) needs to be identified, thus establishing the need to set up defenses around the network environment and critical devices.
- These defenses around the network are the defensive perimeter.
- After the topology has been gathered, identification of the network boundaries and all devices on the network borders is crucial.
- The network topology is used to define all systems within the AoO and can be used to identify these boundaries and devices.
- Boundaries are identified as connections that leave the network environment.
- Boundary connections can connect to the internet, external entities, or other organizational networks.
- A thorough analysis of the network, a detailed network map, and well-defined network boundaries are crucial to proper establishment of a defensive perimeter.

#### Defensive Perimeters
- Generally, multiple perimeters, both internal and external, exist within any network.
- Internal perimeters exist within individual sections of the network and impose additional security controls to help protect and segregate network sections.
- External perimeters exist along the edge of the network enterprise and generally reach out toward the internet or external entities.
- Internal perimeters allow for another layer of defense to network segments, whereas the external perimeter generally has the highest number of security controls to protect the entirety of the network.

- The first key step in identifying these defensive perimeters is to identify all devices along the network boundaries.
- The network gateways directly connect the network edge and devices.
- These devices typically include the gateway router, a firewall, and a proxy server.
- Other devices may be included, depending on the requirements of the network.
- A common high-level security control for the external perimeter is the Demilitarized Zone (DMZ), which is a network segment that includes external-facing services and acts as a layer between the internal network and external entities.
- The edge network boundary and all the devices identified along this boundary form the defensive external perimeter.

- Internal defensive perimeters may be more difficult to identify but typically can be identified by separate router connections, unique subnets, or unique Virtual Local Area Networks (VLAN).
- Some internal perimeters may appear similar to a typical external perimeter to ensure critical infrastructure has increased security levels, but they will not have any external connections.
- Devices that provide the separation and protections between these network segments are the key defensive perimeter devices to identify.
- Devices usually include switches and routers but may include firewalls and other controls as well.

### Identify Boundary and Edge Devices
- Identification of all systems within the organizational AoO outlines critical systems to protect, which enforces the need for a strong defensive perimeter.
- One key concept to apply to a defensive perimeter is defense-in-depth, which is critical to the proper defense of a network.
- This concept means to apply multiple layers of security devices and controls between the internal systems and external connections.
- To ensure this concept is in place, one must understand and identify numerous devices along defensive perimeters to protect internal systems.

- Internal systems lie within the security boundary and typically include such devices as **workstations**, **databases**, **printers**, **operational servers**, and **network devices**.
- These devices provide the ability to perform operations and must be secured within the defensive perimeters of the network.
- As discussed, many internal systems are segregated into their own network segments that often have their own internal perimeter.
- This provides an additional layer of security for the defense-in-depth concept.
- Check device configurations for networking devices that connect internal systems, as these need to include protections along these internal perimeters.

- Along with internal systems and their protections, the concept of defense-in-depth is bolstered by numerous security devices along the external perimeter.
- Security perimeter devices typically lie on or near the boundaries of the AoO and provide multiple layers of security to all devices inside the network boundary.
- Examples include **firewalls**, **guards**, **proxy servers**, **DMZ**, **IPD/IDS**, and networking devices with additional security controls.
- Below is a breakdown of a few common perimeter defenses.

#### Firewall -Vyatta Firewall
- Vyatta is an open-source, Linux-based virtual router and firewall.
- Using CLI (Command Line Interface), Vyatta may be used to implement numerous firewall rules to filter, block, or restrict traffic.
- VyOS is the Operating System (OS) used by Vyatta devices.
  ![68f6bf2c-3001-4a0a-a1a7-96c3ea41b6f3](https://github.com/user-attachments/assets/40ba61eb-e4b4-40aa-8acb-9f8f7c0a4e07)

- Figure 3.4-2 shows the output of the firewall rules.
- The current Firewall Global Settings show that all Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6) traffic will be accepted for an established and related network connection state.
- These rules apply stateful packet inspection, which means the firewall analyzes connection state details rather than just packet header details like a stateless firewall.
- The lack of information in the Rulesets Information section shows no firewall restrictions are applied to any interfaces.
- This means the firewall is allowing all traffic and contains no restrictions of addresses allowed to traverse through the firewall.
- Typically, Rulesets are populated with various firewall rules for devices within the network and prevent traffic from entering organizational networks from external connections.
  ![e460a945-3239-4c46-aeed-8b2b4792adcc](https://github.com/user-attachments/assets/dea7acd2-6d75-454f-bcaf-5bab6b732e4c)

#### Edge Router - Cisco OS
- Cisco IOS (Internetwork Operating System) is the proprietary OS used on all Cisco networking devices.
- Cisco IOS uses CLI to administer secure networking configurations through **routing**, **access control lists**, Port Address Translation (**PAT**), Network Address Translation (**NAT**), and more.
- For secure settings on an edge router, restrictions for accessing the device remotely should exist.
- Figure 3.4-4 lists some common configurations for how to secure Secure Shell (SSH) connections to a Cisco router.
  ![a50a159e-0013-4cbf-8d82-a1b5ccc4dee5](https://github.com/user-attachments/assets/db2038d4-24f8-4f6b-b0c3-e504687c6be5)

- Access Control Lists (ACL) are another major security control for networks.
- Figure 3.4-5 shows commands for a common configuration for two ACLs on a Cisco router to permit only (**IP**)–routing traffic from an authorized subnet and Virtual Teletype (**VTY**) traffic from known authorized source devices.
- **VTY lines** are a command line interface (CLI) created in a router and used to facilitate a connection to the daemon via Telnet or SSH.
- ACLs on Cisco devices have a feature called implicit deny, meaning that if no specific rule exists permitting traffic on the ACL list, then the traffic is denied.
- Based upon the list in Figure 3.4-5, devices from 64.210.18.131 would be allowed to establish a Telnet connection with the router, but a device from 192.168.1.1 would be denied.
  ![ec580923-a611-4abc-b9b4-67f8039ff326](https://github.com/user-attachments/assets/79d64fef-bb55-4819-9dc4-ec3e958373f8)

#### DMZ
- The DMZ is a secure area for forward-facing devices, typically isolated from the internal network with its own network segment and firewall rules.
- The DMZ is the front ground for providing forward-facing services but also monitoring the network.
- The DMZ becomes an ideal spot for generating alerts for potentially malicious activity.
  ![0edf6c1e-dc55-4961-b026-f6ccd8b7a294](https://github.com/user-attachments/assets/b7968990-78d5-4ff5-bb78-20fb82c3f75c)

- This DMZ includes all the devices that provide forward-facing services, such as email, domain name services, and web traffic.
- These devices are separated from the internal network but also provide an area to initially detect possible malicious activity.
- The separation from internal traffic means all external requests are routed to the DMZ network.
- This prevents enumeration of internal network devices from threat actors through routine external requests.
- Other security devices may also exist within the DMZ to provide additional security controls.
- The firewall is the first security device in the DMZ, used to route and protect external traffic only to the DMZ and prevent unauthorized access to the internal network of the organization.
- Additionally, DMZ security controls often include such devices as a proxy server, honeypot, or additional routers or switches.
- A proxy server is used to establish more secure external connections from the internal network.
- A honeypot may be used to masquerade as a real device with fictitious information to draw in adversaries.
- The device is used to create alerts and discover adversary activity without compromising damaging services within the network.
- **NOTE**: Some DMZs are set up with a dual-firewall topology.
  - The **first firewall** sits **between the DMZ and the edge router** and has rules to **allow the external services to send and receive external communications**.
  - The **second firewall** sits **between the DMZ and the internal network** and has rules to **prevent any unauthorized access back into the internal network**.

#### Data Malipulation from Security Controls
- Security devices and controls can manipulate data as it travels through the perimeter of the network they operate on.
- This can occur in the following ways.
  - Encryption/Decryption of Traffic: Packets are encrypted with a cryptographic algorithm before transmission to secure traffic from being intercepted in a readable format.
    - Messages can then be decrypted by the recipient.
  - Filtering Content of Data and Proxy Connections: Proxy servers act like a gateway to external entities.
    - The proxy server translates traffic between networks or protocols and acts as an intermediary server separating end-user clients from the destinations they browse.
    - Traffic flows through the proxy server instead of directly out of the network to the external entity.
    - The request comes back through that same proxy server, and the proxy server forwards the data received from the external entity to the original requestor.
    - This prevents any direct connections to internal systems and also masquerades the device information of internal systems from being exposed on the internet or external networks.
    - Proxy servers can also filter certain content.
      - This occurs by configuring the device to restrict or block specific web content based on specific criteria, such as inappropriate content or non-work-related websites.
  - NAT or PAT:
    - NAT and PAT provide another way of masking the internal addresses of the network.
    - NAT and PAT are generally configured on an edge router or firewall.
    - NAT, when configured on a networking device, takes any internal addresses that are attempting to send network traffic outside the internal network and translates them to a different IP address as it leaves the network.
    - PAT works in a similar way but allows for multiple connections for each IP address by altering the port established for the connection.
    - Each connection is given a unique port that allows for the connections to be sourced back to the proper internal destination.
  - Blocking/Restricting Traffic: Firewall rules and ACLs are the primary function for blocking traffic and are found on routers and firewalls.
    - Additionally, blocking or restricting traffic may be from a blocklist or allowlist.
    - This takes specific device information, such as a Media Access Control (MAC) address or an IP address, and creates a list of only allowed addresses (allowlist) or banned addresses (blocklist).
  - Duplication of Data: Some security devices ingest all network data possible.
    - In some instances, these devices may require a complete copy of network data.
    - Physical network taps or logical span ports may be used to duplicate this network data to be ingested by security devices, such as a Security Information and Event Manager (SIEM).

### Ensuring Defenses on the Perimeter
- Network security controls are critical along all boundaries of a network.
- Devices need to be configured with numerous security controls, including access control, allowlisting/blocklisting, content filtering, and malicious activity prevention, where possible.
- These secure configurations are key to implementing a strong defensive boundary.
- Additionally, monitoring the perimeter of the network is a key function of securing a network.
- Sensors, forwarders, or other centralized logging methods can be used to provide timely data to such security tools as a SIEM.
- A SIEM can provide CDAs with a focused area to monitor the defensive boundaries and other portions of the network.
- Alerts can also be created to detect anomalous behavior.
- The perimeter devices are configured for a log stash or SIEM tool that makes the logging able to be easily parsed and allows for the generation of alerts based on potentially malicious activity that occurs on those devices. 

- Kibana alerts are generated by the various modules listed on the Security Onion - Alerts page: Playbook, Suricata, Wazuh, and Zeek.
- These modules come with various signatures that trigger if an event relates to potentially malicious or anomalous activity
- Ensuring that alerts are set up to closely monitor the activity of devices on the defensive perimeter is critical.
- For example, if an unauthorized IP attempts to connect directly to the edge router of an enterprise network, an alert could be generated.
- This alert could include key details about the attempted connector, such as its IP address, MAC address, or the port or protocol attempted to be used.
- This information can be used to search for additional activity from the unauthorized connection source or to build a potential list of known malicious addresses.
- Proper setup of these monitoring devices is critical.
- Individual logs generally do not provide enough information, as the logs are granular and can take many man-hours to analyze individually.
- Dashboards like the ones built into Kibana can help to quickly review large amounts of logs and get a better picture of what is actually occurring on the network.
- An issue arises when handling encrypted traffic since Kibana and other security tools are unable to read logs from encrypted network traffic.
- Additionally, monitoring the perimeter can provide early detection of malware on the network, which is key to preventing the spread of the malware across the environment.
- When CDAs are alerted to the presence of malware, all data and devices must be recorded.
- The information will then be passed to response teams within the organization's cybersecurity enterprise to properly resolve the issue.

## Validating Inventory
### Validating by Scanning
#### Overview
- Network map/inventory validation may be accomplished in many ways.
- Both active and passive methods are useful and have applications, depending on the network or mission partner requirements.
- Methods used to enumerate networks may be separated into active or passive execution.
- Active methods are covered first, as they may be more accurate and faster than passive methods when targeting active hosts directly.
- Hosts may be validated using various active measures, such as the following:
  - Pinging (Nmap, ping)
  - Port scanning (Nmap)
  - DNS lookups
  - NetBIOS queries

- In larger networks or networks with Operational Technology (OT) equipment, ensure that requests do not flood the network too quickly.
- More passive methods may be required for some networks or to comply with mission partner requirements. Especially for OT networks, any outside traffic is generally not allowed and may even cause disruption or downtime.

#### Pinging and Port Scanning
- Such utilities as Nmap or the standard ping utility may be used to actively scan a network.
- Although scanning a network as a whole using Nmap is a straightforward way to map out a network to validate inventories, Network Analysts must be careful when interacting with mission partner networks using the tool.
- This is because active scanning with Nmap may trigger rules and alerts or, in extreme cases, interfere with operation.
- Even so, the effectiveness and utility of Nmap to quickly scan a network make the utility a valuable tool.
- Both Nmap and the ping utility use Internet Control Message Protocol (**ICMP**) packets to determine if a system is online and reachable.
- A simple ping request may glean some information. For example, Unix-like Operating Systems (OS) typically respond with a Total Time to Live (TTL) of 64, whereas Windows hosts typically respond with a TTL of 128.
- However, many hosts — especially Windows hosts — block or drop traffic, which can make using only ICMP traffic insufficient, or exceptions to this firewall rule may be requested.
- In addition to using ICMP traffic, Nmap can use connection attempts to various common ports to determine if a particular host is online, such as those used for Secure Shell (SSH) or Server Message Block (SMB)
- RedSeal, as demonstrated in previous lessons, is capable of importing the results of Nmap scans.
- RedSeal can help in mapping out networks by providing not only a visualization layer but also a useful utility to centralize data collection and analysis.

#### DNS Queries and NetBIOS Queries
- Queries may be used to validate network inventory entries.
- Active Directory (AD) may contain a wealth of knowledge about networks that use Windows domains, although this information may be stale if AD entries are not actively maintained, given that entries are often not automatically removed when inactive.
- Although Lightweight Directory Access Protocol (LDAP) queries may be more efficient, a simpler way to interact with AD using commonly available tools is to perform DNS queries against a DNS server configured in the AD domain.
- DNS or other name lookup services may be assumed to exist on modern AD domains.
- This is because a basic requirement of a Windows AD network is to have DNS or other name lookup services available.
- Notably, this information may be stale (disconnected hosts may appear in AD domains) or incomplete (only devices configured to use AD assets may appear).
- AD configurations vary from mission partner to mission partner.
- Although AD domain controllers tend to host DNS in addition to other directory services, DNS may be delegated to other hosts.
- The nslookup tool may be used to perform DNS queries once the DNS servers have been identified, through either mission partner documentation or traffic analysis.
- If configured correctly, nslookup may be used to query for the hostname for a particular IP address. See the example code below.

  ```
  C:\Users\trainee>nslookup 172.16.2.4
  Server:  dc01.energy.lan
  Address:  172.16.2.5
  
  Name:    sql.energy.lan
  Address:  172.16.2.4
  ```

- In the example, the IP address being queried for is 172.16.2.4 and the server being queried against is 172.16.2.5.
  - The server returns a name of sql.energy.lan for this IP address.
  - This lookup is done via reverse DNS lookup; the tables that enable this are not a requirement for networks to function correctly and may not always be defined or available.

- Aside from querying AD (via LDAP or DNS queries), various protocols (such as NetBIOS) may be used to query remote machines directly.
- NetBIOS may be used to perform many functions, such as NetBIOS Name Service, which has the ability to query remote machines for the NetBIOS name associated with a specific IP.
- The nmblookup tool is available on Windows machines to perform such a query.
- Due to security concerns with this protocol (it is used by attackers to spoof or perform Man-in-the-Middle [MitM] attacks), it may not always be enabled as a fallback for DNS queries.
- In addition, the wmic command line utility may be used to perform the lookup via Windows Management Instrumentation (WMI), and PowerShell has cmdlets that may be used to perform host lookups.

### Validation Using Connection Logs
#### Overview
- Because scanning tools may overwhelm some types of devices (especially OT devices) or networks, more passive methods may be used.
- NetFlow, connection logs, and other connection-based information sources may be used to perform inventory validation in a low-impact way.
- These sources can determine active hosts as well as services in active use.
- For example, if traffic on port 22 is indicated, then SSH traffic may be assumed to be accessible on the host.
- Parsing this data may be used to complete and validate network maps and to help identify anomalies in actual practice (for example, services being accessed that should not be accessible or enabled).

#### NetFlow
- NetFlow is a feature, originally a proprietary protocol used by Cisco devices, for tracking flows and data associated with these flows, such as bytes transferred or number of packets.
- This data, typically captured by Layer 3 devices, may be used to build out network maps by demonstrating actual connections between hosts on different subnets.
- This allows for tracking of active hosts on a network as well as services in use that are exposed (and used) across subnets.
- Layer 3 devices with this feature enabled can store the data in memory, store the data to disk, or forward data to a NetFlow collector.
- NetFlow collectors store and aggregate data from one or more NetFlow-enabled devices.
- NetFlow considers the following seven values to uniquely identify a flow:
  - Interface: The ingress interface, on the recording device, for this flow.
  - Source IP address: Source IP from the IP header.
  - Destination IP address: Destination IP from the IP header.
  - IP protocol: Such as Transmission Control Protocol (TCP) or User Datagram Protocol (UDP).
  - Source port: For TCP and UDP only. Value of 0 is stored for all other protocols.
  - Destination port: For TCP and UDP. Type and code stored here for ICMP; value of 0 is stored for all other protocols.
  - Type of service: Eight-bit field that maps to the same value in IP datagrams. The exact nature of this field is beyond the scope of this lesson.
- Any packet that matches on all seven values increments counters (such as bytes transferred and number of packets) for that particular flow.
- NetFlow is covered in more detail in subsequent lessons and is introduced here only to illustrate a potential data source to be used in mapping networks.

#### Connection Logs
- Zeek stores and aggregates data about connections in a log known as the connection log (or conn.log).
- Similar to NetFlow, this data includes connection metadata, such as IP addresses, port numbers, and protocols.
- Connection logs differ from NetFlow flows in several ways, including the following:
  - Source of data. (Unlike NetFlow, connection logs are generally generated by sensors.)
  - Amount of metadata stored. (Connection logs include such information as application protocols.)
  - Granularity. (Zeek stores data about each session or connection rather than just aggregating the data based on the seven criteria identified above.)
- In Security Onion, these logs are forwarded to Elastic Search. This allows for easy querying of this data by the user. 

### Validating Using Packet Capture Analysis
- Network Packet Captures (PCAP) provide valuable insight into networks without directly interacting with any hosts on the network.
- This can be vital for OT networks, where low-powered devices might be overwhelmed by even minor active-scanning techniques.
- As with connection log analysis, there may be gaps in coverage, and only hosts that are active and services that are used during that time period can be seen.
- Although Wireshark can be used to manually map out a network, more programmatic methods should be used whenever possible to save time and effort.
- For example, importing the data into Security Onion can allow the data to be queried to more easily consume the data.
- This can be combined with other tools to either focus the research paths or enhance or enrich the data, such as using RedSeal to import device configurations to generate a map containing each subnet before querying Kibana.
- The following is an example of how to analyze a network by combining tools to produce a network map completely offline:
  - Import network device configurations into RedSeal.
  - Import data, such as customer-supplied packet captures, into Security Onion using so-import-pcap.
  - Use RedSeal to identify subnets of interest.
  - Use Kibana in Security Onion to determine hosts and services in use for each subnet.
- NOTE: The behavior of so-import-pcap depends on the version of Security Onion being used.
- In older versions, this command would make changes to the configuration of a system that would impact data collection.
- The following workflow makes use of this command; however, it should not be used lightly or without research.


# MOD 4
## Posture Impact
### Security-Focused Configuration Management (SecCM)
- The configuration of a system is a representation of a system’s components, how they are arranged, and how they are connected.
- Each component can affect the security posture of the system as a whole.
- Configuration management represents the process in which changes to the system, which will inevitably occur over time, are handled and processed.
- Organizations cannot control natural disasters like floods and earthquakes, hackers, and other threats.
- However, organizations can limit vulnerabilities and reduce threats via implementation of a robust security-focused configuration management process.
- This process is referred to as SecCM in National Institute of Standards and Technology (NIST) Special Publication (SP) 800-128, Guide for Security-Focused Configuration Management of Information Systems.

#### Terminology
- Before diving further into SecCM, it is important to define a few common configuration management terms:
  - **Configuration item**: An identifiable component of a system (for example, hardware, software, firmware, documentation, or a combination thereof) that is a discrete element under change control.
  - **Baseline configuration**: An approved set of specifications for a configuration item at a given point in time. The baseline is used for future builds, releases, and/or changes to the item.
  - **Configuration management plan** (CM plan): A description of the roles, responsibilities, policies, and procedures for managing the configuration of the system or product.
  - **Configuration Control Board** (CCB): A group of qualified people responsible for controlling and approving changes throughout the lifecycle of a system or product; also be referred to as Change Control Board (CCB).
  - **Configuration item identification**: The methodology for selecting what items to place under configuration management and how to name them.
  - **Configuration change control**: The process for managing updates to a baseline configuration.
  - **Configuration monitoring**: The process for testing or assessing a configuration item against an established baseline and for reporting its compliance.

### Phases of SecCM
![5e6136ae-eb11-404d-adef-62f61c9301cb](https://github.com/user-attachments/assets/ef1a3ce0-45e1-4277-b5d4-5a45a03d20ab)
- Typically, SecCM phases are followed sequentially, with the monitoring phase providing oversight on the overall process. Organizations should adapt the flowchart to fit their environment’s needs. 

#### Planning
- Planning for security early in an environment can have a great impact on the success of a project later on.
- The planning phase includes developing the foundation to build a security-focused CM program, including the creation of the policy and procedures for an organization to abide by and dissemination of that information throughout the organization.
- The policy addresses the implementation of SecCM plans, integration into existing security programs, frequency and personnel involved in CCBs, the tools and technology used in change control processes, the organization’s use of baseline configurations, and the methods for monitoring compliance to the CM plan.

#### Identifying and Implementing Configurations
- The phase of identifying and implementing configurations takes the baseline configurations approved during the planning phase and starts their implementation throughout the organization.
- For a typical system, the baseline codifies the configuration item’s **settings**, **software versions**, **physical or logical arrangement**, and **required security controls**.
- Where possible, a baseline configuration is applied via automation to ensure uniformity. 

#### Controlling Configuration Changes
- Change is inevitable to an organization and its systems, which makes the phase of controlling configuration changes one of the most difficult to handle.
- This phase addresses how future changes to a baseline are managed while maintaining the security of the baseline.
- With SecCM, organizations ensure that changes are formally identified, proposed, reviewed, analyzed for security impact, tested, and approved prior to implementation.
- To maintain the secure integrity of a system, organizations typically enforce strict change time windows, employ access restrictions to who can implement a change, and maintain audit records to capture unauthorized and/or undocumented changes to a system.

#### Monitoring
- The monitoring phase is responsible for validating that a system is adhering to the prescribed organizational policies, procedures, and secure baselines.
- Monitoring helps to uncover new risks to an organization by identifying unauthorized or undocumented changes.
- SecCM monitoring is accomplished through assessment and reporting activities.
- Where possible, automation should be used to report and possibly correct on deviations from an established baseline.
- Monitoring can also support metrics gathering that can be used to provide quantitative evidence that a SecCM program is meeting its goals or needs to be tuned. 

### Types of Changes
- While an organization audits its systems for changes during the monitoring phase, it will likely come across changes that are determined to be unauthorized.

#### Authorized Changes
- Authorized changes refer to changes that have **gone through the prescribed change control process** and have been **implemented or are pending implementation**.
- Examples of a change that would undergo approval include installation of new Commercial Off-the-Shelf (COTS) software, a new networking device (for example, a router, switch, firewall, or VPN gateway), and an upgrade of an existing Database Management System (DBMS).
- It is also important for an organization to designate in its CM plan any changes that do not require change control.
- These types of changes are deemed preapproved. Examples of preapproved changes vary from organization to organization but may include database content updates, removal of temporary files, and creation/deletion of new low-privileged users. 

#### Unscheduled or Unauthorized Changes
- Even organizations with robust and well-followed CM plans undoubtedly encounter changes not officially approved or controlled.
- Sometimes an activity, such as installing patches outside a configuration change control process, can have a significant impact on a system’s security posture.
- This may happen for various reasons, such as the change’s being conducted as a result of a critical vulnerability discovered on a system.
- This would be considered an unscheduled (or emergency) change.
- Whenever an unscheduled change occurs, it is incumbent on the system owners to document and review the change, even after the fact. 

- Other times, a change activity may be deemed unauthorized.
- Unauthorized changes may occur when a system administrator makes a change but is unaware that the change requires a prescribed change control process.
- Unauthorized changes may also occur maliciously and may be an indicator of a compromise.
- Examples of a malicious change are an attacker’s enabling Remote Desktop Services (RDS), modifying a system’s password policy so that passwords never expire, and disabling the antivirus on a user’s workstation.
- All authorized changes become a part of the system’s new baseline configuration, creating a “known-good” snapshot of the system, and marking a potential rollback, or restore point, for a system to return to if the need arises. 

### Security Impact Analysis
- According to NIST SP 800-128, security impact analysis is “the analysis conducted by qualified staff within an organization to determine the extent to which changes to the system affect the security posture of the system.”
- Within the CM plan, an organization should include the specific requirements that a change must be tested and scrutinized against in a security impact analysis.
- Security impact analysis occurs during the “controlling configuration changes” phase of SecCM, when designated personnel in an organization analyze and evaluate changes for adverse effects and then submit the analysis to a CCB for review, preferably prior to the change’s being implemented.
- However, security impact analysis may also occur after an unscheduled change.
- Designated personnel should conduct a security impact analysis after any change is implemented in order to verify that the change was completed as planned, with no unanticipated impacts to the environment’s security controls.

#### Conducting a Security Impact Analysis
- Once a determination is made that a change request requires a security impact analysis, qualified staff in an organization follow the five steps listed below, according to NIST SP 800-128:
1. Understand the change.
   - The first step in analyzing a change is understanding it.
   - This is accomplished best by developing a high-level overview of the change and highlighting how the change will modify the configuration item’s present state.
   - The analysts conducting the security impact analysis should review any available documentation (for example, architectural diagrams, network maps, and audit records) and interview the change owners to gain as much insight as possible into the change.
   - This step helps to dictate many of the activities further in the security impact analysis. 
3. Identify vulnerabilities.
   - To the extent possible, a security impact analysis must identify and discover any vulnerabilities that the change may introduce into the changed component.
   - This step takes varying forms, depending on the proposed change.
   - For example, for a change involving the installation of a COTS hardware or software product, this step likely includes a search of the National Vulnerability Database (NVD) for any known vulnerabilities related to the product.
   - Additional vulnerability analysis may include a Dynamic Application Security Test (DAST) scan of the product and a secure source code review, if the code is available.
   - More than just focusing on the individual component being changed, a security impact analysis should review how the change may affect the whole system.
   - To get this holistic view, an organization may create a threat model to highlight any threats that would result after the change is implemented.
5. Assess risk.
   - A change may introduce a new risk to the organization, but that does not necessarily mean that the change will be rejected. However, once a vulnerability is identified, a risk assessment of the vulnerability must be conducted. This risk assessment should capture the impact of the vulnerability, based on the likelihood of the threat occurring and the criticality of the system if exploited. The organization may choose to follow a risk management framework described in detail in the Risk Mitigation Plan lesson of the Cyber Defense Analyst – Basic (CDA-B) course, such as NIST’s Risk Assessment Process (NIST SP 800-30, Guide for Conducting Risk Assessments) or the USCYBERCOM Risk Assessment Methodology (CWP 3-33.4, Cyber Protection Team Organization, Functions, and Employment) to document this risk assessment. The risk assessment should produce a rating (for example, low, medium, high, critical) based on the organization’s practices.
7. Assess impact on existing security controls.
   - An assessor must analyze, in particular, the impact that a change may have on existing security controls, either temporarily or permanently. For example, if a Web Application Firewall (WAF) that is responsible for filtering malicious Hypertext Transfer Protocol (HTTP) requests to a critical web server requires updating, a period may exist when the firewall cannot provide protection during the upgrade. Some permanent changes may directly impact the secure baseline configuration, such as a change in software (for example, installation of a new antivirus program). Just like during the Assess Risks step, the output of this step is to assess any new risk to the organization and develop mitigating controls as needed.
9. Plan safeguards and countermeasures.
    - Once an assessor has fully documented the risks for the change, it is up to the organization to determine the level of risk it is willing to accept or avoid. A change that has sufficient risk and cannot be altered or avoided undoubtedly requires development of mitigating controls, which are safeguards and countermeasures that reduce the risk to acceptable levels. The MITRE ATT&CK® framework publishes an extensive list of mitigations for an organization to consider. Two mitigations included in the list are protecting sensitive information with strong encryption (M1041: Encrypt Sensitive Information) and using network appliances to filter ingress or egress traffic (M1037: Filter Network Traffic).

#### Security Impact Analysis Template
- NIST 800-128, Appendix I, provides a sample security impact analysis template. Organizations are encouraged to modify the template to fit their needs. A copy of the template is attached.


## Vulnerability Based Hunts
### Threat Hunting Refresher
- Threat hunting is a proactive process to detect and separate threats that navigate past existing security functions.
- During the introduction to threat hunting, the concept of the four-phase Threat Hunting Loop was also discussed. The Threat Hunting Loop phases, in order, are as follows:
1. Creating a hypothesis.
2. Investigating the idea.
3. Uncovering new patterns and Tactics, Techniques, and Procedures (TTP).
4. Informing and enriching analytics and detection capabilities.

- Vulnerability-based hunts use vulnerabilities identified within an organization to drive the hypothesis for planning an approach to seeking threats.
- The core hypothesis is that vulnerable systems are more likely to be attacked at some point, so investigating those systems provides a greater opportunity for the analyst to uncover evidence of an attack at some point in its lifecycle.
- Once an indicator has been found, analysts are able to inform and enrich an organization’s detection and defensive capabilities through detection signatures and intelligence.

#### Added Benefits
- Although vulnerability-based threat hunting is the immediate focus of this lesson, the following are a few added benefits that apply to each role of a CPT.

#### Discovery and Counter Infiltration (D&CI)
- An understanding of what an adversary is likely to leverage in an attack aids in the ability to efficiently detect, locate, and defeat both known and unknown threats.

#### Cyber Threat Emulation (CTE)
- Understanding the process of vulnerability-based hunts provides insight into the risk-and-reward decision-making that real-world adversaries make.
- Additionally, an understanding of defensive capabilities and skills is needed to evaluate defenders and defenses.

#### Threat Mitigation
- The effect of identifying which items are most likely to be targeted assists in deciding priority areas for patching or applying other mitigating controls if a patch is unavailable or, due to system requirements, patching is not an option to address the vulnerability identified.
- Threat hunting also allows for additional opportunities to proactively identify cybersecurity inadequacies that require mitigation or improvement.
- One example of this benefit is identifying unaccounted systems that have fallen outside routine maintenance schedules needed to keep equipment functioning properly.

#### Training
- Any threat hunt that attributes observed and new TTPs of threat actors can add value to future training by maintaining documentation of those TTPs.

### Targeting Strategy
#### Network Inventory
- The act of taking network inventory is the process of accounting for all physical assets, network connections, and traffic within a mission partner’s ownership in order to gain situational awareness of the Operational Environment (OE).
- Having an accurate understanding of the mission partner’s network is critical in the success of any CPT mission.
- This is especially the case regarding vulnerability-based hunting, as any missing information causes gaps in situational awareness to accurately assess KT-C and conduct full-coverage vulnerability scanning.

#### Identifying KT-C
- Key terrain associated with cyberspace may be considered a physical node or data that is essential for mission accomplishment.
- Determining KT-C may be achieved by overlapping the mission partner’s critical assets, business functions, and key network infrastructure for both operational continuity and security.

#### Threat Assessment Reports
- Detailed threat assessment reports are commonly used in CPT operations.
- Intelligence, operations, and mission partners provide detailed information that allows CPTs to be brought up to speed on a particular network, adversary, and terrain.
- A critical component of analyzing a detailed threat assessment report is identifying what information is useful for the mission and how that information is optimally applied.
- If possible, it is beneficial to gain historical information, as activity found may be attributed to past threats.

#### Vulnerability Scanning
- Vulnerability scanning is the act of collecting system information and identifying whether that system is possibly susceptible to exploitation.
- The methods of identifying whether a system is potentially vulnerable ranges from simply identifying the version of a service to partially executing an exploit and identifying if the attempt was successful.
- The methods of scanning for vulnerabilities range from leveraging frameworks such as Nessus to more specialized tools such as Nikto or applying tools designed for a specific vulnerability.
- This lesson discusses the use of Nessus. However, it is beneficial to remember that more specialized vulnerability scanning tools exist.
- Accurate and full-coverage vulnerability scanning is dependent on an accurate network inventory.
- Whenever possible, review past vulnerability assessments and scans, as any threat activity observed may have leveraged a vulnerability that no longer exists due to the continuous changes of a live environment.

#### The Big Picture
- All the factors mentioned above should be considered when planning an approach for each vulnerability-based hunt.
- Complete network accountability is required to identify KT-C and gain an accurate assessment of which areas are vulnerable and which are more resilient within the mission partner’s network.
- Combining the information gathered with threat assessment reports helps in deciding how to prioritize the effort spent conducting analysis around vulnerable systems.
- Consider which threats are most likely and their TTPs, and then factor in how each threat’s TTPs match up with KT-C and which systems are vulnerable.
- Ultimately, no golden ratio of the factors mentioned exists, as one analyst may have a different opinion from another, so it is important to work with the team to develop a strategy.

### Identifying Indicators
- Hunt analysts must have a solid understanding of the numerous technical aspects they encounter on a mission.
- This knowledge serves as a foundation to build on with further needed research as an analyst encounters unfamiliar information during a mission.
- This section discusses strategies that aid in identifying malicious activity from network metadata.

#### Having Strong Fundamental Skills
- Arguably, the most important tool a hunt analyst has is an understanding of networking and protocol fundamentals.
- That foundation is required to gain a strong understanding of how data flows through a mission partner’s network.
- For example, does the mission partner’s network contain a proxy for their web traffic? If so, what type of proxy is it? Do other points exist where web traffic is handled? If so, how is it processed?
- Knowing how a service works, how it flows, and how it is processed within a mission partner’s network is a key factor in an analyst’s success. A few such fundamentals are described below.

##### Ports and Protocols
- What protocol, or set of protocols, does a service use?
- For instance, mail, at its core, may use SMTP. However, DNS is also used, and although the primary protocol is SMTP, a user may access their mail through a browser-based web client.
- Understanding the function and supporting mechanics behind a service that exists is needed to understand the mission partner’s network. 

##### Data Flow
- It is important to be able to identify at which points within a network data is **switched**, **routed**, **collected**, and **transformed**.
- Nodes that perform NAT and proxying change how data appears as it is collected and sent to a Security Information and Event Management (SIEM) suite.
- These nuances in how data changes as it traverses a network need to be accounted for by an analyst as they operate. 

##### Collection Points
- Depending on the situation (for example, limited storage capacity), it may be impossible to have all collection points feed into a SIEM.
- During such scenarios, an analyst may need to separately review data from individual collection points to account for any gaps in their analysis.
- Having an understanding of how service data is processed in a network aids in accounting for these gaps.
- Consider the example of how web traffic can be analyzed at any point data is collected within its flow, however, one of the best locations for web specific data analysis will be a web proxy, as it specializes in the analysis and handling of web protocols.
- This is a broad topic, and an analyst’s success is dependent on their understanding of the mission partner’s network, how data is handled within it, and which collection points handle the different services.
- An analyst should know this information to understand how activity on the mission partner’s network should look in order to identify anything unusual.

### Exploitation Indicators
- Vulnerabilities may be broken down into two main categories:
  - those that can be exploited locally
  - those that can be exploited remotely.
- An analyst must know what to look for regarding both types of exploitation categories when conducting a vulnerability-based hunt.

#### Local Exploits and Their Indicators
- Local exploits, as the name suggests, are exploits that can be triggered only from within the system being exploited.
- One of the most common examples of a local exploit is the variety of privilege escalation attacks that target Operating System (OS) mechanisms.
- Indicators of local exploitation are likely observed from endpoint detection solutions and system logs as long as the detection capabilities are sufficiently configured.
- This means that indicators from network metadata will be follow-on activity, such as Command-and-Control (C2) traffic, pivoting, reconnaissance, and exfiltration. 

#### Remote Exploits and Their Indicators
- Remote exploitation is not to be confused with remote code execution, although remote code execution exploits provide the most obvious example of remote exploitation.
- Remote exploitation is one method threat actors may leverage to gain a foothold or move laterally.
- Many IPS/IDS signatures focus on identifying this type of activity, as triggering these types of exploits requires some type of sequence or amount of data to be sent through a network in a predictable manner.
- Although network signatures are the easiest method of detecting remote exploits, they should not be relied on, as signatures need to be tuned, it is not feasible to have a signature for every exploit variant, the signature databases must be kept up to date, and the appliances that use them must be implemented correctly.
- Finally, in many instances, signatures are incapable of inspecting a remote exploit’s payload as threat actors use encryption to obfuscate their activity. 

#### Combining Exploits
- One assumption analysts may make is that vulnerabilities not labeled as critical or high are less likely to be harmful and therefore are less likely to be used by threat actors.
- Analysts should consider how the vulnerabilities uncovered on an operation may be leveraged in combination to cumulatively pose a larger risk.
- This use of several “lesser” vulnerabilities in succession is more likely to occur when an adversary is acting against a mature environment. 

- One example of combining vulnerabilities is an attack that leverages an information disclosure vulnerability combined with a file inclusion vulnerability.
- In this example, an information disclosure vulnerability is used to access path information to gain information on where uploaded files are stored.
- The location information is then used to exploit a file inclusion vulnerability to execute a previously uploaded file.
- That file contains malicious code that executes when accessed.
- The uploaded malicious file would have remained in an unknown location without the information disclosure vulnerability.

#### Observation of Exploitation Alerts
- Although vulnerability-based hunting uses vulnerability reports to identify which systems are likely to be targeted, finding evidence of direct exploitation is unlikely.
- Understanding how different types of exploits can be used to identify malicious activity not directly determined by a signature's alerts is also critical.
- Additionally, the key to gaining insight into a threat's attack path is to ask if exploitation of observed vulnerabilities is beneficial to a threat actor and how successful exploits can be used to advance their goals.

### Open-Source Research (OSR)
- Analysts should supplement their current understanding of any given situation with further research.
- Research regarding vulnerability-based hunting commonly deals with given vulnerabilities and potential indicators of malicious activity. 

#### Research on Publicly Available Exploits
- Vulnerability reports almost universally provide some type of reference to related Common Vulnerabilities and Exposures (CVEs), and such references are a great starting point for searching for publicly available exploits.
- Both code and tutorials on how to exploit vulnerabilities are highly accessible with a simple query through any search engine, using such keywords as the specific CVE and exploit or tutorial.
- Some resources are more reputable than others; the Exploit Database is a good choice. The ability to review exploit source code is beneficial in identifying what data is being sent to trigger the exploit and providing insight into what an analyst should look for during a hunt.

#### The C2 Matrix
- Understanding the tools and techniques available to adversaries is critical to an analyst’s success.
- Adversaries use some form of a C2 framework to efficiently orchestrate their efforts.
- Although more advanced adversaries use customized frameworks for this, it is important to understand how these frameworks are designed.
- To accomplish this, the C2 Matrix is a useful tool.
- The C2 Matrix catalogs many C2 frameworks and summarizes their features in a matrix.

#### Security Product Vendors and Social Media
- Many larger security product vendors have blogs that provide a reputable source of information about current topics in cybersecurity, often with varying levels of technical detail.
- Additionally, these vendors’ employees may use social media platforms to promote themselves and their companies by sharing information on their personal research in cybersecurity.
- It is beneficial for analysts to follow these sources of information to stay current with the constantly evolving battlefield of cyberspace.

### Anomaly-Based Detection
- The key to anomaly-based detection is identifying anything outside well-defined patterns.
- An observed baseline of network behavior, the defined rules of a protocol, inventoried devices, system and service uptime, and even documented problems are all well-defined patterns with regard to threat hunts.
- The following are items to consider when using an anomaly-based detection strategy.

#### Traffic Volume
- The fluctuation of traffic volume normally falls within a predictable pattern in any given 24-hour period.
- Any deviation from that pattern is of interest and can indicate a range of things, including **C2 traffic**, **reconnaissance**, **lateral movement**, **data staging for exfiltration**, **data exfiltration**, or **tool staging**.
- Much of the context is **dependent on such factors** as whether an **established baseline exists**, **how current that baseline is**, **network accountability**, and **perspective of the statistical information**, such as **ingress/egress or internal/external** traffic.

#### Data Flow
- The direction of communication and context of data flow may be an indicator of abnormal activity.
- Is a server acting as a client for a system that is identified as a workstation? Is peer-to-peer traffic standard or unusual?
- Abnormal flow of communications may indicate **lateral movement**, **pivoting**, Man-in-the-Middle (**MitM**) or **spoofing attacks**, or **C2 chains**.

#### Protocol Standards
- Protocol standards are documented through Requests for Comments (**RFC**).
- However, their implementation in practice is left to the application designer.
- Typically, application designers adhere to the standards defined for the protocol they are working with.
- However, threats have found that certain definitions within a given protocol may be ignored in order to carry control data within them.
- Common examples of this are C2 frameworks that use (**HTTPS**) request fields to transfer data.
- Additionally, malformed protocol data may be used to trigger remote exploits.

#### Endpoint Accountability
- Although servers within an organization’s environment are fairly easy to maintain inventory of, network accountability of workstations within an organization may be challenging.
- Many security vendors provide some type of solution that tracks systems and attempts to identify any systems unaccounted for.
- However, the effectiveness of those solutions may vary.
- An unaccounted-for system may be **unpatched**, **provide an obsolete service**, **miss a mandated security solution**, or even be a **malicious device** on the network.
- Effort must be taken to identify the purpose and ownership of any unaccounted system.

#### Change Management
- Any changes outside the change management chain should be questioned.
- Attackers may make any changes they deem necessary to better enable their success.
- These changes may actually include **fixes to avoid unwanted attention of a key system**, **modifications of networking equipment** to allow access to a network, **log erasure**, or **service configuration changes** to support an effort such as an MitM attack.

#### Errors and Crashes
- Service downtime and errors may be an indication of a direct exploitation attempt, as many exploits leverage application flaws to create a preferred state of execution.
- The conditions that cause these desired flaws to be leveraged normally cause an application to crash or throw errors.
- If a device has a history of crashing or a short period of throwing errors unexpectedly, those may be indicators of exploitation attempts.


## Unauthorized Changes
### Authentication, Authorization, and Accounting
- Authentication, Authorization, and Accounting (**AAA**) is a framework for controlling and monitoring access to information systems.
- Although each component of AAA can stand on its own, implementation of all parts of the framework is vital for an effective security strategy.

#### Authentication
﻿- Authentication is the first pillar of the AAA framework.
- Authentication is the process of identifying a user, person, or other entity and validating that they are who they say they are.
- Authentication is most commonly accomplished by an entity’s possession of an assigned set of credentials that is unique to them (for example, a username and password).
- When a system needs to validate a user’s identity, the user provides their unique credentials, and the credentials are checked against an authentication database.
- If the provided credentials match the credentials in the database, the user is authenticated.
- Although the use of usernames and passwords is the most common type of authentication, many other forms of authentication credentials exist.
- Each type of authentication mechanism has its own unique characteristics and capabilities.

#### Authorization
﻿- After a user’s identity has been validated, the next part of the AAA framework is determining what actions the user is allowed to perform. 
- Authorization is the process of determining the level of access and authority permitted for an authenticated user.
- Numerous approaches to authorization exist, but, simply put, authorization revolves around managing the rights that specific authenticated entities possess.
- For example, a standard user of a computer may not be authorized to install software on a computer.
- If the user attempts to install software, authorization has the role to determine if the action is allowed and, if it is not, to prevent the action from occurring.

#### Accounting
﻿- Accounting is the final component of the AAA framework. 
- Accounting is the process of logging and monitoring activities conducted by users.
- Examples of logged activities include user authentications (both valid and invalid), actions taken by users, the length of time users are connected, where users are connected from, and the amount of network resources consumed.
- The purpose of accounting is to log activities so they may be investigated from a security context if required in the future.
- Because user activity often occurs across numerous network devices and systems, it is common to aggregate accounting logs to a central repository (such as a [SIEM] system).

### Overvew of AAA Implementation
- AAA is simple as a concept, but it is often much more difficult to implement.
- Modern information systems and networks can be quite complex.
- Additionally, a user’s actions can span multiple segments and devices within a network. Consider the following example:
  - A user remotely logs in to their organization’s internal systems via a Virtual Private Network (VPN).
  - They log in by providing their credentials and two-factor authentication code.
  - Once the user has been authenticated and connects to the VPN, they access files on an internal file server.

- Although the above example sounds routine and simple, this example becomes rather complex in the scope of AAA, including such steps as the following:
  - The VPN gateway must be able to verify the user’s credentials against a central authentication system.
  - Once the credentials are verified and the user is connected, the file server must determine if the user is authorized to access the files they are attempting to open.
  - To accomplish accounting, all the disparate systems and devices must be able to forward log data to a central repository. 
- Such complexity continues to increase with the size and sophistication of the underlying network and information systems.

#### Identity and Access Management
- Identity and Access Management (**IAM**) is a framework of policies and technologies that **establish user identities and permissions within an enterprise**.
- An effective IAM program is crucial to an effective AAA implementation, as the following explains.
- IAM speaks primarily to the first two tenets of AAA: authentication and authorization.
- In an environment with a mature IAM posture, a central database typically exists that contains all identities (including authentication credentials) and roles (authorization privileges).
- For effective AAA, all systems that require any form of authentication or authorization should verify credentials and privileges to the central database. 
- In a mature IAM implementation, the underlying systems are typically implemented into other business and personnel processes.
- This depends on the people, processes, and technology that are implemented within an organization; however, understanding this workflow is critical to understanding IAM.
- In larger organizations, it is common for IAM technologies to be implemented with other business systems, such as Human Resource Management (HRM) systems.
- In this type of configuration, accounts and resources may be automatically provisioned for users when they are onboarded by the HRM system.
- Actions that occur in the HRM system can affect the authorization level of the user, up to and including a user’s termination.

#### AAA Protocols
- Standardized network and application protocols exist for the purposes of accomplishing AAA.
- Two common AAA protocols are **Remote Authentication Dial-In User Service (RADIUS) and Terminal Access Controller Access Control System (TACACS)**.
- These protocols enable centralized AAA within an environment and establish standardized communication and transport mechanisms for handling authentication and authorization requests.
- Servers running such services as RADIUS or TACACS provide accounting by logging authentication and authorization transactions.
- Consider the following example of the RADIUS protocol:
  - A user wants to use their organization’s enterprise wireless network.
  - The user finds the correct wireless network on their system and attempts to connect.
  - Before the user is able to establish a connection to the network, they must first provide their enterprise credentials.
  - Once the credentials are provided, the wireless access point acts as a RADIUS client by forwarding the authentication credentials to a RADIUS server.
  - The RADIUS server compares the received credentials against a central database and, if valid, returns an Access-Accept message to the RADIUS client.
  - This information is also logged on the RADIUS server.
  - Upon receiving the accept message, the wireless access point allows the user to establish a connection. 
- As illustrated above, the RADIUS server logs authentication information and requests.
- This accomplishes accounting under the AAA umbrella.
- Accounting logs typically contain information about authentication and authorization requests and often contain various data elements.
- The elements contained in the log are often unique to specific devices or configurations within a network.
- Figure 4.3-1 provides an example of an account log from a RADIUS server:
  <img width="575" height="541" alt="9ae0d5e0-fdcf-4de2-9615-35a76dc6566f" src="https://github.com/user-attachments/assets/5b5431bc-823c-4075-bbc5-d349685bb98a" />

- The RADIUS accounting log in Figure 4.3-1 indicates the start of a session for two different users.
- Information from RADIUS accounting logs can be used in a forensic investigation when necessary.
- For instance, the User-Name field indicates the user who is the subject of the authentication request.
- The NAS-IP-Address field indicates the Internet Protocol (IP) address of the device that sent the authentication request (such as a router, switch, or VPN). 

#### Log Aggregation
- In the scope of AAA, accounting consists of logging session information and statistics.
- A variety of session information exists and can be used for various purposes
- For the purpose of security and within the scope of AAA, common accounting data points include the following:
  - The user/identity performing the activity.
  - How and where the user is connecting to the resource (such as internal network, VPN, or IP address).
  - The time of access of any network resources.
  - What network resources were accessed.
- In complex networks, the data elements listed above often span infrastructure.
- For effective use of this information in a security context, it needs to be readily available without having to extrapolate data from numerous endpoints.
- This is accomplished through **log aggregation**.
  - **Log aggregation** is the process of consolidating and standardizing log information across an environment.
  - In an environment with log aggregation in place, in-scope systems (such as authentication services, VPN gateways, file servers, and network infrastructure) forward system log information to a central repository (such as a SIEM system).
  - This system normalizes and stores the log data so that all log data (even data from disparate systems) can be searched and analyzed in a single location.
  - **Log aggregation** is foundational for being able to **track changes**, **especially unauthorized ones**, within an environment.
  - Effective log aggregation **leaves a forensic trail** when changes are executed.
  - Having a forensic trail enables analysts to research changes after the fact and re-create the steps that led to the change.
  - This significantly aids in investigating changes that are potentially unauthorized.

### Log Aggregation Concepts
#### Log Sources
- Identification of the log sources to aggregate must be determined prior to configuration of the aggregation itself.
- Determining what logs to aggregate can be a daunting task, as numerous types of logs and source devices exist, especially within complex networks.
- Incorporating too few log sources can lead to important data being missed; incorporating too many sources can add a significant amount of noise and lead to log fatigue.
- Determining what logs to aggregate can usually be done by answering the following questions:
  - Which systems or devices need to forward log data?
  - What types of log data on each system or device are important in a security context and should be forwarded?

- Consider a Windows server. By default, multiple types of logs are available on a Windows server; there is a system log, an application log, and a security log.
- Although each type of log has a distinct purpose, it does not always make sense to aggregate all these log types.
- Based on the requirements of the network and system at hand, it may make sense to forward and aggregate only security logs.
- Knowledge of the underlying network, as well as of its applications and services, is critical to determining the proper logs to aggregate.

#### Log Aggregation Configuration
- Once in-scope systems and logs have been identified, log aggregation itself must be configured.
- Specific log aggregation configuration varies between environments and the tools in use, but the concepts behind the technical workings of log aggregation are consistent.

##### The Log Aggregator
- Before configuring any systems or devices to forward log data, the aggregator must be configured.
- Although different tools work differently behind the scenes, many tools share common characteristics, and the same configuration items typically must be determined.
- The following are common questions and configurations that must be answered for log aggregation:
  - What platform is used for log aggregation, and what is its deployment architecture?
  - What system or device hosts the log aggregation platform?
  - Where are aggregated logs to be stored? Is sufficient storage in place for the desired amount of log retention?
  - Where is the log aggregator located logically within the network? Are additional forwarding nodes required based on network requirements and controls?

- Although inner workings vary between tools, many platforms consist of a central repository for log data and one or more forwarding nodes that are responsible for receiving log data from endpoints and forwarding it to the central repository.
- **Forwarding nodes** are typically used in **complex environments** where either the **number of endpoints is very large or network security controls are strict** between different segments of a network. 

- When configuring log aggregation, determination of the desired log data retention period is important.
- Log retention periods are often dictated by policies.
- Because the amount of disk space required for log retention relies on numerous variables (primarily the number of endpoints for which logs are being received and the quantity of log messages from those endpoints), no simple formula exists to determine this amount.
- When log aggregation is first configured and established, the amount of disk space used by the log repository should be monitored over time and adjusted to fit the needs and requirements of the mission partner network.

##### Sending and Receiving Logs
- Once an aggregator has been established within an environment, it must be configured to receive logs from the various log sources within the target network.
- Again, the specific configuration varies between different log aggregation platforms, but configuration concepts are typically similar.

- Because log sources may come from any number of different devices and log messages are formatted differently across those devices, the aggregator must be configured for the specific log sources to be received.
- This configuration usually includes details on how to normalize the log message (so that the data contained within a log from a specific source can be standardized with log data from other sources) and in what manner to expect the logs (what device the logs are coming from and over what protocol, such as syslog).

- Once the aggregator has been configured to accept logs for a particular source, the endpoint-generating logs must be configured to forward the logs to the aggregator.
- Different techniques are available to accomplish log forwarding, and the available techniques may vary by device, but the vast majority of devices support sending log information via the syslog protocol.
- Regardless of the protocol being used, the endpoint in question should be configured to forward logs via a mutually available protocol or method that is present for both the endpoint and log aggregator.

##### Alerting and Monitoring
- Forwarding of log data to a central repository is important, but it is not useful or actionable when proper monitoring and alerting parameters are not configured.
- Such sophisticated platforms as fully featured SIEMs often have built-in monitoring and alert rules that can be leveraged.
- Other platforms may require that monitoring rules be configured from scratch. 

- Although options vary, it is important to set up monitoring and alerting in a way that is practical for the environment and network in question.
- Enabling too many alerting features can result in alert fatigue, when an overwhelming number of alerts desensitize those tasked with responding to the alerts.
- This can cause actionable alerts to go unnoticed.
- On the contrary, having too few alerting features enabled can cause important events to not be alerted on, allowing potential unauthorized changes, breaches, or compromises to go unnoticed.

- Choosing the right alerts to configure is subjective, based on the security requirements of an environment.
- Environments where a stricter level of control or security is required usually have a higher level of alerting and monitoring in place.
- It is also common for policies and standards to dictate certain types of monitoring that must be in place.

- Although no exact formula exists to determine what to implement in the way of monitoring, there are several considerations that should be made from a security and AAA context.
- Examples of such considerations include the following:
  - **Suspicious authentication behavior and patterns**.
    - Repeated unsuccessful authentication attempts (especially if followed by successful authentication).
    - Successful authentication from suspicious or unusual locations.
    - Authentication attempts (successful or unsuccessful) to privileged systems or systems not typically accessed by users.
  - **Potentially unauthorized behavior**.
    - Attempted or unauthorized access to privileged or critical systems.
    - Changes made to privileged or important systems.
    - Suspicious network traffic and activity (such as unexpected activity between disparate systems).
  - **Potentially malicious behavior**.

- Having in-depth knowledge of the system or network in question can also help in determining events to alert on.
- Given this knowledge, determining what is important on a personal level is also an effective approach to implementing sufficient monitoring. 

### Identifying and Responding to Changes
- CPTs are responsible for monitoring and responding to changes.
- When effective AAA practices are in place with sufficient logging and alerting, CPT operators are empowered with the necessary resources to contextualize events.
- Effectively responding to events requires critical thinking and a thorough understanding of the environment being operated in.
- Although effective logging can help fill information gaps when investigating activity, a full understanding of the environment and the ability to ask probing questions to get to the root of an alert are critical.

#### Understanding and Evaluating Changes
- Changes occur within networks frequently.
- Some changes may be well thought out, planned, and authorized, but others may not.
- The ability to think critically about the change that occurred and ask probing questions can help in determining if the change in question was authorized.

##### Identifying and Understanding the Change
- When notified or alerted of a change that is occurring, the first step in responding to the change is understanding the nature and scope of the change.
- Although some changes may seem simple on the surface, they often have higher-order consequences that are not always obvious.
- Consider the following example:
  - A change is requested to allow devices in subnet A to access a specific device in subnet B on TCP port 80.
  - The change is implemented on the firewall between the two subnets to allow any device in subnet A to access any device in subnet B on TCP port 80.
- The change request stated that devices in subnet A need to access a specific device in subnet B on TCP port 80, but the change was implemented to allow access to any device in subnet B on port 80.
- The request was met, but the change has potentially higher-order consequences. Critical thinking in such a scenario is thus highly important.
- It is not obvious in the above example that other devices may exist within subnet B that are outside the scope of the intended change.
- With the change implemented as described, unintended access is being granted to other devices within subnet B on port 80.
- If an out-of-scope device in subnet B is running a service on port 80, that service may now be unintentionally accessible to devices in subnet A.
- This also opens up the potential for vulnerabilities and compromise, especially if systems that are not in scope are running vulnerable software that could be impacted by the change.

##### Was the Change Authorized?
- Once the change is understood, it must be determined whether the change was authorized.
- An authorized change is a change that has been requested, planned, vetted, approved, and correctly implemented by an authorized individual.
- In most organizations, changes are vetted through a formal change management process.
- Change management usually follows a standardized approach and implements a common framework (such as [NIST] SP 800-128, Guide for Security-Focused Configuration Management of Information Systems).
- In networks with formal change management in place, it must be determined if the change was properly implemented via the change management policy and process.
- The first step of validating whether a change is authorized is to determine if the change that was implemented matches a formal request or need for the change.
  - Change management processes often factor in potential consequences and lay out a detailed plan and strategy for how the change should be implemented.
  - In the previous example, the intent of the requested change was met, but the implemented change was far broader than intended.
  - In this case, the change itself may have been authorized, but it was not implemented in the correct manner.
  - This should be brought to the appropriate team’s attention for scrutiny.
- Changes sometimes occur outside the scope of a formal change management process.
- This does not necessarily mean that the change was not authorized, but it does mean that the change should be examined. 
