- Ingress/Egress Configs (Which direction is the traffic going?) 

## Splunk Forwarders
- There are three different types of Splunk forwarders:
  - **Universal** forwarder: Contains only the components that are necessary to forward data. A universal forwarder has no indexing or data searching capability; however, they have the smallest system resource usage.
  - **Heavy** forwarder: Parses data before it is forwarded and routes data based on criteria like source or event type.
    - A heavy forwarder also indexes data locally and forwards to another Splunk instance.
    - With all these features, a heavy forwarder consumes the most system resources.
  - **Light** forwarder: Sacrifices additional capabilities found in heavy forwarders for the sake of preserving system resources.
- No indexing or data parsing is performed and is used only to forward data to Splunk instances.
- A light forwarder is generally used only in legacy applications.

### D﻿ata Types
- The primary use case for these forwarders is in a network environment that feeds data collection to a Splunk Enterprise instance.
- There are three different types of data that these forwarders transmit
  - **Raw**: The forwarder sends unaltered data over a Transmission Control Protocol (TCP) stream.
    - It does not convert the data into a Splunk communication format.
    - The forwarder simply collects data and sends it, which is useful for sending data to non-Splunk systems.
  - **Unparsed**: No transformations are done to the data; however, the data is tagged with a source, source type, and host information.
    - The data stream is also divided into blocks and timestamped for easier categorization by the receiving indexer.
  - **Parsed**: This data is broken down into individual events, which are then tagged and forwarded.
    - Because the data has been parsed, the forwarder can perform conditional routing based on specific data found in the events.
    - Both universal and heavy forwarders are capable of sending raw data. However, unparsed data is used for universal forwarders and parsed data is used for heavy forwarders.

### Advanced Features and Configurations
- Many advanced features are used with Splunk forwarders to help increase their capabilities.
- Such features include data parsing, which allows the performance of event and field extractions.
- Searching and alerting allows alert generation and pre-instance searching for heavy forwarders.
- Load balancing forwards data over multiple paths to alleviate any congestion in network traffic that may occur.
- Event filtering analyzes each event and only forwards data that meets filter criteria.
- Once a Splunk forwarder is downloaded from the Splunk website, it can be installed.
- The installation wizard provides opportunities for a username and password to be configured, as well as an endpoint specified to receive forwarded data.
- Additionally, a receiving indexer can be configured.
- There are four key Splunk universal forwarder configuration files:
  - **inputs**.conf controls how the forwarder collects data.
  - **outputs**.conf controls how the forwarder sends data to an indexer or other forwarder.
  - **server**.conf controls connection and performance tuning.
  - **deploymentclient**.conf controls connecting to a deployment server.
- The configuration files of the universal forwarder can be edited at the installation location, C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local


## Kibana Netflow Data
### NetFlow Data Ingestion
- The Filebeat NetFlow module listens on a configured port ([UDP] or [TCP]) for incoming raw NetFlow data from these devices.
- When NetFlow records arrive, the Filebeat NetFlow module normalizes and enriches them into one of the nine data types described above, saving the data into netflow.log.
- It then forwards the normalized records to Elasticsearch for long-term storage and analysis.

### Log Generation and Processing
- Filebeat processes the incoming NetFlow data using a pipeline.
- The ingested NetFlow data is broken into hundreds of fields, depending on the NetFlow version and the values present in the data.
- Each field has an associated data type.
- For example, netflow.destination_ipv4_address is an ip type, and netflow.destination_transport_port is an integer type.
- The pipeline performs field extraction, parsing, and normalization to create structured records with predefined fields.
- Common fields that may be used to perform NetFlow queries include, but are not limited to, the following:
  - event.action: netflow_flow
  - event.dataset: netflow.log
  - event.module: netflow
  - flow.id: (random assigned id)
  - input.type: netflow
  - netflow.destination_ipv4_address
  - netflow.destination_transport_port
  - NetFlow Search Queries
- View entire count of NetFlow data: `* | groupby event.dataset`
- Show Source IP with highest occurance: `* | groupby event.dataset netflow.source_ipv4_address`
- Add an additinal column for desination IP" `* | groupby event.dataset netflow.source_ipv4_address netflow.destination_ipv4_address`
- View source port numbers: `* | groupby event.dataset netflow.source_transport_port`
- Create a column of destination ports: `* | groupby event.dataset netflow.source_transport_port netflow.destination_transport_port`

### NetFlow Queries Using Kibana
- Query for NetFlow data: `event.dataset: "netflow.log"`
- Add the following fields to the output: `source.ip, destination.ip, source.port, destination.port`
- Refine search to identify IP addresses using port 0: `event.dataset: "netflow.log" and (netflow.source_transport_port: 0 and netflow.destination_transport_port: 0)`
- Search for flows larger than .095MB or larger than 100,000 bytes: `event.dataset: "netflow.log" and network.bytes > 100000`
