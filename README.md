<!--
SPDX-FileCopyrightText: (c) 2025 Crown Copyright, Government of Canada (Canadian Centre for Cyber Security / Communications Security Establishment)
SPDX-License-Identifier: MIT
-->

# Network Traffic Exploration

> [!CAUTION]
> This repository contains inactive but real malware. Please handle carefully.

This project will revisit the
[U.S. National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition (MACCDC) 2012](https://www.netresec.com/?page=MACCDC)
network traffic dataset.
How would new tools and fresh ideas perform on this legacy dataset?
Do you have an inquisitive or a detective mind?
Do you have a cool idea for a big data project?
Or just curious to know more?
Please join us on this exploration!

If you are a Canadian citizen interested in working on similar projects,
consider applying at <https://www.cse-cst.gc.ca/en/careers/>


## Prerequisites

- Minimum: **60 GB** free disk space to decompress all the project files.
  Recommended: **120 GB** free disk space as workspace.
- Git LFS (i.e. Git Large File Storage).
- _OPTIONAL: Docker Compose or Podman Compose for rebuilding the artefacts._

### Install Git LFS

| Operating System | Procedure |
|:---------------- |:---------------------- |
| Archlinux        | `sudo pacman -S git-lfs` |
| Debian/Ubuntu    | `sudo apt update && sudo apt install git-lfs` |
| macOS            | `brew install git-lfs` |
| Redhat/Fedora    | `sudo dnf install git-lfs` |
| SLES/openSUSE    | `sudo zypper install git-lfs` |
| Windows          | Install [Git for Windows](https://gitforwindows.org/). Git LFS support is included by default. |


## Directory Structure

* [config/](./config) contains Suricata configuration files for building Suricata container image.
* [docker/](./docker) contains Docker files for building Suricata container image.
* [logs/](./logs) contains network event log files.
* [pcaps/](./pcaps) contains PCAP files from [U.S. National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition (MACCDC) 2012](https://www.netresec.com/?page=MACCDC).


## Some Project Ideas

- Draw the network map (e.g. IP addresses, hostnames, OS types, running services).
  Which attacking machine was the most aggressive?
  Which defending machine was the most attacked?
  Reconstruct the timeline of what happened.

- What traffic should not be here?
  Find evidence of weak security practices (i.e. not necessarily malicious).
  Notice the dataset is from 2012.
  The best security practices at that time, may not be what is recommended today.

- Improve the default Suricata rules.
  Mitigate the number of False Positive (FP) alerts and False Negative (FN) misses.

- Build and/or deploy tools that will help to analyze or visualize the network data
  (e.g automated PCAP ingestion, machine learning assisted summarization).


## Useful Resources

- Arkime.com, [Arkime - Network Analysis & Packet Capture](https://arkime.com/).
- Australian Signals Directorate (ASD), [Constellation - Data Visualisation and Analytics Software](https://www.constellation-app.com/).
- Canadian Centre for Cyber Security (CCCS), [Assemblyline 4 - Automated malware analysis framework](https://cybercentrecanada.github.io/assemblyline4_docs/).
- Canadian Centre for Cyber Security (CCCS), [CaRT (Compressed and RC4 Transport)](https://github.com/CybercentreCanada/cart/).
- Cybersecurity & Infrastructure Security Agency (CISA), [Malcolm - A powerful, easily deployable network traffic analysis tool suite for network security monitoring](https://cisagov.github.io/Malcolm/).
- Elastic.co, [Analyzing Network Packets with Wireshark, Elasticsearch, and Kibana](https://www.elastic.co/blog/analyzing-network-packets-with-wireshark-elasticsearch-and-kibana/), 2017-2019.
- Github.com, [Installing Git LFS](https://docs.github.com/en/repositories/working-with-files/managing-large-files/installing-git-large-file-storage).
- Government Communications Headquarters (GCHQ), [CyberChef - The Cyber Swiss Army Knife](https://github.com/gchq/CyberChef/).
- Open Information Security Foundation (OISF), [Suricata Eve JSON Format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).
- Security Onion Solutions, [Security Onion Documentation](https://docs.securityonion.net/en/2.4/).
- Tutte Institute for Mathematics and Computing (TIMC), [This Not That - A Data Map Exploration Tool](https://thisnotthat.readthedocs.io/en/latest/).
- Wireshark.org, [Wireshark Training Documentation](https://www.wireshark.org/docs/).
- Zeek.org, [Zeek Documentation](https://docs.zeek.org/en/current/).
