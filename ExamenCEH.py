import random
import os

print("""
::::'######::'########:'########::'########:'####:'########:'####:'########:'########::::::::'########:'########:'##::::'##:'####::'######:::::'###::::'##::::::::::'##::::'##::::'###:::::'######::'##:::'##:'########:'########:::::
:::'##... ##: ##.....:: ##.... ##:... ##..::. ##:: ##.....::. ##:: ##.....:: ##.... ##::::::: ##.....::... ##..:: ##:::: ##:. ##::'##... ##:::'## ##::: ##:::::::::: ##:::: ##:::'## ##:::'##... ##: ##::'##:: ##.....:: ##.... ##::::
::: ##:::..:: ##::::::: ##:::: ##:::: ##::::: ##:: ##:::::::: ##:: ##::::::: ##:::: ##::::::: ##:::::::::: ##:::: ##:::: ##:: ##:: ##:::..:::'##:. ##:: ##:::::::::: ##:::: ##::'##:. ##:: ##:::..:: ##:'##::: ##::::::: ##:::: ##::::
::: ##::::::: ######::: ########::::: ##::::: ##:: ######:::: ##:: ######::: ##:::: ##::::::: ######:::::: ##:::: #########:: ##:: ##:::::::'##:::. ##: ##:::::::::: #########:'##:::. ##: ##::::::: #####:::: ######::: ########:::::
::: ##::::::: ##...:::: ##.. ##:::::: ##::::: ##:: ##...::::: ##:: ##...:::: ##:::: ##::::::: ##...::::::: ##:::: ##.... ##:: ##:: ##::::::: #########: ##:::::::::: ##.... ##: #########: ##::::::: ##. ##::: ##...:::: ##.. ##::::::
::: ##::: ##: ##::::::: ##::. ##::::: ##::::: ##:: ##:::::::: ##:: ##::::::: ##:::: ##::::::: ##:::::::::: ##:::: ##:::: ##:: ##:: ##::: ##: ##.... ##: ##:::::::::: ##:::: ##: ##.... ##: ##::: ##: ##:. ##:: ##::::::: ##::. ##:::::
:::. ######:: ########: ##:::. ##:::: ##::::'####: ##:::::::'####: ########: ########:::::::: ########:::: ##:::: ##:::: ##:'####:. ######:: ##:::: ##: ########:::: ##:::: ##: ##:::: ##:. ######:: ##::. ##: ########: ##:::. ##::::
::::......:::........::..:::::..:::::..:::::....::..::::::::....::........::........:::::::::........:::::..:::::..:::::..::....:::......:::..:::::..::........:::::..:::::..::..:::::..:::......:::..::::..::........::..:::::..:::::
'########::'######::::::::::::'######:::'#######::'##::::'##:'##::: ##::'######::'####:'##:::::::::::::::::'######::'##:'########:'##::::'##::::'########:'########::'######::'########::::'########:'##::::'##::::'###::::'##::::'##:
 ##.....::'##... ##::::::::::'##... ##:'##.... ##: ##:::: ##: ###:: ##:'##... ##:. ##:: ##::::::::::::::::'##... ##: ##: ##.....:: ##:::: ##::::... ##..:: ##.....::'##... ##:... ##..::::: ##.....::. ##::'##::::'## ##::: ###::'###:
 ##::::::: ##:::..::::::::::: ##:::..:: ##:::: ##: ##:::: ##: ####: ##: ##:::..::: ##:: ##:::::::::::::::: ##:::..:: ##: ##::::::: ##:::: ##::::::: ##:::: ##::::::: ##:::..::::: ##::::::: ##::::::::. ##'##::::'##:. ##:: ####'####:
 ######::: ##:::::::'#######: ##::::::: ##:::: ##: ##:::: ##: ## ## ##: ##:::::::: ##:: ##:::::::::::::::: ##:::::::.##: ######::: #########::::::: ##:::: ######:::. ######::::: ##::::::: ######:::::. ###::::'##:::. ##: ## ### ##:
 ##...:::: ##:::::::........: ##::::::: ##:::: ##: ##:::: ##: ##. ####: ##:::::::: ##:: ##:::::::::::::::: ##:::::::'##: ##...:::: ##.... ##::::::: ##:::: ##...:::::..... ##:::: ##::::::: ##...:::::: ## ##::: #########: ##. #: ##:
 ##::::::: ##::: ##:::::::::: ##::: ##: ##:::: ##: ##:::: ##: ##:. ###: ##::: ##:: ##:: ##:::::::::::::::: ##::: ##: ##: ##::::::: ##:::: ##::::::: ##:::: ##:::::::'##::: ##:::: ##::::::: ##:::::::: ##:. ##:: ##.... ##: ##:.:: ##:
 ########:. ######:::::::::::. ######::. #######::. #######:: ##::. ##:. ######::'####: ########::::::::::. ######:: ##: ########: ##:::: ##::::::: ##:::: ########:. ######::::: ##::::::: ########: ##:::. ##: ##:::: ##: ##:::: ##:
........:::......:::::::::::::......::::.......::::.......:::..::::..:::......:::....::........::::::::::::......:::..::........::..:::::..::::::::..:::::........:::......::::::..::::::::........::..:::::..::..:::::..::..:::::..::                                                                                                                                                                                                
                                                                                                                                                                                                                                      
                                                                                          C|EH Test Exam - The Matrix flavoured
                                                                                        With +100 random questions from previous
                                                                                               exams gathered by OSINT.

""")
# --- Cuestionario (puedes ampliarlo/modificarlo) ---
cuestionario = [
    {
        "pregunta": "What is a set of extensions to DNS that provide to DNS clients (resolvers) origin authentication, authenticated denial of existence and data integrity, but not availability or confidentiality?",
        "opciones": [
            "A) Zone Transfer", 
            "B) Resource Transfer", 
            "C) Resource records", 
            "D) DNSSEC"
            ],
        "respuesta": "D",
        "explicacion": "The Domain Name System Security Extensions (DNSSEC) is a suite of Internet Engineering Task Force (IETF) specifications for securing certain kinds of information provided by DNS for use on IP networks. DNSSEC is a set of extensions to DNS provide to DNS clients (resolvers) origin authentication of DNS data, authenticated denial of existence, and data integrity, but not availability or confidentiality. DNSSEC is necessary because the original DNS design did not include security but was designed to be a scalable distributed system. DNSSEC adds security while maintaining backward compatibility."
    },
    {
        "pregunta": "Josh, a security analyst, wants to choose a tool for himself to examine links between data. One of the main requirements is to present data using graphs and link analysis. Which of the following tools will meet John's requirements?",
        "opciones": [
            "A) Metasploit.",
            "B) Maltego.",
            "C) Analyst's Notebook.",
            "D) Palantir."
        ],
        "respuesta": "B",
        "explicacion": "Maltego is a software used for open-source intelligence and forensics, developed by Paterva from Pretoria, South Africa. Maltego focuses on providing a library of transforms for discovery of data from open sources and visualizing that information in a graph format, suitable for link analysis and data mining. As of 2019, the team of Maltego Technologies headquartered in Munich, Germany has taken responsibility for all global customer-facing operations.\nMaltego permits creating custom entities, allowing it to represent any type of information in addition to the basic entity types which are part of the software. The basic focus of the application is analyzing real-world relationships (Social Networks, OSINT APIs, Self-hosted Private Data and Computer Networks Nodes) between people, groups, Webpages, domains, networks, internet infrastructure, and social media affiliations. Maltego extends its data reach with integrations from various data partners. Among its data sources are DNS records, whois records, search engines, social networking services, various APIs and various metadata.\n\nIncorrect answers:\n\nMetasploit https://en.wikipedia.org/wiki/Metasploit_Project\nThe Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.\nIts best-known sub-project is the open-source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.\nThe Metasploit Project includes anti-forensic and evasion tools, some of which are built into the Metasploit Framework. Metasploit is pre-installed in the Kali Linux operating system.\n\nAnalyst's Notebook https://en.wikipedia.org/wiki/Analyst%27s_Notebook\nIBM Security i2 Analyst's Notebook is a software product from IBM for data analysis and investigation. Based on ELP (entity-link-property) methodology, it reveals relationships between data entities to discover patterns and provide insight into data. It is commonly used by digital analysts at law enforcement, military and other government intelligence agencies, and by fraud departments.\n\nPalantir https://en.wikipedia.org/wiki/Palantir_Technologies\nPalantir Technologies is a public American software company that specializes in big data analytics. Headquartered in Denver, Colorado, it was founded by Peter Thiel, Nathan Gettings, Joe Lonsdale, Stephen Cohen, and Alex Karp in 2003. The company's name is derived from The Lord of the Rings where the magical palantíri were \"seeing-stones,\" described as indestructible balls of crystal used for communication and to see events in other parts of the world.\nThe company is known for three projects in particular: Palantir Gotham, Palantir Metropolis, and Palantir Foundry. Palantir Gotham is used by counter-terrorism analysts at offices in the United States Intelligence Community (USIC) and United States Department of Defense. In the past, Gotham was used by fraud investigators at the Recovery Accountability and Transparency Board, a former US federal agency which operated from 2009 to 2015. Gotham was also used by cyber analysts at Information Warfare Monitor, a Canadian public-private venture which operated from 2003 to 2012. Palantir Metropolis is used by hedge funds, banks, and financial services firms. Palantir Foundry is used by corporate clients such as Morgan Stanley, Merck KGaA, Airbus, and Fiat Chrysler Automobiles NV."
    },
    {
        "pregunta": "Determine the attack according to the following scenario:\nBenjamin performs a cloud attack during the translation of the SOAP message in the TLS layer. He duplicates the body of the message and sends it to the server as a legitimate user. As a result of these actions, Benjamin managed to access the server resources to unauthorized access.",
        "opciones": [
            "A) Wrapping",
            "B) Cloud Hopper",
            "C) Cloudborne",
            "D) Side-channel"
        ],
        "respuesta": "A",
        "explicacion": "Wrapping attacks aim at injecting a faked element into the message structure so that a valid signature covers the unmodified element while the faked one is processed by the application logic. As a result, an attacker can perform an arbitrary Web Service request while authenticating as a legitimate user.\nWrapping attack which uses Extensible Mark-up Language (XML) signature element in order to weaken the web servers’ validation requests. When a user requests for a service, it is interacted with using Simple Object Access Protocol (SOAP) and submitted in XML format. This type of attack usually occurs during the translation of SOAP messages in the Transport Layer Service (TLS) layer between the web server and valid user. The message body will be duplicated and sent to the server as a valid user. The hacker will copy the user’s account login details. During the login session, the hackers will inject a spurious element into the message structure. They will modify the original content with malicious code. After that, the message is sent to servers. The server will approve the message as the body is unchanged. As a result, the hackers will be able to access the server resources to unauthorized access.\n\nIncorrect answers:\n\nCloud Hopper\nhttps://www.bankinfosecurity.com/report-cloud-hopper-attacks-affected-more-msps-a-13565\nThe hacking campaign, known as “Cloud Hopper,” was the subject of a U.S. indictment in December that accused two Chinese nationals of identity theft and fraud. Prosecutors described an elaborate operation that victimized multiple Western companies but stopped short of naming them. A Reuters report at the time identified two: Hewlett Packard Enterprise and IBM.\n\nCloudborne\nAn attack scenario affecting various cloud providers could allow an attacker to implant persistent backdoors for data theft into bare-metal cloud servers, which would be able to remain intact as the cloud infrastructure moves from customer to customer. This opens the door to a wide array of attacks on businesses that use infrastructure-as-a-service (IaaS) offerings.\nAppropriately dubbed “Cloudborne” by Eclypsium, the attack vector (which the firm characterizes as a critical weakness) consists of the use of a known vulnerability in bare-metal hardware along with a weakness in the “reclamation process.”\nIn the Cloudborne scenario, an attacker can first use a known vulnerability in Supermicro hardware (present in many cloud providers’ infrastructure, the firm said), to overwrite the firmware of a Baseboard Management Controller (BMC). BMCs are a third-party component designed to enable remote management of a server for initial provisioning, operating system reinstall and troubleshooting.\n\nSide-channel https://en.wikipedia.org/wiki/Side-channel_attack\nA side-channel attack is any attack based on information gained from the implementation of a computer system, rather than weaknesses in the implemented algorithm itself (e.g. cryptanalysis and software bugs). Timing information, power consumption, electromagnetic leaks or even sound can provide an extra source of information, which can be exploited."
    },
    {
        "pregunta": "Determine what of the list below is the type of honeypots that simulates the real production network of the target organization?",
        "opciones": [
            "A) High-interaction Honeypots.",
            "B) Pure Honeypots.",
            "C) Research honeypots.",
            "D) Low-interaction Honeypots."
        ],
        "respuesta": "B",
        "explicacion": "Pure honeypots are full-fledged production systems. The attacker's activities are monitored by using a bug tap installed on the honeypot's link to the network. No other software needs to be installed. Even though a pure honeypot is useful, a more controlled mechanism stealthiness of the defense mechanisms can be ensured.\n\nIncorrect answers:\n\nLow-interaction Honeypots\nA low interaction honeypot will only give an attacker minimal access to the operating system. ‘Low interaction’ means precisely that the adversary will not be able to interact with your decoy system in any depth, as it is a much more static environment. A low interaction honeypot will usually emulate a small number of internet protocols and network services, just enough to deceive the attacker and no more. In general, most businesses simulate TCP and IP protocols, which allows the attacker to think they are connecting to a real system and not a honeypot environment.\nA low interaction honeypot is simple to deploy, does not give access to a real root shell, and does not use significant resources to maintain. However, a low interaction honeypot may not be effective enough, as it is only the basic simulation of a machine. It may not fool attackers into engaging, and it’s certainly not in-depth enough to capture complex threats such as zero-day exploits.\n\nHigh interaction honeypots\nA high interaction honeypot emulates certain protocols or services. The attacker is provided with real systems to attack, making it far less likely they will guess they are being diverted or observed. As the systems are only present as a decoy, any traffic that is found is by its very existence malicious, making it easy to spot threats and track and trace an attacker's behavior. Using a high interaction honeypot, researchers can learn the tools an attacker uses to escalate privileges or the lateral movements they make to attempt to uncover sensitive data.\n\nResearch honeypots\nResearch honeypots are run to gather information about the black hat community's motives and tactics targeting different networks. These honeypots do not add direct value to a specific organization; instead, they are used to research the threats that organizations face and to learn how to better protect against those threats. Research honeypots are complex to deploy and maintain, capture extensive information and are used primarily by research, military, or government organizations."
    },
    {
        "pregunta": "Which type of viruses tries to hide from antivirus programs by actively changing and corrupting the chosen service call interruptions when they are being run?",
        "opciones": [
            "A) Stealth/Tunneling virus",
            "B) Cavity virus",
            "C) Polymorphic virus",
            "D) Tunneling virus"
        ],
        "respuesta": "A",
        "explicacion": "Tunneling Virus: This virus attempts to bypass detection by antivirus scanner by installing itself in the interrupt handler chain. Interception programs, which remain in the background of an operating system and catch viruses, become disabled during the course of a tunneling virus. Similar viruses install themselves in device drivers.\n\nStealth Virus: It is a very tricky virus as it changes the code that can be used to detect it. Hence, the detection of the virus becomes very difficult. For example, it can change the read system call such that whenever the user asks to read a code modified by a virus, the original form of code is shown rather than infected code.\n\nNOTE: I don't know why EC-Council decided to combine 2 types of viruses into one. Nevertheless, on their exam, the Stealth/ tunneling virus (as in the book) is encountered on the exam, but I think the Tunneling virus is fine too.\n\nIncorrect answers:\n\nCavity virus\nTo avoid detection by users, some viruses employ different kinds of deception. Some old viruses, especially on the DOS platform, make sure that the \"last modified\" date of a host file stays the same when the file is infected by the virus. This approach does not fool antivirus software, however, especially those which maintain and date cyclic redundancy checks on file changes. Some viruses can infect files without increasing their sizes or damaging the files. They accomplish this by overwriting unused areas of executable files. These are called cavity viruses.\n\nPolymorphic virus https://en.wikipedia.org/wiki/Polymorphic_code\nPolymorphic code was the first technique that posed a serious threat to virus scanners. Just like regular encrypted viruses, a polymorphic virus infects files with an encrypted copy of itself, which is decoded by a decryption module. In the case of polymorphic viruses, however, this decryption module is also modified on each infection. A well-written polymorphic virus therefore has no parts which remain identical between infections, making it very difficult to detect directly using \"signatures\". Antivirus software can detect it by decrypting the viruses using an emulator, or by statistical pattern analysis of the encrypted virus body."
    },
    {
        "pregunta": "Which of the following is not included in the list of recommendations of PCI Data Security Standards?",
        "opciones": [
            "A) Do not use vendor-supplied defaults for system passwords and other security parameters.",
            "B) Rotate employees handling credit card transactions on a yearly basis to different departments.",
            "C) Protect stored cardholder data.",
            "D) Encrypt transmission of cardholder data across open, public networks."
        ],
        "respuesta": "B",
        "explicacion": "Build and Maintain a Secure Network\n1. Install and maintain a firewall configuration to protect cardholder data.\n2. Do not use vendor-supplied defaults for system passwords and other security parameters.\nProtect Cardholder Data\n3. Protect stored cardholder data.\n4. Encrypt transmission of cardholder data across open, public networks.\nMaintain a Vulnerability Management Program\n5. Use and regularly update anti-virus software or programs.\n6. Develop and maintain secure systems and applications.\nImplement Strong Access Control Measures\n7. Restrict access to cardholder data by business need-to-know.\n8. Assign a unique ID to each person with computer access.\n9. Restrict physical access to cardholder data.\nRegularly Monitor and Test Networks\n10. Track and monitor all access to network resources and cardholder data.\n11. Regularly test security systems and processes.\nMaintain an Information Security Policy\n12. Maintain a policy that addresses information security for employees and contractors."
    },
    {
        "pregunta": "Philip, a cybersecurity specialist, needs a tool that can function as a network sniffer, record network activity, prevent and detect network intrusion. Which of the following tools is suitable for Philip?",
        "opciones": [
            "A) Nmap",
            "B) Cain & Abel",
            "C) Snort",
            "D) Nessus"
        ],
        "respuesta": "C",
        "explicacion": "Snort is a free open source network intrusion detection system (IDS) and intrusion prevention system (IPS) created in 1998 by Martin Roesch, founder and former CTO of Sourcefire. Snort is now developed by Cisco, which purchased Sourcefire in 2013.\nSnort's open-source network-based intrusion detection/prevention system (IDS/IPS) has the ability to perform real-time traffic analysis and packet logging on Internet Protocol (IP) networks. Snort performs protocol analysis, content searching and matching.\nThe program can also be used to detect probes or attacks, including, but not limited to, operating system fingerprinting attempts, semantic URL attacks, buffer overflows, server message block probes, and stealth port scans.\nSnort can be configured in three main modes: 1. sniffer, 2. packet logger, and 3. network intrusion detection.\n\nSniffer Mode\nThe program will read network packets and display them on the console.\n\nPacket Logger Mode\nIn packet logger mode, the program will log packets to the disk.\n\nNetwork Intrusion Detection System Mode\nIn intrusion detection mode, the program will monitor network traffic and analyze it against a rule set defined by the user. The program will then perform a specific action based on what has been identified.\n\nIncorrect answers:\n\nNmap https://en.wikipedia.org/wiki/Nmap\nNmap (Network Mapper) is a free and open-source network scanner created by Gordon Lyon (also known by his pseudonym Fyodor Vaskovich). Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses.\nNmap provides a number of features for probing computer networks, including host discovery and service and operating system detection. These features are extensible by scripts that provide more advanced service detection, vulnerability detection, and other features. Nmap can adapt to network conditions including latency and congestion during a scan.\n\nCain & Abel https://en.wikipedia.org/wiki/Cain_and_Abel\nCain and Abel (often abbreviated to Cain) is a password recovery tool for Microsoft Windows. It can recover many kinds of passwords using methods such as network packet sniffing, cracking various password hashes by using methods such as dictionary attacks, brute force and cryptanalysis attacks. Cryptanalysis attacks are done via rainbow tables which can be generated with the winrtgen.exe program provided with Cain and Abel. Cain and Abel is maintained by Massimiliano Montoro and Sean Babcock.\n\nNessus https://en.wikipedia.org/wiki/Nessus_(software)\nNessus is a proprietary vulnerability scanner developed by Tenable, Inc."
    },
    {
        "pregunta": "Suppose your company has implemented identify people based on walking patterns and made it part of physical control access to the office. The system works according to the following principle:\nThe camera captures people walking and identifies employees, and then they must attach their RFID badges to access the office.\nWhich of the following best describes this technology?",
        "opciones": [
            "A) The solution will have a high level of false positives.",
            "B) Biological motion cannot be used to identify people.",
            "C) Although the approach has two phases, it actually implements just one authentication factor.",
            "D) The solution implements the two factors authentication: physical object and physical characteristic."
        ],
        "respuesta": "D",
        "explicacion": "The authentication factors of a multi-factor authentication scheme may include:\n· Something you have: Some physical object in the possession of the user, such as a security token (USB stick), a bank card, a key, etc.\n· Something you know: Certain knowledge only known to the user, such as a password, PIN, TAN, etc.\n· Something you are: Some physical characteristic of the user (biometrics), such as a fingerprint, eye iris, voice, typing speed, pattern in key press intervals, etc.\n· Somewhere you are: Some connection to a specific computing network or using a GPS signal to identify the location."
    },
    {
        "pregunta": "Which of the following protocols is used in a VPN for setting up a secure channel between two devices?",
        "opciones": [
            "A) PPP",
            "B) SET",
            "C) PEM",
            "D) IPSEC"
        ],
        "respuesta": "D",
        "explicacion": "Internet Protocol Security (IPsec) is a secure network protocol suite that authenticates and encrypts the packets of data to provide secure encrypted communication between two computers over an Internet Protocol network. It is used in virtual private networks (VPNs).\n\nIncorrect answers:\n\nPPP https://en.wikipedia.org/wiki/Point-to-Point_Protocol\nPoint-to-Point Protocol (PPP) is a Data link layer (layer 2) communications protocol between two routers directly without any host or any other networking in between. It can provide connection authentication, transmission encryption, and compression.\n\nPEM https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail\nPrivacy-Enhanced Mail (PEM) is a file format for storing and sending cryptographic keys, certificates, and other data, based on a set of 1993 IETF standards defining \"privacy-enhanced mail.\" While the original standards were never broadly adopted, and were supplanted by PGP and S/MIME, the textual encoding they defined became very popular. The PEM format was eventually formalized by the IETF in RFC 7468.\n\nSET https://en.wikipedia.org/wiki/Secure_Electronic_Transaction\nSecure Electronic Transaction (SET) is a communications protocol standard for securing credit card transactions over networks, specifically, the Internet. SET was not itself a payment system, but rather a set of security protocols and formats that enabled users to employ the existing credit card payment infrastructure on an open network in a secure fashion. However, it failed to gain attraction in the market. Visa now promotes the 3-D Secure scheme."
    },
    {
        "pregunta": "You know that the application you are attacking is vulnerable to an SQL injection, but you cannot see the result of the injection. You send a SQL query to the database, which makes the database wait before it can react. You can see from the time the database takes to respond, whether a query is true or false. What type of SQL injection did you use?",
        "opciones": [
            "A) Blind SQLi.",
            "B) Out-of-band SQLi.",
            "C) Error-based SQLi.",
            "D) UNION SQLi."
        ],
        "respuesta": "A",
        "explicacion": "Blind SQLi\nThe attacker sends data payloads to the server and observes the response and behavior of the server to learn more about its structure. This method is called blind SQLi because the data is not transferred from the website database to the attacker, thus the attacker cannot see information about the attack in-band.\nBlind SQL injections rely on the response and behavioral patterns of the server so they are typically slower to execute but may be just as harmful. Blind SQL injections can be classified as follows:\nBoolean—that attacker sends a SQL query to the database prompting the application to return a result. The result will vary depending on whether the query is true or false. Based on the result, the information within the HTTP response will modify or stay unchanged. The attacker can then work out if the message generated a true or false result.\nTime-based—attacker sends a SQL query to the database, which makes the database wait (for a period in seconds) before it can react. The attacker can see from the time the database takes to respond, whether a query is true or false. Based on the result, an HTTP response will be generated instantly or after a waiting period. The attacker can thus work out if the message they used returned true or false, without relying on data from the database.The attacker sends data payloads to the server and observes the response and behavior of the server to learn more about its structure. This method is called blind SQLi because the data is not transferred from the website database to the attacker, thus the attacker cannot see information about the attack in-band.\n\nIncorrect answers:\n\nError-based SQLi\nThe Error based technique, when an attacker tries to insert malicious query in input fields and get some error which is regarding SQL syntax or database.\nFor example, SQL syntax error should be like this:\nYou have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ‘‘VALUE’’. The error message gives information about the database used, where the syntax error occurred in the query. Error based technique is the easiest way to find SQL Injection.\n\nUNION SQLi\nWhen an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the UNION keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.\nThe UNION keyword lets you execute one or more additional SELECT queries and append the results to the original query. For example:\nSELECT a, b FROM table1 UNION SELECT c, d FROM table2\nThis SQL query will return a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.\nFor a UNION query to work, two key requirements must be met:\n· The individual queries must return the same number of columns.\n· The data types in each column must be compatible between the individual queries.\nTo carry out an SQL injection UNION attack, you need to ensure that your attack meets these two requirements.\n\nOut-of-band SQLi\nThe attacker can only carry out this form of attack when certain features are enabled on the database server used by the web application. This form of attack is primarily used as an alternative to the in-band and inferential SQLi techniques.\nOut-of-band SQLi is performed when the attacker can’t use the same channel to launch the attack and gather information, or when a server is too slow or unstable for these actions to be performed. These techniques count on the capacity of the server to create DNS or HTTP requests to transfer data to an attacker."
    },
    {
        "pregunta": "Which of the following tools is a command-line vulnerability scanner that scans web servers for dangerous files/CGIs?",
        "opciones": [
            "A) John the Ripper",
            "B) Kon-Boot",
            "C) Snort",
            "D) Nikto"
        ],
        "respuesta": "D",
        "explicacion": "Nikto is a free software command-line vulnerability scanner that scans web servers for dangerous files/CGIs, outdated server software, and other problems. It performs generic and server types specific checks. It also captures and prints any cookies received. The Nikto code itself is free software, but the data files it uses to drive the program are not.\n\nIncorrect answers:\n\nSnort https://www.snort.org/\nSnort is a free open source network intrusion detection system (IDS) and intrusion prevention system (IPS) created in 1998 by Martin Roesch, founder and former CTO of Sourcefire. Snort is now developed by Cisco, which purchased Sourcefire in 2013.\n\nJohn the Ripper https://www.openwall.com/john/\nJohn the Ripper is an Open Source password security auditing and password recovery tool available for many operating systems.\n\nKon-Boot https://en.wikipedia.org/wiki/Kon-Boot\nKon-Boot is a software utility that allows users to bypass Microsoft Windows passwords and Apple macOS passwords (Linux support has been deprecated) without lasting or persistent changes to system on which it is executed. It is also the first reported tool capable of bypassing Windows 10 online (live) passwords and supporting both Windows and macOS systems."
    },
    {
        "pregunta": "Which of the following application security testing method of white-box testing, in which only the source code of applications and their components is scanned for determines potential vulnerabilities in their software and architecture?",
        "opciones": [
            "A) IAST",
            "B) DAST",
            "C) SAST",
            "D) MAST"
        ],
        "respuesta": "C",
        "explicacion": "Static application security testing (SAST) is used to secure software by reviewing the source code of the software to identify sources of vulnerabilities.\nUnlike dynamic application security testing (DAST) tools for black-box testing of application functionality, SAST tools focus on the code content of the application, white-box testing. An SAST tool scans the source code of applications and its components to identify potential security vulnerabilities in their software and architecture. Static analysis tools can detect an estimated 50% of existing security vulnerabilities.\n\nIncorrect answers:\n\nDAST https://en.wikipedia.org/wiki/Dynamic_application_security_testing\nA dynamic application security testing (DAST) tool is a program which communicates with a web application through the web front-end in order to identify potential security vulnerabilities in the web application and architectural weaknesses. It performs a black-box test. Unlike static application security testing tools, DAST tools do not have access to the source code and therefore detect vulnerabilities by actually performing attacks.\nDAST tools allow sophisticated scans, detecting vulnerabilities with minimal user interactions once configured with host name, crawling parameters and authentication credentials. These tools will attempt to detect vulnerabilities in query strings, headers, fragments, verbs (GET/POST/PUT) and DOM injection.\n\nMAST\nMobile Application Security Testing (MAST) is a blend of SAST, DAST, and forensic techniques while it allows mobile application code to be tested specifically for mobile-specific issues such as jailbreaking, and device rooting, spoofed Wi-Fi connections, validation of certificates, data leakage prevention, etc.\n\nIAST\nInteractive Application Security Testing (IAST). Hybrid approaches have been around – combining SAST and DAST – but the cybersecurity industry has recently started to consider them under the term IAST. IAST tools can check whether known vulnerabilities (from SAST) can be exploited in a running application (i.e., DAST). These tools combine knowledge of data flow and application flow in an application to visualize advanced attack scenarios using test cases which are further used to create additional test cases by utilizing DAST results recursively."
    },
    {
        "pregunta": "Jack sent an email to Jenny with a business proposal. Jenny accepted it and fulfilled all her obligations. Jack suddenly refused his offer when everything was ready and said that he had never sent an email. Which of the following digital signature properties will help Jenny prove that Jack is lying?",
        "opciones": [
            "A) Integrity", 
            "B) Non-Repudiation", 
            "C) Authentication", 
            "D) Confidentiality"
            ],
        "respuesta": "B",
        "explicacion": "Non-repudiation is the assurance that someone cannot deny the validity of something. Nonrepudiation is a legal concept that is widely used in information security and refers to a service, which provides proof of the origin of data and the integrity of the data. In other words, non-repudiation makes it very difficult to successfully deny who/where a message came from as well as the authenticity and integrity of that message."
    },
    {
        "pregunta": "What means the flag \"-oX\" in a Nmap scan?",
        "opciones": [
            "A) Output the results in truncated format to the screen.", 
            "B) Run a Xmas scan.", 
            "C) Output the results in XML format to a file.", 
            "D) Run an express scan."
            ],
        "respuesta": "C",
        "explicacion": "The `-oX` flag in Nmap specifies that the scan results should be saved in XML format to a file.  This is useful for parsing the results with other tools or for archiving scan data."
    },
    {
        "pregunta": "Which of the following characteristics is not true about the Simple Object Access Protocol?",
        "opciones": [
            "A) Only compatible with the application protocol HTTP.", 
            "B) Allows for any programming model.", 
            "C) Exchanges data between web services.", 
            "D) Using Extensible Markup Language."
            ],
        "respuesta": "A",
        "explicacion": "SOAP (Simple Object Access Protocol) is not limited to HTTP. It can be used with various application-layer protocols, including SMTP, FTP, and others. While HTTP is the most common transport protocol for SOAP, it's not the only one."
    },
    {
        "pregunta": "Which of the following wireless standard has bandwidth up to 54 Mbit/s and signals in a regulated frequency spectrum around 5 GHz?",
        "opciones": [
            "A) 802.11g", 
            "B) 802.11i", 
            "C) 802.11n", 
            "D) 802.11a"
            ],
        "respuesta": "D",
        "explicacion": "The 802.11a wireless standard operates in the 5 GHz frequency band and supports a maximum data rate of 54 Mbps. It uses Orthogonal Frequency-Division Multiplexing (OFDM) for modulation."
    },
    {
        "pregunta": "Which of the following cipher is based on factoring the product of two large prime numbers?",
        "opciones": [
            "A) SHA-1", 
            "B) RSA", 
            "C) MD5", 
            "D) RC5"
            ],
        "respuesta": "B",
        "explicacion": "The RSA (Rivest-Shamir-Adleman) cryptosystem's security relies on the practical difficulty of factoring the product of two large prime numbers. This is the foundation of its encryption and decryption processes."
    },
    {
        "pregunta": "Which of the following command will help you launch the Computer Management Console from\" Run \" windows as a local administrator Windows 7?",
        "opciones": [
            "A) gpedit.msc", 
            "B) ncpa.cpl", 
            "C) compmgmt.msc", 
            "D) services.msc"
            ],
        "respuesta": "C",
        "explicacion": "The command `compmgmt.msc` is the shortcut to launch the Computer Management console in Windows. This console provides access to various system tools, including Disk Management, Event Viewer, and Device Manager."
    },
    {
        "pregunta": "Which of the following best describes a software firewall?",
        "opciones": [
            "A) Software firewall is placed between the anti-virus application and the IDS components of the operating system.", 
            "B) Software firewall is placed between the desktop and the software componentsof the operating system.", 
            "C) Software firewall is placed between the router and the networking components of the operating system.", 
            "D) Software firewall is placed between the normal application and the networking components of the operating system."],
        "respuesta": "B",
        "explicacion": "A software firewall is placed between the normal application and the networking components of the operating system and regulates data traffic through two things: port numbers, and applications. Depending on your firewall settings, your firewall could stop programs from accessing the Internet, and/or block incoming or outgoing access via ports. For example, Port 80 is your Internet connection. Leaving outgoing Port 80 open is ok, because that is what allows you to browse the Internet. Leaving incoming Port 80 open is a different story. If it’s left open, anybody could access your network through Port 80. One downside to a software-only firewall is that you have to train and maintain the software to recognize threats. As you add or update programs, your firewall will block them, until you tell it not to. Additionally it only protects the device it is installed on. That’s what it does by design."
    },
    {
        "pregunta": "What are the two main conditions for a digital signature?",
        "opciones": [
            "A) Unique and have special characters.",
            "B) It has to be the same number of characters as a physical signature and must be unique.",
            "C) Unforgeable and authentic.",
            "D) Legible and neat."
        ],
        "respuesta": "C",
        "explicacion": "This is a digital code that can be attached to an electronically transmitted message that uniquely identifies the sender. Like a written signature, the purpose of a digital signature is to guarantee that the individual sending the message really is who he or she claims to be. Digital signatures are significant for electronic commerce and are a key component of most authentication schemes. To be effective, digital signatures must be unforgeable. There are several different encryption techniques to guarantee this level of security. The digital signature should also have the capability of being transported to other recipients. For instance, if a document is sent to a third party and they need to verify that the signature is authentic and if it is not readable on their software, it means that it will not be possible for them to access the document."
    },
    {
        "pregunta": "Which of the following best describes the \"white box testing\" methodology?",
        "opciones": [
            "A) The internal operation of a system is completely known to the tester.", 
            "B) Only the external operation of a system is accessible to the tester.", 
            "C) Only the internal operation of a system is known to the tester.", 
            "D) The internal operation of a system is only partly accessible to the tester."
            ],
        "respuesta": "A",
        "explicacion": "White-box testing (also known as clear box, glass box, or structural testing) is a testing method where the tester has full knowledge of the internal workings, structure, and code of the system being tested. This allows for very thorough testing, targeting specific code paths and logic."
    },
    {
        "pregunta": "Why is a penetration test considered to be better than a vulnerability scan?",
        "opciones": [
            "A) The tools used by penetration testers tend to have much more comprehensive vulnerability databases.", 
            "B) Penetration tests are intended to exploit weaknesses in the architecture of your IT network, while a vulnerability scan does not typically involve active exploitation.", 
            "C) A penetration test is often performed by an automated tool, while a vulnerability scan requires active engagement.", 
            "D) Vulnerability scans only do host discovery and port scanning by default."
            ],
        "respuesta": "B",
        "explicacion": "A penetration test goes beyond simply identifying vulnerabilities (like a vulnerability scan). It actively attempts to *exploit* those vulnerabilities to demonstrate the potential impact of a real-world attack. This provides a more realistic assessment of risk."
    },
    {
        "pregunta": "Alex, a cybersecurity specialist, received a task from the head to scan open ports. One of the main conditions was to use the most reliable type of TCP scanning. Which of the following types of scanning should Alex use?",
        "opciones": [
            "A) Half-open Scan.", 
            "B) TCP Connect/Full Open Scan.", 
            "C) Xmas Scan.", 
            "D) NULL Scan."],
        "respuesta": "B",
        "explicacion": "A TCP Connect scan (also known as a full open scan) completes the full three-way handshake (SYN, SYN-ACK, ACK) with the target system. This makes it the most reliable type of TCP scan because it definitively confirms whether a port is open and listening.  The other scan types are less reliable because they rely on inferences from the *absence* of certain responses, or on non-standard TCP behavior."
    },
    {
     "pregunta": "What best describes two-factor authentication for a credit card (using a card and pin)?",
     "opciones": [
         "A) Something you have and something you know.", 
         "B) Something you have and something you are.", 
         "C) Something you know and something you are.", 
         "D) Something you are and something you remember."
         ],
     "respuesta": "A",
     "explicacion": "Two-factor authentication (2FA) requires two different types of authentication factors.  Using a credit card and PIN combines:\n*   **Something you have:** The physical credit card.\n*   **Something you know:** The PIN code."
    },
    {
    "pregunta": "Which of the following does not apply to IPsec?",
    "opciones": [
        "A) Work at the Data Link Layer", 
        "B) Encrypts the payloads", 
        "C) Provides authentication.", 
        "D) Use key exchange."
        ],
    "respuesta": "A",
    "explicacion": "IPsec (Internet Protocol Security) operates at the *Network Layer* (Layer 3) of the OSI model, *not* the Data Link Layer (Layer 2).  It provides encryption, authentication, and key exchange, but does so at the IP packet level, not the frame level of the Data Link Layer."
    },
    {
    "pregunta": "According to the Payment Card Industry Data Security Standard, when is it necessary to conduct external and internal penetration testing?",
    "opciones": [
        "A) At least once a year and after any significant upgrade or modification.", 
        "B) At least twice a year or after any significant upgrade or modification.", 
        "C) At least once every three years or after any significant upgrade or modification.", 
        "D) At least once every two years and after any significant upgrade or modification."
        ],
    "respuesta": "A",
    "explicacion": "PCI DSS requirement 11.3 mandates that penetration testing (both internal and external) be performed at least annually *and* after any significant infrastructure or application upgrade or modification."
    },
    {
    "pregunta": "What identifies malware by collecting data from protected computers while analyzing it on the provider’s infrastructure instead of locally?",
    "opciones": [
        "A) Heuristics-based detection", 
        "B) Behavioural-based detection", 
        "C) Cloud-based detection", 
        "D) Real-time protection"
        ],
    "respuesta": "C",
    "explicacion": "Cloud-based malware detection offloads the analysis of potentially malicious files and behaviors to a cloud service provider's infrastructure.  This allows for more powerful analysis and the leveraging of threat intelligence from a large number of sources."
    },
    {
    "pregunta": "You are configuring the connection of a new employee's laptop to join an 802.11 network. You used a sniffer and found the WAP is not responding. What causes this?",
    "opciones": [
        "A) The laptop is configured for the wrong channel.", 
        "B) The laptop cannot see the SSID of the wireless network.", 
        "C) The WAP does not recognize the la[top's MAC address.", 
        "D) The laptop is not configured to use DHCP."
        ],
    "respuesta": "C",
    "explicacion": "If the Wireless Access Point (WAP) is configured for MAC address filtering and the new laptop's MAC address is not on the allowed list, the WAP will ignore association requests from the laptop.  The other options could cause connection problems, but wouldn't typically result in the WAP completely ignoring the requests as seen with a packet sniffer.  If the channel was wrong or the SSID was hidden, the laptop wouldn't even *send* the association request to that WAP. DHCP issues would happen *after* a successful association."
    },
    {
    "pregunta": "Which of the following is a logical collection of Internet-connected devices such as computers, smartphones or Internet of things (IoT) devices whose security has been breached and control ceded to a third party?",
    "opciones": [
        "A) Spambot", 
        "B) Botnet", 
        "C) Spear Phishing", 
        "D) Rootkit"
        ],
    "respuesta": "B",
    "explicacion": "A botnet is a network of compromised computers (bots) controlled by a single attacker (bot herder). These bots can be used for various malicious purposes, such as sending spam, launching DDoS attacks, or stealing data."
    },
    {
    "pregunta": "After several unsuccessful attempts to extract cryptography keys using software methods, Mark is thinking about trying another code-breaking methodology. Which of the following will best suit Mark based on his unsuccessful attempts?",
    "opciones": [
        "A) Frequency Analysis.", 
        "A) Extraction of cryptographic secrets through coercion or torture.", 
        "B) A backdoor is placed into a cryptographic algorithm by its creator.", 
        "C) Forcing the targeted keystream through a hardware-accelerated device such as an ASIC.", 
        "D) Attempting to decrypt ciphertext by making logical assumptions about the contents of the original plain text."],
    "respuesta": "A",
    "explicacion": "A \"rubber-hose attack\" is a colloquial term for obtaining cryptographic keys or other secrets through coercion, threats, or physical violence (the name refers to the idea of beating someone with a rubber hose until they reveal the information)."
    },
    {
    "pregunta": "The firewall prevents packets from entering the organization through certain ports and applications. What does this firewall check?",
    "opciones": [
        "A) Presentation layer headers and the session layer port numbers.", 
        "B) Application layer port numbers and the transport layer headers.", 
        "C) Application layer headers and transport layer port numbers.", 
        "D) Network layer headers and the session layer port numbers."
        ],
    "respuesta": "C",
    "explicacion": "Firewalls primarily operate at the transport layer (Layer 4) and application layer (Layer 7) of the OSI model.\n\n*   **Transport Layer:** Firewalls examine port numbers (e.g., TCP port 80 for HTTP, port 443 for HTTPS) in the transport layer headers (TCP or UDP) to control access based on the service or application being used.\n*   **Application Layer:** More sophisticated firewalls (application-layer firewalls or proxies) can also inspect the *content* of the packets, including application layer headers.  This is how a Web Application Firewall (WAF) can detect and block SQL injection attacks, for instance. It looks at the HTTP request itself.  The question mentions *applications*, implying inspection beyond just port numbers."
    },
    {
    "pregunta": "Which of the following is the method of determining the movement of a data packet from an untrusted external host to a protected internal host through a firewall?",
    "opciones": [
            "A) MITM",
            "B) Firewalking",
            "C) Session hijacking",
            "D) Network sniffing"
        ],
        "respuesta": "B",
        "explicacion": "Firewalking is a technique developed by Mike Schiffman and David Goldsmith that utilizes traceroute techniques and TTL values to analyze IP packet responses in order to determine gateway ACL (Access Control List) filters and map networks. It is an active reconnaissance network security analysis technique that attempts to determine which layer 4 protocols a specific firewall will allow.\nFirewalking is the method of determining the movement of a data packet from an untrusted external host to a protected internal host through a firewall.\nThe idea behind firewalking is to determine which ports are open and whether packets with control information can pass through a packet-filtering device.\nGathering information about a remote network protected by a firewall can be accomplished using firewalking. One of the uses of firewalking is to determine the hosts present inside the perimeter of the protected network. Another application is to determine the list of ports accessible via a firewall.\n\nIncorrect answers:\n\nSession Hijacking https://en.wikipedia.org/wiki/Session_hijacking\nIn computer science, session hijacking, sometimes also known as cookie hijacking, exploits a valid computer session—sometimes also called a session key—to gain unauthorized access to information or services in a computer system. It refers to the theft of a magic cookie used to authenticate a user to a remote server. It has particular relevance to web developers. The HTTP cookies used to maintain a session on many web sites can be easily stolen by an attacker using an intermediary computer or access to the saved cookies on the victim's computer. After successfully stealing appropriate session cookies, an adversary might use the Pass the Cookie technique to perform session hijacking. Cookie hijacking is commonly used against client authentication on the internet. Modern web browsers use cookie protection mechanisms to protect the web from being attacked.\n\nNetwork sniffing https://en.wikipedia.org/wiki/Sniffing_attack\nSniffing attack or a sniffer attack, in context of network security, corresponds to theft or interception of data by capturing the network traffic using a sniffer (an application aimed at capturing network packets). When data is transmitted across networks, if the data packets are not encrypted, the data within the network packet can be read using a sniffer. Using a sniffer application, an attacker can analyze the network and gain information to eventually cause the network to crash or to become corrupted, or read the communications happening across the network.\n\nMITM https://en.wikipedia.org/wiki/Man-in-the-middle_attack\nA man-in-the-middle (MITM) is a cyberattack where the attacker secretly relays and possibly alters the communications between two parties who believe that they are directly communicating with each other."
    },
    {
        "pregunta": "Often, for a successful attack, hackers very skillfully simulate phishing messages. To do this, they collect the maximum information about the company that they will attack: emails of real employees (including information about the hierarchy in the company), information about the appearance of the message (formatting, logos), etc. What is the name of this stage of the hacker's work?",
        "opciones": [
            "A) Exploration stage",
            "B) Investigation stage",
            "C) Reconnaissance stage",
            "D) Enumeration stage"
        ],
        "respuesta": "C",
        "explicacion": "In this stage, attackers act like detectives, gathering information to understand their target truly. From examining email lists to open source information, their goal is to know the network better than those who run and maintain it. They hone in on the technology's security aspect, study the weaknesses, and use any vulnerability to their advantage.\nThe reconnaissance stage can be viewed as the most important because it takes patience and time, from weeks to several months. Any information the infiltrator can gather on the company, such as employee names, phone numbers, and email addresses, will be vital.\nAttackers will also start to poke the network to analyze what systems and hosts are there. They will note any changes in the system that can be used as an entrance point. For example, leaving your network open for a vendor to fix an issue can also allow the cybercriminal to plant himself inside.\nBy the end of this pre-attack phase, attackers will have created a detailed map of the network, highlighted the system’s weaknesses, and continued with their mission. Another point of focus during the reconnaissance stage is understanding the network's trust boundaries. With an increase in employees working from home or using their personal devices for work, there is an increase in data breaches.\nNOTE: Reconnaissance takes place in two parts − Active Reconnaissance and Passive Reconnaissance. And again, the problem of the question is in the levels of abstraction. It can be difficult to choose one correct option if it is part of something larger. Reconnaissance is a set of processes and techniques (Footprinting, Scanning & Enumeration) to discover and collect information about a target system covertly. \"Footprinting\" would have been more correct."
    },
    {
        "pregunta": "Imagine the following scenario:\n1. An attacker created a website with tempting content and benner like: 'Do you want to make $10 000 in a month?'.\n2. Victim clicks to the interesting and attractive content URL.\n3. Attacker creates a transparent 'iframe' in front of the banner which victim attempts to click.\nVictim thinks that he/she clicks to the 'Do you want to make $10 000 in a month?' banner but actually he/she clicks to the content or UPL that exists in the transparent 'iframe' which is set up by the attacker.\nWhat is the name of the attack which is described in the scenario?",
        "opciones": [
            "A) Session Fixation",
            "B) Clickjacking Attack",
            "C) HTML Injection",
            "D) HTTP Parameter Pollution"
        ],
        "respuesta": "B",
        "explicacion": "https://en.wikipedia.org/wiki/Clickjacking\nClickjacking is an attack that tricks a user into clicking a webpage element which is invisible or disguised as another element. This can cause users to unwittingly download malware, visit malicious web pages, provide credentials or sensitive information, transfer money, or purchase products online.\nTypically, clickjacking is performed by displaying an invisible page or HTML element, inside an iframe, on top of the page the user sees. The user believes they are clicking the visible page but in fact they are clicking an invisible element in the additional page transposed on top of it.\n\nIncorrect answers:\n\nSession Fixation https://en.wikipedia.org/wiki/Session_fixation\nSession fixation is a web application attack in which attackers can trick a victim into authenticating the application using the attacker's Session Identifier. Unlike Session Hijacking, this does not rely on stealing the Session ID of an already authenticated user.\nA simple way attacker can send a link containing a fixed session-id, and if the victim clicks on the link, the victim’s session id will be fixed since the attacker already know the session id so he/she can easily hijack the session.\n\nHTML Injection https://en.wikipedia.org/wiki/Code_injection\nThe essence of this type of injection attack is injecting HTML code through the website's vulnerable parts. The Malicious user sends HTML code through any vulnerable field to change the website’s design or any information displayed to the user.\nAs a result, the user may see the data the malicious user sent. Therefore, in general, HTML Injection is just the injection of markup language code to the page's document.\nData that is being sent during this type of injection attack may be very different. It can be a few HTML tags that will display the sent information. Also, it can be the whole fake form or page. When this attack occurs, the browser usually interprets malicious user data as legit and displays it.\nChanging a website’s appearance is not the only risk that this type of attack brings. It is quite similar to the XSS attack, where the malicious user steals other person’s identities.\nTherefore stealing another person’s identity may also happen during this injection attack.\n\nHTTP Parameter Pollution https://en.wikipedia.org/wiki/HTTP_parameter_pollution\nHTTP Parameter Pollution (HPP) is a vulnerability that occurs due to the passing of multiple parameters having the same name. There is no RFC standard on what should be done when passed multiple parameters. For example, if the parameter username is included in the GET or POST parameters twice.\nSupplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways. By exploiting these effects, an attacker may bypass input validation, trigger application errors, or modify internal variables values. As HTTP Parameter Pollution affects a building block of all web technologies, server and client-side attacks exist.\nIn 2009, immediately after the publication of the first research on HTTP Parameter Pollution, the technique received attention from the security community as a possible way to bypass web application firewalls."
    },
    {
        "pregunta": "Black hat hacker Ivan wants to implement a man-in-the-middle attack on the corporate network. For this, he connects his router to the network and redirects traffic to intercept packets. What can the administrator do to mitigate the attack?",
        "opciones": [
            "A) Use the Open Shortest Path First (OSPF).",
            "B) Add message authentication to the routing protocol.",
            "C) Use only static routes in the corporation's network.",
            "D) Redirection of the traffic is not possible without the explicit admin's confirmation."
        ],
        "respuesta": "B",
        "explicacion": "The area most open to attack is often the routing systems within your enterprise network. Because of some of the sniffing-based attacks, an enterprise routing infrastructure can easily be attacked with man-in-the-middle and other attacks designed to corrupt or change the routing tables with the following results:\n· Traffic redirection— enabling the attacker to modify traffic in transit or sniff packets;\n· Traffic sent to a routing black hole— the attacker can send specific routes to null0, effectively kicking IP addresses off the network;\n· Router denial-of-service (DoS)—attacking the routing process can crash the router or severe service degradation;\n· Routing protocol DoS—Similar to the attack previously described against a whole router, a routing protocol attack could be launched to stop the routing process from functioning properly;\n· Unauthorized route prefix origination—this attack aims to introduce a new prefix into the routing table that shouldn't be there. The attacker might do this to get a covert attack network to be routable throughout the victim network.\nThere are four primary attack methods for these attacks:\n· Configuration modification of existing routers;\n· Introduction of a rogue router that participates in routing with legitimate routers;\n· Spoofing a valid routing protocol message or modifying a valid message in transit;\n· Sending of malformed or excess packets to a routing protocol process.\nThese four attack methods can be mitigated in the following ways:\n· To counter configuration modification of existing routers, you must secure the routers. This includes not only the configuration of the router but also the supporting systems it makes use of, such as TFTP servers.\n· Anyone can attempt to introduce a rogue router, but to cause damage, the attacker needs the other routing devices to believe the sent information. This can most easily be blocked by adding message authentication to your routing protocol. Additionally, the routing protocol message types can be blocked by ACLs from networks with no need to originate them.\n· Message authentication can also help prevent the spoofing or modification of a valid routing protocol message. Besides, the transport layer protocol (such as TCP for BGP) can further complicate message spoofing because of the difficulty in guessing pseudo-random initial sequence numbers (assuming a remote attacker).\n· Excess packets can be stopped through the use of traditional DoS mitigation techniques. Malformed packets, however, are nearly impossible to stop without the participation of the router vendor. Only through exhaustive testing and years of field use do routing protocol implementations correctly deal with most malformed messages. This is an area of computer security that needs increased attention, not just in routing protocols but in all network applications."
    },
    {
        "pregunta": "Which of the options presented below is not a Bluetooth attack?",
        "opciones": [
            "A) Bluesmacking", 
            "B) Bluesnarfing", 
            "C) Bluejacking", 
            "D) Bluedriving"
            ],
        "respuesta": "D",
        "explicacion": "Bluedriving is a Bluetooth wardriving utility. It can capture Bluetooth devices, lookup their services, get GPS information, and present everything in a nice web page.  It is used for research and reconnaissance, not for attacking."
    },
    {
        "pregunta": "Which of the following program attack both the boot sector and executable files?",
        "opciones": ["A) Polymorphic virus", "B) Multipartite Virus", "C) Macro virus", "D) Stealth virus"],
        "respuesta": "B",
        "explicacion": "A multipartite virus is a type of computer virus that infects and spreads in multiple ways.  Crucially, it can infect both the boot sector of a hard drive *and* executable files.  This makes it more difficult to eradicate than viruses that only target one area."
    },
    {
        "pregunta": "The company \"Usual company\" asked a cybersecurity specialist to check their perimeter email gateway security.  The specialist spoofs the sender address to make it appear as though an email came from within the company:"
        "\n1. From: employee76@usualcompany.com"
        "\n2. To: employee34@usualcompany.com"
        "\n3. Subject: Test Message"
        "\n4. Date:5/8/2021 11:22"
        "\n2. What is this attack?",
        "opciones": ["A) Email Harvesting", "B) Email Masquerading", "C) Email Spoofing", "D) Email Phishing"],
        "respuesta": "C",
        "explicacion": "Email spoofing is the act of forging an email header to make it appear as though it originated from a different source. In this case, the specialist is forging the 'From' address to make the email look like it came from an internal employee."
    },
    {
        "pregunta": "Rajesh, the system administrator analyzed the IDS logs and noticed that when accessing the external router from the administrator's computer to update the router configuration, IDS registered alerts. What type of an alert is this?",
        "opciones": ["A) False negative", "B) True positve", "C) True negative", "D) False positive"],
        "respuesta": "D",
        "explicacion": "A false positive occurs when an Intrusion Detection System (IDS) incorrectly flags legitimate activity as malicious. In this scenario, the administrator's legitimate action of updating the router configuration is mistakenly identified as an attack."
    },
    {
        "pregunta": "For the company, an important criterion is the immutability of the financial reports sent by the financial director to the accountant. They need to be sure that the accountant received the reports and it hasn't been changed. How can this be achieved?",
        "opciones": ["A) Use a hash algorithm in the document once CFO approved the financial statements.", "B) Reports can send to the accountant using an exclusive USB for that document.", "C) Use a protected excel file.", "D) Financial reports can send the financial statements twice, one by email and the other delivered in USB and the accountant can compare both."],
        "respuesta": "A",
        "explicacion": "Using a cryptographic hash function (like SHA-256) on the financial report creates a unique 'fingerprint' of the document.  The CFO can calculate the hash and provide it to the accountant separately. The accountant can then calculate the hash of the received document. If the hashes match, it confirms the document's integrity (it hasn't been altered).  This doesn't prevent interception, but it guarantees *detection* of any modification."
    },
    {
        "pregunta": "While using your bank's online servicing you notice the following string in the URL bar:\nhttp://www.MyPersonalBank.com/account?id=368940911028389&Damount=10980&Camount=21\nYou observe that if you modify the Damount & Camount values and submit the request, that data on the web page reflect the changes. Which type of vulnerability is present on this site?",
        "opciones": ["A) Web Parameter Tampering", "B) Cookie Tampering", "C) SQL injection", "D) XSS Reflection"],
        "respuesta": "A",
        "explicacion": "Web parameter tampering involves manipulating parameters in the URL (or in POST data) to modify application data.  The scenario described directly shows modification of `Damount` and `Camount` values in the URL, which is a clear example of parameter tampering."
    },
    {
        "pregunta": "Ferdinand installs a virtual communication tower between the two authentic endpoints to mislead the victim. What attack does Ferdinand perform?",
        "opciones": ["A) Aspidistra", "B) Wi-Jacking", "C) Sinkhole", "D) aLTEr"],
        "respuesta": "D",
        "explicacion": "The aLTEr attack is a specific type of man-in-the-middle attack targeting 4G LTE networks. It involves setting up a fake base station (eNodeB) to intercept and potentially modify communication between a user's device and the legitimate network."
    },
    {
        "pregunta": "You analyze the logs and see the following output from the machine with the IP address of 192.168.0.132:\n1. Time August 21 11:22:06 Port:20 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n2. Time August 21 11:22:08 Port:21 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n3. Time August 21 11:22:11 Port:22 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n4. Time August 21 11:22:14 Port:23 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n5. Time August 21 11:22:15 Port:25 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n6. Time August 21 11:22:19 Port:80 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n7. Time August 21 11:22:21 Port:443 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\nWhat conclusion can you make based on this output?",
        "opciones": [
            "A) Denial of service attack targeting 192.168.0.132", 
            "B) Port scan targeting 192.168.0.30", 
            "C) Teardrop attack targeting 192.168.0.132", 
            "D) Port scan targeting 192.168.0.132"
            ]
            ,
        "respuesta": "D",
        "explicacion": "The logs show sequential connections from 192.168.0.30 to 192.168.0.132 across a range of common ports. This pattern is indicative of a port scan, where an attacker is checking which ports are open on the target machine."
    },
    {
        "pregunta": "With which of the following SQL injection attacks can an attacker deface a web page, modify or add data stored in a database and compromised data integrity?",
        "opciones": [
            "A) Unauthorized access to an application.", 
            "B) Compromised Data Integrity.", 
            "C) Loss of data availability.", 
            "D) Information Disclosure."
            ],
        "respuesta": "B",
        "explicacion": "SQL injection allows attackers to execute arbitrary SQL commands.  This can include `UPDATE` and `INSERT` statements, which directly modify the data within the database, thus compromising its integrity."
    },
    {
        "pregunta": "The attacker enters its malicious data into intercepted messages in a TCP session since source routing is disabled. He tries to guess the responses of the client and server. What hijacking technique is described in this example?",
        "opciones": [
            "A) RST", 
            "B) TCP/IP", 
            "C) Blind", 
            "D) Registration"
            ],
        "respuesta": "C",
        "explicacion": "Blind hijacking occurs when an attacker cannot see the responses from the server or client.  They inject data into the TCP stream, hoping to correctly guess the sequence and acknowledgment numbers, but without direct feedback."
    },
    {
        "pregunta": "What actions should be performed before using a Vulnerability Scanner for scanning a network?",
        "opciones": [
            "A) TCP/IP stack fingerprinting.", 
            "B) Checking if the remote host is alive.", 
            "C) TCP/UDP Port scanning.", 
            "D) Firewall detection."
            ],
        "respuesta": "B",
        "explicacion": "Before running a vulnerability scan, it's essential to confirm that the target host is online and reachable. Vulnerability scanners often start by performing a simple ping or similar check to ensure the target is active."
    },
    {
        "pregunta": "Which of the following is the risk that remains after the amount of risk left over after natural or inherent risks have been reduced?",
        "opciones": [
            "A) Residual risk", 
            "B) Impact risk", 
            "C) Inherent risk", 
            "D) Deferred risk"
            ],
        "respuesta": "A",
        "explicacion": "Residual risk is the risk that remains after security controls and mitigation strategies have been implemented. It's the risk that an organization must accept or further mitigate through additional measures."
    },
    {
        "pregunta": "Which of the following incident handling process phases is responsible for defining rules, employees training, creating a back-up, and preparing software and hardware resources before an incident occurs?",
        "opciones": [
            "A) Recovery", 
            "B) Containment", 
            "C) Identification", 
            "D) Preparation"
            ],
        "respuesta": "D",
        "explicacion": "The preparation phase is crucial for proactive incident response. It involves establishing policies, procedures, training, and resources to effectively handle potential incidents before they happen."
    },
    {
        "pregunta": "Wireshark is one of the most important tools for a cybersecurity specialist. It is used for network troubleshooting, analysis, software, etc. And you often have to work with a packet bytes pane. In what format is the data presented in this pane?",
        "opciones": [
            "A) ASCII only", 
            "B) Hexadecimal", 
            "C) Binary", 
            "D) Decimal"
            ],
        "respuesta": "B",
        "explicacion": "Wireshark's packet bytes pane displays the raw data of a packet in hexadecimal format (hexdump). This allows for a detailed examination of the packet's contents."
    },
    {
        "pregunta": "Alex, a cyber security specialist, should conduct a pentest inside the network, while he received absolutely no information about the attacked network. What type of testing will Alex conduct?",
        "opciones": [
            "A) Internal, Black-box.", 
            "B) External, Black-box.", 
            "C) Internal, Grey-box.", 
            "D) Internal, White-box."
            ],
        "respuesta": "A",
        "explicacion": "This scenario describes an internal penetration test (conducted from within the network) with a black-box approach (no prior information provided to the tester).  The tester simulates an insider threat with no knowledge of the internal systems."
    },
    {
        "pregunta": "What is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program?",
        "opciones": ["A) Concolic testing", "B) Fuzz testing", "C) Security testing", "D) Monkey testing"],
        "respuesta": "B",
        "explicacion": "Fuzz testing (fuzzing) is a technique where automated tools provide a program with a wide range of invalid, unexpected, or random data as input. The program is then monitored for crashes, errors, or other unexpected behavior that might indicate vulnerabilities."
    },
    {
        "pregunta": "Which one of the following Google search operators allows restricting results to those from a specific website?",
        "opciones": ["A) [link:]", "B) [inurl:]", "C) [site:]", "D) [cache:]"],
        "respuesta": "C",
        "explicacion": "The `site:` operator in Google Search restricts results to a specific website or domain. For example, `site:example.com keyword` would only return results from example.com that contain the keyword."
    },
    {
        "pregunta": "Based on the following data, you need to calculate the approximate cost of recovery of the system operation per year:\nThe cost of a new hard drive is $300;\nThe chance of a hard drive failure is 1/3;\nThe recovery specialist earns $10/hour;\nRestore the OS and software to the new hard disk - 10 hours;\nRestore the database from the last backup to the new hard disk - 4 hours;\nAssume the EF = 1 (100%), calculate the SLE, ARO, and ALE.",
        "opciones": ["A) $146", "B) $440", "C) $960", "D) $295"],
        "respuesta": "A",
        "explicacion": "Here's the breakdown of the calculation:\n*   **AV (Asset Value):** $300 (hard drive) + ($10/hour * 14 hours) = $440\n*   **SLE (Single Loss Expectancy):** AV * EF = $440 * 1 = $440\n*   **ARO (Annualized Rate of Occurrence):** 1/3 (given)\n*   **ALE (Annualized Loss Expectancy):** SLE * ARO = $440 * (1/3) = $146.67 (approximately $146)"
    },
    {
        "pregunta": "John needs to choose a firewall that can protect against SQL injection attacks. Which of the following types of firewalls is suitable for this task?",
        "opciones": ["A) Hardware firewall.", "B) Packet firewall.", "C) Stateful firewall.", "D) Web application firewall."],
        "respuesta": "D",
        "explicacion": "A Web Application Firewall (WAF) is specifically designed to protect web applications by inspecting HTTP traffic. It can detect and block common web-based attacks, including SQL injection, cross-site scripting (XSS), and others."
    },
    {
        "pregunta": "Which of the following is the type of violation when an unauthorized individual enters a building following an employee through the employee entrance?",
        "opciones": ["A) Tailgating.", "B) Pretexting.", "C) Announced.", "D) Reverse Social Engineering."],
        "respuesta": "A",
        "explicacion": "Tailgating (also known as piggybacking) is a physical security breach where an unauthorized person follows an authorized person into a restricted area.  This often happens at doorways where access control is in place."
    },
    {
        "pregunta": "The attacker tries to take advantage of vulnerability where the application does not verify if the user is authorized to access the internal object via its name or key. Which of the following queries best describes an attempt to exploit an insecure direct object using the name of the valid account \"User 1\"?",
        "opciones": [
            "A) \"GET /restricted/bank.getaccount('˜User1') HTTP/1.1 Host: westbank.com\"", 
            "B) \"GET /restricted/goldtransfer?to=Account&from=1 or 1=1' HTTP/1.1Host: westbank.com\"", 
            "C) \"GET /restricted/\\r\\n\\%00account%00User1%00access HTTP/1.1 Host: westbank.com\"", 
            "D) \"GET /restricted/accounts/?name=User1 HTTP/1.1 Host: westbank.com\""],
        "respuesta": "D",
        "explicacion": "This is a classic example of an Insecure Direct Object Reference (IDOR) vulnerability. The attacker is directly referencing an object (in this case, a user account) by its name.  If the application doesn't properly check authorization, the attacker might gain access to the 'User1' account details simply by providing the name."
    },
    {
        "pregunta": "Maria is surfing the internet and try to find information about Super Security LLC. Which process is Maria doing?",
        "opciones": [
            "A) Enumeration",
            "B) System Hacking",
            "C) Footprinting",
            "D) Scanning"
        ],
        "respuesta": "C",
        "explicacion": "Footprinting is a part of the reconnaissance process used to gather possible information about a target computer system or network. It could be both passive and active. Reviewing a company’s website is an example of passive footprinting, whereas attempting to gain access to sensitive information through social engineering is an example of active information gathering. Footprinting is basically the first step where hacker gathers as much information as possible to find ways to intrude into a target system or at least decide what type of attacks will be more suitable for the target.\nDuring this phase, a hacker can collect the following information:\n· Domain name\n· IP Addresses\n· Namespaces\n· Employee information\n· Phone numbers\n· E-mails\n· Job Information\n\nIncorrect answers:\n\nScanning\nSecurity scanning can mean many different things, but it can be described as scanning a website's security, web-based program, network, or file system for either vulnerabilities or unwanted file changes. The type of security scanning required for a particular system depends on what that system is used. The more complicated and intricate the system or network is, the more in-depth the security scan has. Security scanning can be done as a one-time check, but most companies who incorporate this into their security practices buy a service that continually scans their systems and networks.\nOne of the more popular open-source software platforms that run security scans is called Nmap. It has been around for a very long time and has the ability to find and exploit vulnerabilities in a network. Several online scans are available; however, these come with varying degrees of effectiveness and cost-efficiency.\nNOTE: In the context of an EC-Council course and exam, think of these definitions like this:\nFootprinting is a passive collection of information without touching the target system/network/computer.\nScanning is an active collection of information associated with a direct impact on the target.\nYes, that's not entirely true, but this course has big problems with abstraction levels. It is almost impossible to present a lot of topics in such a short period of time.\n\nEnumeration\nEnumeration is defined as a process that establishes an active connection to the target hosts to discover potential attack vectors in the system. The same can be used to exploit the system further. Enumeration is used to gather the below:\n· Usernames, Group names\n· Hostnames\n· Network shares and services\n· IP tables and routing tables\n· Service settings and Audit configurations\n· Application and banners\n· SNMP and DNS Details\n\nSystem Hacking\nSystem hacking is a vast subject that consists of hacking the different software-based technological systems such as laptops, desktops, etc. System hacking is defined as compromising computer systems and software to access the target computer and steal or misuse their sensitive information. Here, the malicious hacker exploits a computer system's weaknesses or network to gain unauthorized access to its data or take illegal advantage."
    },
    {
        "pregunta": "Maria conducted a successful attack and gained access to a Linux server. She wants to avoid that NIDS will not catch the succeeding outgoing traffic from this server in the future. Which of the following is the best way to avoid detection of NIDS?",
        "opciones": [
            "A) Encryption",
            "B) Out of band signaling",
            "C) Alternate Data Streams",
            "D) Protocol Isolation"
        ],
        "respuesta": "A",
        "explicacion": "When the NIDS encounters encrypted traffic, the only analysis it can perform is packet level analysis, since the application layer contents are inaccessible. Given that exploits against today’s networks are primarily targeted against network services (application layer entities), the packet-level analysis ends up doing very little to protect our core business assets."
    },
    {
        "pregunta": "Ivan, a black hat hacker, sends partial HTTP requests to the target webserver to exhaust the target server’s maximum concurrent connection pool. He wants to ensure that all additional connection attempts are rejected. What type of attack does Ivan implement?",
        "opciones": [
            "A) Fragmentation",
            "B) Slowloris",
            "C) Spoofed Session Flood",
            "D) HTTP GET/POST"
        ],
        "respuesta": "B",
        "explicacion": "Slowloris is a type of denial of service attack tool which allows a single machine to take down another machine's web server with minimal bandwidth and side effects on unrelated services and ports.\nSlowloris tries to keep many connections to the target web server open and hold them open as long as possible. It accomplishes this by opening connections to the target web server and sending a partial request. Periodically, it will send subsequent HTTP headers, adding to, but never completed, the request. Affected servers will keep these connections open, filling their maximum concurrent connection pool, eventually denying additional connection attempts from clients.\nThe program was named after Slow lorises, a group of primates that are known for their slow movement.\n\nIncorrect answers:\n\nHTTP GET/POST (HTTP Flood) https://en.wikipedia.org/wiki/HTTP_Flood\nHTTP Flood is a type of Distributed Denial of Service (DDoS) attack in which the attacker manipulates HTTP and POST unwanted requests in order to attack a web server or application. These attacks often use interconnected computers that have been taken over with the aid of malware such as Trojan Horses. Instead of using malformed packets, spoofing and reflection techniques, HTTP floods require less bandwidth to attack the targeted sites or servers.\n\nSpoofed Session Flood\nFake Session attacks try to bypass security under the disguise of a valid TCP session by carrying an SYN, multiple ACK and one or more RST or FIN packets. This attack can bypass defence mechanisms that are only monitoring incoming traffic on the network. These DDoS attacks can also exhaust the target’s resources and result in a complete system shutdown or unacceptable system performance.\n\nFragmentation https://en.wikipedia.org/wiki/IP_fragmentation_attack\nIP fragmentation attacks are a kind of computer security attack based on how the Internet Protocol (IP) requires data to be transmitted and processed. Specifically, it invokes IP fragmentation, a process used to partition messages (the service data unit (SDU); typically a packet) from one layer of a network into multiple smaller payloads that can fit within the lower layer's protocol data unit (PDU). Every network link has a maximum size of messages that may be transmitted, called the maximum transmission unit (MTU). If the SDU plus metadata added at the link-layer exceeds the MTU, the SDU must be fragmented. IP fragmentation attacks exploit this process as an attack vector.\nPart of the TCP/IP suite is the Internet Protocol (IP) which resides at the Internet Layer of this model. IP is responsible for the transmission of packets between network endpoints. IP includes some features which provide basic measures of fault-tolerance (time to live, checksum), traffic prioritization (a type of service) and support for the fragmentation of larger packets into multiple smaller packets (ID field, fragment offset). The support for fragmentation of larger packets provides a protocol allowing routers to fragment a packet into smaller packets when the original packet is too large for the supporting datalink frames. IP fragmentation exploits (attacks) use the fragmentation protocol within IP as an attack vector."
    },
    {
        "pregunta": "Which regulation defines security and privacy controls for all U.S. federal information systems except those related to national security?",
        "opciones": [
            "A) PCI-DSS",
            "B) NIST-800-53",
            "C) EU Safe Harbor",
            "D) HIPAA"
        ],
        "respuesta": "B",
        "explicacion": "NIST Special Publication 800-53 provides a catalog of security and privacy controls for all U.S. federal information systems except those related to national security. It is published by the National Institute of Standards and Technology, which is a non-regulatory agency of the United States Department of Commerce. NIST develops and issues standards, guidelines, and other publications to assist federal agencies in implementing the Federal Information Security Modernization Act of 2014 (FISMA) and to help with managing cost-effective programs to protect their information and information systems.\n\nIncorrect answers:\n\nPCI-DSS https://en.wikipedia.org/wiki/Payment_Card_Industry_Data_Security_Standard\nThe Payment Card Industry Data Security Standard (PCI DSS) is an information security standard for organizations that handle branded credit cards from the major card schemes. The PCI Standard is mandated by the card brands but administered by the Payment Card Industry Security Standards Council. The standard was created to increase controls around cardholder data to reduce credit card fraud.\n\nEU Safe Harbor\nhttps://en.wikipedia.org/wiki/International_Safe_Harbor_Privacy_Principles\nThe International Safe Harbor Privacy Principles or Safe Harbour Privacy Principles were principles developed between 1998 and 2000 in order to prevent private organizations within the European Union or United States which store customer data from accidentally disclosing or losing personal information.\n\nHIPAA https://en.wikipedia.org/wiki/Health_Insurance_Portability_and_Accountability_Act\nThe Health Insurance Portability and Accountability Act of 1996 (HIPAA or the Kennedy–Kassebaum Act) is a United States federal statute enacted by the 104th United States Congress and signed into law by President Bill Clinton on August 21, 1996. It was created primarily to modernize the flow of healthcare information, stipulate how personally identifiable information maintained by the healthcare and healthcare insurance industries should be protected from fraud and theft, and address limitations on healthcare insurance coverage"
    },
    {
        "pregunta": "Ivan, a black hat hacker, tries to call numerous random numbers inside the company, claiming he is from the technical support service. It offers company employee services in exchange for confidential data or login credentials. What method of social engineering does Ivan use?",
        "opciones": [
            "A) Reverse Social Engineering",
            "B) Tailgating",
            "C) Quid Pro Quo",
            "D) Elicitation"
        ],
        "respuesta": "C",
        "explicacion": "There is a social engineering technique \"baiting\" that exploits the human’s curiosity. Baiting is sometimes confused with other social engineering attacks. Its main characteristic is the promise of goods that hackers use to deceive the victims.\nA classic example is an attack scenario in which attackers use a malicious file disguised as a software update or generic software. An attacker can also power a baiting attack in the physical world, such as disseminating infected USB tokens in the parking lot of a target organization and waiting for internal personnel to insert them into corporate PCs.\nThe malware installed on the USB tokens will compromise the PCs, gaining the full control needed for the attacks.\nA quid pro quo attack (aka “something for something” attack) is a variant of baiting. Instead of baiting a target with the promise of a good, a quid pro quo attack promises a service or a benefit based on a specific action's execution.\nIn a quid pro quo attack scenario, the hacker offers a service or benefit in exchange for information or access.\nThe most common quid pro quo attack occurs when a hacker impersonates an IT staffer for a large organization. That hacker attempts to contact the target organization's employees via phone and then offers them some upgrade or software installation.\nThey might request victims to facilitate the operation by disabling the AV software temporarily to install the malicious application.\n\nIncorrect answers:\n\nReverse Social Engineering\nReverse Social Engineering (RSE) is a form of social engineering attack. It has the same aim as a typical social engineering attack but with a completely different approach. This is a person-to-person attack in which an attacker convinces the target that he or she has a problem or might have a certain problem in the future and that he, the attacker, is ready to help solve the problem.\nFor example, the hacker establishes contact with the target through e-mail or other social media platforms, using multiple schemes and pretending to be a benefactor or skilled security personnel to convince them to provide access to their system/network. Though this technique may seem outdated and ridiculous, it has proved highly effective, especially when the victim's system/network shows signs of being compromised. Usually, in social engineering attacks, the attackers approach their targets. While in a reverse social engineering attack, the victim goes to the attacker unknowingly.\n\nTailgating\nTailgating, sometimes referred to as piggybacking, is a physical security breach in which an unauthorized person follows an authorized individual to enter a secured premise.\nTailgating provides a simple social engineering-based way around many security mechanisms one would think of as secure. Even retina scanners don't help if an employee holds the door for an unknown person behind them out of misguided courtesy.\nPeople who might tailgate include disgruntled former employees, thieves, vandals, mischiefmakers, and issues with employees or the company. Any of these can disrupt business, cause damage, create unexpected costs, and lead to further safety issues.\n\nElicitation\nElicitation means to bring or draw out or arrive at a conclusion (truth, for instance) by logic. Alternatively, it is defined as stimulation that calls up (or draws forth) a particular class of behaviors, as in \"the elicitation of his testimony was not easy.\"\nIn training materials, the National Security Agency of the United States government defines elicitation as \"the subtle extraction of information during an apparently normal and innocent conversation.\"\nThese conversations can occur anywhere that the target is—a restaurant, the gym, a daycare—anywhere. Elicitation works well because it is low risk and often very hard to detect. Most of the time, the targets don't ever know where the information"
    },
    {
        "pregunta": "John performs black-box testing. It tries to pass IRC traffic over port 80/TCP from a compromised web-enabled host during the test. Traffic is blocked, but outbound HTTP traffic does not meet any obstacles. What type of firewall checks outbound traffic?",
        "opciones": [
            "A) Stateful",
            "B) Packet Filtering",
            "C) Circuit",
            "D) Application"
        ],
        "respuesta": "D",
        "explicacion": "Internet Relay Chat (IRC) is an application layer protocol that facilitates communication in text. The chat process works on a client/server networking model. IRC clients are computer programs that users can install on their system or web-based applications running either locally in the browser or on a third-party server. These clients communicate with chat servers to transfer messages to other clients.\nIRC is a plaintext protocol that is officially assigned port 194, according to IANA. However, running the service on this port requires running it with root-level permissions, which is inadvisable. As a result, the well-known port for IRC is 6667, a high-number port that does not require elevated privileges. However, an IRC server can also be configured to run on other ports as well.\nYou can't tell if an IRC server is designed to be malicious solely based on port number. Still, if you see an IRC server running on port a WKP such as 80, 8080, 53, 443, it's almost always going to be malicious; the only real reason for IRCD to be running on port 80 is to try to evade firewalls.\n\nAn application firewall is a form of firewall that controls input/output or system calls of an application or service. It operates by monitoring and blocking communications based on a configured policy, generally with predefined rule sets to choose from. The application firewall can control communications up to the OSI model's application layer, which is the highest operating layer, and where it gets its name. The two primary categories of application firewalls are network-based and host-based.\nApplication layer filtering operates at a higher level than traditional security appliances. This allows packet decisions to be made based on more than just source/destination IP Addresses or ports. It can also use information spanning across multiple connections for any given host.\n\nNetwork-based application firewalls\nNetwork-based application firewalls operate at the application layer of a TCP/IP stack. They can understand certain applications and protocols such as File Transfer Protocol (FTP), Domain Name System (DNS), or Hypertext Transfer Protocol (HTTP). This allows it to identify unwanted applications or services using a non-standard port or detect if an allowed protocol is being abused.\n\nHost-based application firewalls\nA host-based application firewall monitors application system calls or other general system communication. This gives more granularity and control but is limited to only protecting the host it is running on. Control is applied by filtering on a per-process basis. Generally, prompts are used to define rules for processes that have not yet received a connection. Further filtering can be done by examining the process ID of the owner of the data packets. Many host-based application firewalls are combined or used in conjunction with a packet filter."
    },
    {
        "pregunta": "John, a cybersecurity specialist, received a copy of the event logs from all firewalls, Intrusion Detection Systems (IDS) and proxy servers on a company's network. He tried to match all the registered events in all the logs, and he found that their sequence didn't match. What can cause such a problem?",
        "opciones": [
            "A) The security breach was a false positive.",
            "B) A proper chain of custody was not observed while collecting the logs.",
            "C) The network devices are not all synchronized.",
            "D) The attacker altered events from the logs."
        ],
        "respuesta": "C",
        "explicacion": "Many network and system administrators don't pay enough attention to system clock accuracy and time synchronization. Computer clocks can run faster or slower over time, batteries and power sources die, or daylight-saving time changes are forgotten. Sure, there are many more pressing security issues to deal with, but not ensuring that the time on network devices is synchronized can cause problems. And these problems often only come to light after a security incident.\nIf you suspect a hacker is accessing your network, for example, you will want to analyze your log files to look for any suspicious activity. If your network's security devices do not have synchronized times, the timestamps' inaccuracy makes it impossible to correlate log files from different sources. Not only will you have difficulty in tracking events, but you will also find it difficult to use such evidence in court; you won't be able to illustrate a smooth progression of events as they occurred throughout your network."
    },
    {
        "pregunta": "John, a cybersecurity specialist, received a copy of the event logs from all firewalls, Intrusion Detection Systems (IDS) and proxy servers on a company's network. He tried to match all the registered events in all the logs, and he found that their sequence didn't match. What can cause such a problem?",
        "opciones": [
            "A) The security breach was a false positive.",
            "B) A proper chain of custody was not observed while collecting the logs.",
            "C) The network devices are not all synchronized.",
            "D) The attacker altered events from the logs."
        ],
        "respuesta": "C",
        "explicacion": "Many network and system administrators don't pay enough attention to system clock accuracy and time synchronization. Computer clocks can run faster or slower over time, batteries and power sources die, or daylight-saving time changes are forgotten. Sure, there are many more pressing security issues to deal with, but not ensuring that the time on network devices is synchronized can cause problems. And these problems often only come to light after a security incident.\nIf you suspect a hacker is accessing your network, for example, you will want to analyze your log files to look for any suspicious activity. If your network's security devices do not have synchronized times, the timestamps' inaccuracy makes it impossible to correlate log files from different sources. Not only will you have difficulty in tracking events, but you will also find it difficult to use such evidence in court; you won't be able to illustrate a smooth progression of events as they occurred throughout your network."
    },
    {
        "pregunta": "The Web development team is holding an urgent meeting, as they have received information from testers about a new vulnerability in their Web software. They make an urgent decision to reduce the likelihood of using the vulnerability. The team beside to modify the software requirements to disallow users from entering HTML as input into their Web application. Determine the type of vulnerability that the test team found?",
        "opciones": [
            "A) Cross-site scripting vulnerability.",
            "B) Cross-site Request Forgery vulnerability.",
            "C) SQL injection vulnerability.",
            "D) Website defacement vulnerability."
        ],
        "respuesta": "A",
        "explicacion": "There is no single, standardized classification of cross-site scripting flaws, but most experts distinguish between at least two primary flavors of XSS flaws: non-persistent and persistent. In this issue, we consider the non-persistent cross-site scripting vulnerability.\nThe non-persistent (or reflected) cross-site scripting vulnerability is by far the most basic type of web vulnerability. These holes show up when the data provided by a web client, most commonly in HTTP query parameters (e.g. HTML form submission), is used immediately by server-side scripts to parse and display a page of results for and to that user, without properly sanitizing the content.\nBecause HTML documents have a flat, serial structure that mixes control statements, formatting, and the actual content, any non-validated user-supplied data included in the resulting page without proper HTML encoding, may lead to markup injection. A classic example of a potential vector is a site search engine: if one searches for a string, the search string will typically be redisplayed verbatim on the result page to indicate what was searched for. If this response does not properly escape or reject HTML control characters, a crosssite scripting flaw will ensue.\n\nIncorrect answers:\n\nWebsite defacement vulnerability\nWebsite defacements are the unauthorized modification of web pages, including the addition, removal, or alteration of existing content. These attacks are commonly carried out by hacktivists, who compromise a website or web server and replace or alter the hosted website information with their own messages.\n\nSQL injection vulnerability https://en.wikipedia.org/wiki/SQL_injection\nSQL injection is a code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker). SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.\n\nCross-site Request Forgery vulnerability https://en.wikipedia.org/wiki/Crosssite_request_forgery\nCross-site request forgery, also known as one-click attack or session riding and abbreviated as CSRF (sometimes pronounced sea-surf) or XSRF, is a type of malicious exploit of a website where unauthorized commands are submitted from a user that the web application trusts. There are many ways in which a malicious website can transmit such commands; specially-crafted image tags, hidden forms, and JavaScript XMLHttpRequests, for example, can all work without the user's interaction or even knowledge. Unlike cross-site scripting (XSS), which exploits the trust a user has for a particular site, CSRF exploits the trust that a site has in a user's browser."
    },
    {
        "pregunta": "Victor, a white hacker, received an order to perform a penetration test from the company \"Test us\". He finds an employee's email and sends a phishing email impersonating the employee's boss, leading to network compromise. What type of attack did Victor use?",
        "opciones": [
            "A) Eavesdropping", 
            "B) Piggybacking", 
            "C) Social engineering", 
            "D) Tailgating"
            ],
        "respuesta": "C",
        "explicacion": "Victor used social engineering by impersonating a trusted figure (the employee's boss) and leveraging psychological manipulation (urgency) to trick the employee into clicking a malicious link.  This is a classic phishing attack, a subset of social engineering."
    },
    {
        "pregunta": "Which of the following Nmap's commands allows you to most reduce the probability of detection by IDS when scanning common ports?",
        "opciones": [
            "A) nmap -sT -O -T0", 
            "B) nmap -A --host-timeout 99-T1", 
            "C) nmap -sT -O -T2", 
            "D) nmap -A – Pn"
            ],
        "respuesta": "A",
        "explicacion": "The `-T0` option in Nmap specifies the 'paranoid' timing template, which is the slowest and most stealthy scan option. It minimizes the chances of detection by intrusion detection systems (IDS) by sending packets very slowly."
    },
    {
        "pregunta": "Which of the following is a network software suite designed for 802.11 WEP and WPA-PSK keys cracking that can recover keys once enough data packets have been captured?",
        "opciones": [
            "A) Aircrack-ng", 
            "B) WLAN-crack", 
            "C) Airguard", 
            "D) Wificracker"
            ],
        "respuesta": "A",
        "explicacion": "Aircrack-ng is a well-known and widely used suite of tools specifically designed for wireless network security assessment, including capturing packets and cracking WEP and WPA/WPA2-PSK keys."
    },
    {
        "pregunta": "Which of the following best describes code injection?",
        "opciones": [
            "A) Form of attack in which a malicious user gains access to the codebase on the server and inserts new code.", 
            "B) Form of attack in which a malicious user inserts additional code into the JavaScript running in the browser.", 
            "C) Form of attack in which a malicious user gets the server to execute arbitrary code using a buffer overflow.", 
            "D) Form of attack in which a malicious user inserts text into a data field interpreted as code."],
        "respuesta": "D",
        "explicacion": "Code injection involves injecting malicious code into an application by exploiting vulnerabilities in how the application handles user-supplied input. The injected code is then interpreted and executed by the application."
    },
    {
        "pregunta": "John, a pentester, received an order to conduct an internal audit in the company. One of its tasks is to search for open ports on servers. Which of the following methods is the best solution for this task?",
        "opciones": [
            "A) Scan servers with Nmap.", 
            "B) Scan servers with MBSA.", 
            "C) Manual scan on each server.", 
            "D) Telnet to every port on each server."
            ],
        "respuesta": "A",
        "explicacion": "Nmap is a powerful and versatile network scanning tool specifically designed for port scanning, service detection, and operating system detection. It's the most efficient and reliable tool for this task."
    },
    {
        "pregunta": "Which of the following is an encryption technique where data is encrypted by a sequence of photons that have a spinning trait while travelling from one end to another?",
        "opciones": [
            "A) Hardware-Based.", 
            "B) Quantum Cryptography.", 
            "C) Homomorphic.", 
            "D) Elliptic Curve Cryptography."
            ],
        "respuesta": "B",
        "explicacion": "Quantum cryptography uses the principles of quantum mechanics, specifically the properties of photons (like their polarization or 'spin'), to perform cryptographic tasks. This is fundamentally different from classical cryptography, which relies on mathematical complexity."
    },
    {
        "pregunta": "Identify the standard by the description: A regulation contains a set of guidelines that everyone who processes any electronic data in medicine should adhere to. It includes information on medical practices, ensuring that all necessary measures are in place while saving, accessing, and sharing any electronic medical data to secure patient data.",
        "opciones": [
            "A) COBIT", 
            "B) ISO/IEC 27002", 
            "C) HIPAA", 
            "D) FISMA"
            ],
        "respuesta": "C",
        "explicacion": "The Health Insurance Portability and Accountability Act (HIPAA) is a US law specifically designed to protect the privacy and security of patient health information in the healthcare industry."
    },
    {
        "pregunta": "You makes a series of interactive queries, choosing subsequent plaintexts based on the information from the previous encryptions. What type of attack are you trying to perform?",
        "opciones": [
            "A) Chosen-plaintext attack", 
            "B) Ciphertext-only attack", 
            "C) Known-plaintext attack", 
            "D) Adaptive chosen-plaintext attack"
            ],
        "respuesta": "D",
        "explicacion": "An adaptive chosen-plaintext attack is a type of chosen-plaintext attack where the attacker can dynamically choose subsequent plaintexts to be encrypted based on the results of previous encryptions. This iterative process allows the attacker to refine their attack and potentially gain more information."
    },
    {
        "pregunta": "Which of the following options represents a conceptual characteristic of an anomaly-based IDS over a signature-based IDS?",
        "opciones": [
            "A) Can identify unknown attacks.", 
            "B) Produces less false positives.", 
            "C) Cannot deal with encrypted network traffic.", 
            "D) Requires vendor updates for a new threat."
            ],
        "respuesta": "A.",
        "explicacion": "Anomaly-based intrusion detection systems (IDS) are designed to detect deviations from established 'normal' behavior.  This allows them to potentially identify *new* or *zero-day* attacks that wouldn't be recognized by a signature-based IDS, which relies on a database of known attack patterns."
    },
    {
        "pregunta": "Alex, the penetration tester, performs a server scan. To do this, he uses the method where the TCP Header is split into many packets so that it becomes difficult to determine what packages are used for. Determine the scanning technique that Alex uses?",
        "opciones": [
            "A) ACK flag scanning", 
            "B) TCP Scanning", 
            "C) IP Fragmentation Scan", 
            "D) Inverse TCP flag scanning"],
        "respuesta": "C",
        "explicacion": "IP fragmentation scanning involves splitting the TCP header across multiple IP packets. This technique can bypass some firewalls and intrusion detection systems that don't properly reassemble fragmented packets for inspection."
    },
    {
        "pregunta": "You conduct an investigation and finds out that the browser of one of your employees sent malicious requests that the employee knew nothing about. Identify the web page vulnerability that the attacker used when the attack to your employee?",
        "opciones": [
            "A) File Inclusion Attack",
            "B) Cross-Site Request Forgery (CSRF)",
            "C) Command Injection Attacks",
            "D) Hidden Field Manipulation Attack"
        ],
        "respuesta": "B",
        "explicacion": "Cross-site request forgery, also known as one-click attack or session riding and abbreviated as CSRF (sometimes pronounced sea-surf) or XSRF, is a type of malicious exploit of a website where unauthorized commands are submitted from a user that the web application trusts. There are many ways in which a malicious website can transmit such commands; specially-crafted image tags, hidden forms, and JavaScript XMLHttpRequests, for example, can all work without the user's interaction or even knowledge. Unlike cross-site scripting (XSS), which exploits the trust a user has for a particular site, CSRF exploits the trust that a site has in a user's browser.\nIn a CSRF attack, an innocent end-user is tricked by an attacker into submitting a web request that they did not intend. This may cause actions to be performed on the website that can include inadvertent client or server data leakage, change of session state, or manipulation of an end user's account.\n\nIncorrect answers:\n\nCommand Injection Attacks\nCommand injection is an attack in which the goal is the execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user-supplied data (forms, cookies, HTTP headers, etc.) to a system shell.\n\nFile Inclusion Attack https://en.wikipedia.org/wiki/File_inclusion_vulnerability\nA file inclusion vulnerability is a type of web vulnerability that is most commonly found to affect web applications that rely on a scripting run time. This issue is caused when an application builds a path to executable code using an attacker-controlled variable in a way that allows the attacker to control which file is executed at run time. A file include vulnerability is distinct from a generic directory traversal attack, in that directory traversal is a way of gaining unauthorized file system access, and a file inclusion vulnerability subverts how an application loads code for execution. Successful exploitation of a file inclusion vulnerability will result in remote code execution on the web server that runs the affected web application. An attacker can use remote code execution to create a web shell on the web server, which can be used for website defacement.\n\nHidden Field Manipulation Attack\nManipulating Hidden Fields: An adversary exploits a weakness in the server's trust of client-side processing by modifying data on the client-side, such as price information, and then submitting this data to the server, which processes the modified data. For example, eShoplifting is a data manipulation attack against an on-line merchant during a purchasing transaction. The manipulation of price, discount or quantity fields in the transaction message allows the adversary to acquire items at a lower cost than the merchant intended. The adversary performs a normal purchasing transaction but edits hidden fields within the HTML form response that store price or other information to give themselves a better deal. The merchant then uses the modified pricing information in calculating the cost of the selected items."
    },
    {
        "pregunta": "Identify the type of jailbreaking which allows user-level access and does not allow iboot-level access?",
        "opciones": [
            "A) Userland Exploit",
            "B) Bootrom Exploit",
            "C) iBootrom Exploit",
            "D) iBoot Exploit"
        ],
        "respuesta": "A",
        "explicacion": "Jailbreaking can be defined as a process of installing a modified set of kernel patches that allows users to run third party applications not signed by OS vendor.\nIt provides root level access of the operating system and permits downloading of third-party applications, themes, extensions on an iOS devices.\nIt removes sandbox instructions, enabling malicious applications to get access to restricted mobile resources and information. Types of jailbreaking: Tethered, Semi- Tethered and Untethered.\n\nTypes Of jailbreaking exploits:\n1. Userland Exploit: It allows user-level access but does not allow iboot-level access.\n2. iBoot Exploit: An iBoot jailbreak allows user-level and iboot-level access.\n3. Bootrom Exploit: It allows user-level access and iboot-level access."
    },
    {
        "pregunta": "Determine the type of SQL injection:\nSELECT * FROM user WHERE name = 'x' AND userid IS NULL; --';",
        "opciones": [
            "A) UNION SQL Injection.",
            "B) End of Line Comment.",
            "C) Tautology.",
            "D) Illegal/Logically Incorrect Query."
        ],
        "respuesta": "B",
        "explicacion": "End-of-Line Comment: After injecting code into a particular field, legitimate code that follows if nullified through the usage of end of line comments."
    },
    {
        "pregunta": "Which of the following SQL injection attack does an attacker usually bypassing user authentication and extract data by using a conditional OR clause so that the condition of the WHERE clause will always be true?",
        "opciones": [
            "A) UNION SQLi",
            "B) Error-Based SQLi",
            "C) End-of-Line Comment",
            "D) Tautology"
        ],
        "respuesta": "D",
        "explicacion": "In a tautology-based attack, the code is injected using the conditional OR operator such that the query always evaluates to TRUE. Tautology-based SQL injection attacks are usually bypass user authentication and extract data by inserting a tautology in the WHERE clause of a SQL query. The query transform the original condition into a tautology, causes all the rows in the database table are open to an unauthorized user. A typical SQL tautology has the form \"or \", where the comparison expression uses one or more relational operators to compare operands and generate an always true condition. If an unauthorized user input user id as abcd and password as anything' or 'x'='x then the resulting query will be:\nselect * from user_details where userid = 'abcd' and password = 'anything' or 'x'='x'\n\nIncorrect answers:\n\nError-based SQLi\nThe Error based technique, when an attacker tries to insert malicious query in input fields and get some error which is regarding SQL syntax or database.\nFor example, SQL syntax error should be like this:\nYou have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ‘‘VALUE’’. The error message gives information about the database used, where the syntax error occurred in the query.\nError based technique is the easiest way to find SQL Injection.\n\nUNION SQLi\nWhen an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the UNION keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.\nThe UNION keyword lets you execute one or more additional SELECT queries and append the results to the original query. For example:\nSELECT a, b FROM table1 UNION SELECT c, d FROM table2\nThis SQL query will return a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.\nFor a UNION query to work, two key requirements must be met:\n· The individual queries must return the same number of columns.\n· The data types in each column must be compatible between the individual queries.\nTo carry out an SQL injection UNION attack, you need to ensure that your attack meets these two requirements.\n\nEnd-of-Line Comment\nAfter injecting code into a particular field, legitimate code that follows if nullified through the usage of end of line comments: SELECT * FROM user WHERE name = 'x' AND userid IS NULL; --';"
    },
    {
        "pregunta": "Which of the following is a protocol that used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block or an autonomous system?",
        "opciones": ["A) CAPTCHA", "B) Internet Engineering Task Force", "C) Internet Assigned Numbers Authority", "D) WHOIS"],
        "respuesta": "D",
        "explicacion": "WHOIS is a protocol specifically designed to query databases that contain information about the registration of domain names, IP addresses, and autonomous systems. It provides details about the owners and contacts associated with these resources."
    },
    {
        "pregunta": "Which of the following will allow you to prevent unauthorized network access to local area networks and other information assets by wireless devices?",
        "opciones": ["A) HIDS", "B) AISS", "C) WIPS", "D) NIDS"],
        "respuesta": "C",
        "explicacion": "A Wireless Intrusion Prevention System (WIPS) is specifically designed to monitor the wireless spectrum, detect unauthorized access points (rogue APs), and take actions to prevent unauthorized wireless access to the network."
    },
    {
        "pregunta": "Identify Secure Hashing Algorithm, which produces a 160-bit digest from a message on principles similar to those used in MD4 and MD5?",
        "opciones": ["A) SHA-2", "B) SHA-1", "C) SHA-0", "D) SHA-3"],
        "respuesta": "B",
        "explicacion": "SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value. It's based on principles similar to MD4 and MD5 but with a larger output size."
    },
    {
        "pregunta": "Ivan, the black hat hacker, split the attack traffic into many packets such that no single packet triggers the IDS. Which IDS evasion technique does Ivan use?",
        "opciones": ["A) Unicode Evasion.", "B) Session Splicing.", "C) Low-bandwidth attacks.", "D) Flooding."],
        "respuesta": "B",
        "explicacion": "Session splicing (or fragmentation) involves breaking the attack payload into multiple smaller packets. This can evade IDS that don't properly reassemble the packets for inspection. While the provided explanation uses the term 'whisker' and refers to it as 'session splicing', the core concept aligns more closely with fragmentation in general IDS evasion techniques."
    },
    {
        "pregunta": "Which of the following tools is packet sniffer, network detector and IDS for 802.11(a, b, g, n) wireless LANs?",
        "opciones": ["A) Abel", "B) Nessus", "C) Nmap", "D) Kismet"],
        "respuesta": "D",
        "explicacion": "Kismet is a wireless network detector, packet sniffer, and intrusion detection system specifically designed for 802.11 wireless networks (a, b, g, and n)."
    },
    {
        "pregunta": "What is the purpose of the demilitarized zone?",
        "opciones": ["A) To add a protect to network devices.", "B) To scan all traffic coming through the DMZ to the internal network.", "C) To provide a place for a honeypot.", "D) To add an extra layer of security to an organization's local area network."],
        "respuesta": "D",
        "explicacion": "A DMZ (demilitarized zone) is a subnetwork that sits between the public internet and an organization's internal (private) network. It provides an additional layer of security by isolating publicly accessible services (like web servers) from the more sensitive internal network."
    },
    {
        "pregunta": "You managed to compromise a server with an IP address of 10.10.0.5, and you want to get fast a list of all the machines in this network. Which of the following Nmap command will you need?",
        "opciones": ["A) nmap -T4 -F 10.10.0.0/24", "B) nmap -T4 -r 10.10.1.0/24", "C) nmap -T4 -q 10.10.0.0/24", "D) nmap -T4 -p 10.10.0.0/24"],
        "respuesta": "A",
        "explicacion": "The `nmap -T4 -F 10.10.0.0/24` command combines a fast scan (`-F`, which scans fewer ports than the default) with an aggressive timing template (`-T4`). This provides a relatively quick way to discover hosts on the 10.10.0.0/24 network.  While 'fast' is subjective, `-F` significantly reduces scan time compared to a default Nmap scan."
    },
    {
        "pregunta": "Attacker uses various IDS evasion techniques to bypass intrusion detection mechanisms. At the same time, IDS is configured to detect possible violations of the security policy, including unauthorized access and misuse. Which of the following evasion method depend on the Time-to-Live (TTL) fields of a TCP/IP ?",
        "opciones": ["A) Obfuscation", "B) Unicode Evasion", "C) Denial-of-Service Attack", "D) Insertion Attack"],
        "respuesta": "D",
        "explicacion": "Insertion attacks can exploit differences in how an IDS and the target host handle packets with manipulated TTL values. The attacker crafts packets with TTLs that allow them to reach the IDS but expire before reaching the intended target, causing the IDS to analyze traffic that the target never sees."
    },
    {
        "pregunta": "alert tcp any any -> 10.199.10.3 21 (msg: \"FTP on the network!\";)\nWhich system usually uses such a configuration setting?",
        "opciones": ["A) Firewall IPTable", "B) Router IPTable", "C) FTP Server rule", "D) IDS"],
        "respuesta": "D",
        "explicacion": "This configuration line resembles a rule for an Intrusion Detection System (IDS), such as Snort. It defines an alert that triggers when TCP traffic is detected going to IP address 10.199.10.3 on port 21 (the standard FTP port), displaying the message \"FTP on the network!\".  While other systems *might* have logging, this specific syntax is highly characteristic of IDS rule sets."
    },
    {
        "pregunta": "What is a \"Collision attack\"?",
        "opciones": ["A) Сollision attack on a hash tries to find two inputs producing the same hash value.", "B) Collision attacks break the hash into several parts, with the same bytes in each part to get the private key.", "C) Collision attacks attempt to recover information from a hash.", "D) Collision attacks try to change the hash."],
        "respuesta": "A",
        "explicacion": "A collision attack against a cryptographic hash function aims to find two different inputs that produce the same hash output (a 'collision').  This undermines the integrity properties of the hash function."
    },
    {
        "pregunta": "Determine the attack by the description: The known-plaintext attack used against DES. This attack causes that encrypting plaintext with one DES key followed by encrypting it with a second DES key is no more secure than using a single key.",
        "opciones": ["A) Traffic analysis attack", "B) Meet-in-the-middle attack", "C) Man-in-the-middle attack", "D) Replay attack"],
        "respuesta": "B",
        "explicacion": "The meet-in-the-middle attack is a known-plaintext attack that exploits the structure of multiple encryption. It works by encrypting from one end and decrypting from the other, meeting in the middle to find a matching key. This attack significantly reduces the effective key strength of double DES."
    },
    {
        "pregunta": "Identify a vulnerability in OpenSSL that allows stealing the information protected under normal conditions by the SSL/TLS encryption used to secure the Internet?",
        "opciones": ["A) SSL/TLS Renegotiation Vulnerability", "B) Heartbleed Bug", "C) Shellshock", "D) POODLE"],
        "respuesta": "B",
        "explicacion": "The Heartbleed bug was a serious vulnerability in the OpenSSL cryptographic library. It allowed attackers to read the memory of servers protected by vulnerable versions of OpenSSL, potentially exposing sensitive data like private keys, passwords, and user data."
    },
    {
        "pregunta": "The evil hacker Antonio is trying to attack the IoT device. He will use several fake identities to create a strong illusion of traffic congestion, affecting communication between neighbouring nodes and networks. What kind of attack does Antonio perform?",
        "opciones": ["A) Side-Channel Attack", "B) Forged Malicious Device", "C) Sybil Attack", "D) Exploit Kits"],
        "respuesta": "C",
        "explicacion": "A Sybil attack involves an attacker creating and controlling multiple fake identities within a network.  This can be used to manipulate voting systems, overwhelm resources, or, as described in the question, disrupt communication by simulating congestion."
    },
    {
        "pregunta": "Elon Tusk plans to make it difficult for the packet filter to determine the purpose of the packet when scanning. Which of the following scanning techniques will Elon use?",
        "opciones": ["A) ACK scanning.", "B) IPID scanning.", "C) ICMP scanning.", "D) SYN/FIN scanning using IP fragments."],
        "respuesta": "D",
        "explicacion": "SYN/FIN scanning with IP fragmentation divides the TCP header across multiple IP packets. This can bypass firewalls and IDS that don't reassemble packets for inspection, making it harder to detect the scan's purpose."
    },
    {
        "pregunta": "John, a penetration tester, decided to conduct SQL injection testing. He enters a huge amount of random data and observes changes in output and security loopholes in web applications. What SQL injection testing technique did John use?",
        "opciones": ["A) Dynamic Testing.", "B) Static Testing.", "C) Function Testing.", "D) Fuzzing Testing."],
        "respuesta": "D",
        "explicacion": "Fuzzing involves providing invalid, unexpected, or random data as input to a program (in this case, a web application). The tester then monitors the application for crashes, errors, or unexpected behavior, which can indicate vulnerabilities like SQL injection."
    },
    {
        "pregunta": "Which of the following Nmap options will you use if you want to scan fewer ports than the default?",
        "opciones": ["A) -p", "B) -T", "C) -sP", "D) -F"],
        "respuesta": "D",
        "explicacion": "The `-F` option in Nmap enables 'fast' mode, which scans only the 100 most common ports instead of the default 1000 ports. This significantly reduces scan time."
    },
    {
        "pregunta": "Rajesh, a network administrator found several unknown files in the root directory of his FTP server. He was very interested in a binary file named \"mfs\".  He found that an anonymous user uploaded and ran the script. The \"mfs\" file is running as a process and listening on a network port. What kind of vulnerability must exist to make this attack possible?",
        "opciones": ["A) File system permissions.", "B) Privilege escalation.", "C) Brute force login.", "D) Directory traversal."],
        "respuesta": "A",
        "explicacion": "For an attacker to upload a file to the root directory and then execute it, the file system permissions on the FTP server must be misconfigured.  Specifically, the anonymous user account has write access to the root directory and execute permissions on the uploaded file. While privilege escalation *might* be a *consequence* of running the malicious 'mfs' file, the *initial* vulnerability is incorrect file system permissions."
    },
    {
        "pregunta": "Michael works as a system administrator. He receives a message that several sites are no longer available.  He can ping the sites and access them via IP address, but not by URL. What problem could Michael identify?",
        "opciones": ["A) Traffic is Blocked on UDP Port 69", "B) Traffic is Blocked on UDP Port 53", "C) Traffic is Blocked on UDP Port 88", "D) Traffic is Blocked on UDP Port 56"],
        "respuesta": "B",
        "explicacion": "The ability to access the sites by IP address but not by URL strongly suggests a DNS resolution problem. DNS primarily uses UDP port 53. If traffic on this port is blocked (by a firewall, for instance), the system cannot translate domain names (URLs) into IP addresses."
    },
    {
        "pregunta": "Ivan, an evil hacker, conducts an SQLi attack that is based on True/False questions. What type of SQLi does Ivan use?",
        "opciones": ["A) Blind SQLi", "B) Classic SQLi", "C) DMS-specific SQLi", "D) Compound SQLi"],
        "respuesta": "A",
        "explicacion": "Blind SQL injection relies on asking the database true/false questions and observing the application's behavior to infer information about the database structure and data. The attacker doesn't directly see the results of their queries, but rather deduces information based on the application's responses."
    },
    {
        "pregunta": "Which of the following web application attack inject the special character elements \"Carriage Return\" and \"Line Feed\" into the user’s input to trick the web server, web application, or user into believing that the current object is terminated and a new object has been initiated?",
        "opciones": ["A) CRLF Injection.", "B) HTML Injection.", "C) Log Injection.", "D) Server-Side JS Injection."],
        "respuesta": "A",
        "explicacion": "CRLF injection involves inserting Carriage Return (CR) and Line Feed (LF) characters into user input. These characters are used to mark the end of a line in HTTP and other protocols. By injecting these characters, attackers can manipulate HTTP responses, potentially splitting responses, injecting headers, or performing other malicious actions."
    },
    {
        "pregunta": "John, a system administrator, is learning how to work with new technology: Docker. He will use it to create a network connection between the container interfaces and its parent host interface. Which of the following network drivers is suitable for John?",
        "opciones": ["A) Bridge networking.", "B) Macvlan networking.", "C) Host networking.", "D) Overlay networking."],
        "respuesta": "B",
        "explicacion": "Macvlan networking in Docker allows you to assign a MAC address to a container, making it appear as a physical device on the network. This is useful for applications that need direct access to the physical network, as opposed to being routed through the Docker host's network stack."
    },
    {
        "pregunta": "Mark, the network administrator, must allow UDP traffic on the host 10.0.0.3 and Internet traffic in the host 10.0.0.2. In addition to the main task, he needs to allow all FTP traffic to the rest of the network and deny all other traffic. Mark applies his ACL configuration on the router, and everyone has a problem with accessing FTP. In addition, hosts that are allowed access to the Internet cannot connect to it. In accordance with the following configuration, determine what happened on the network?\n1. access-list 102 deny tcp any any\n2. access-list 104 permit udp host 10.0.0.3 any\n3. access-list 110 permit tcp host 10.0.0.2 eq www any\n4. access-list 108 permit tcp any eq ftp any",
        "opciones": ["A) The ACL for FTP must be before the ACL 110.", "B) The ACL 104 needs to be first because is UDP.", "C) The ACL 110 needs to be changed to port 80.", "D) The first ACL is denying all TCP traffic, and the router is ignoring the other ACLs."],
        "respuesta": "D",
        "explicacion": "Cisco ACLs are processed sequentially. The first rule `access-list 102 deny tcp any any` denies *all* TCP traffic.  Because this rule matches all TCP packets, subsequent rules that permit specific TCP traffic (like FTP or web traffic) are never reached.  The router stops processing the ACL once a match is found."
    },
    {
        "pregunta": "Which of the following can be designated as \"Wireshark for CLI\"?",
        "opciones": ["A) nessus", "B) tcpdump", "C) ethereal", "D) John the Ripper"],
        "respuesta": "B",
        "explicacion": "tcpdump is a command-line packet analyzer, often described as a CLI (Command Line Interface) equivalent of Wireshark.  Both tools capture and analyze network traffic, but tcpdump operates entirely in the terminal, while Wireshark has a graphical user interface."
    },
    {
        "pregunta": "The attacker posted a message and an image on the forum, in which he embedded a malicious link. When the victim clicks on this link, the victim's browser sends an authenticated request to a server. What type of attack did the attacker use?",
        "opciones": [
            "A) Cross-site request forgery",
            "B) Cross-site scripting",
            "C) SQL injection",
            "D) Session hijacking"
        ],
        "respuesta": "A",
        "explicacion": "Cross-site request forgery, also known as one-click attack or session riding and abbreviated as CSRF (sometimes pronounced sea-surf) or XSRF, is a type of malicious exploit of a website where unauthorized commands are submitted from a user that the web application trusts. There are many ways in which a malicious website can transmit such commands; specially-crafted image tags, hidden forms, and JavaScript XMLHttpRequests, for example, can all work without the user's interaction or even knowledge. Unlike cross-site scripting (XSS), which exploits the trust a user has for a particular site, CSRF exploits the trust that a site has in a user's browser.\nIn a CSRF attack, an innocent end user is tricked by an attacker into submitting a web request that they did not intend. This may cause actions to be performed on the website that can include inadvertent client or server data leakage, change of session state, or manipulation of an end user's account.\n\nIncorrect answers:\n\nCross-site scripting https://en.wikipedia.org/wiki/Cross-site_scripting\nCross-site scripting (XSS) is a type of security vulnerability typically found in web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites accounted for roughly 84% of all security vulnerabilities documented by Symantec up until 2007. XSS effects vary in range from a petty nuisance to significant security risk, depending on the sensitivity of the data handled by the vulnerable site and the nature of any security mitigation implemented by the site's owner network.\n\nSession hijacking https://en.wikipedia.org/wiki/Session_hijacking\nSession hijacking, sometimes also known as cookie hijacking is the exploitation of a valid computer session—sometimes also called a session key—to gain unauthorized access to information or services in a computer system. In particular, it is used to refer to the theft of a magic cookie used to authenticate a user to a remote server. It has particular relevance to web developers, as the HTTP cookies used to maintain a session on many web sites can be easily stolen by an attacker using an intermediary computer or with access to the saved cookies on the victim's computer (see HTTP cookie theft). After successfully stealing appropriate session cookies an adversary might use the Pass the Cookie technique to perform session hijacking. Cookie hijacking is commonly used against client authentication on the internet. Modern web browsers use cookie protection mechanisms to protect the web from being attacked.\n\nSQL injection https://en.wikipedia.org/wiki/SQL_injection\nSQL injection is a code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker). SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database."
    }

]



# --- Frases de felicitación (The Matrix) ---
frases_aprobado = [
    "You have awakened from the Matrix!",
    "You are the One. You have mastered knowledge!",
    "You know now cyber Kung-Fu, sort of.",
    "The Matrix has no control over you",
    "Your mind is free.",
    "You have followed the white rabbit.",
    "You have dodged the bullets of ignorance.",
    "You know the path, now you have walked it.",
    "You have proof that there is no spoon."
]

# --- Frases de ánimo (The Matrix) ---
frases_suspenso = [
    "The Matrix still has you.",
    "You're still connected.",
    "Don't worry, Neo also fell the first time.",
    "Remember, there is no spoon...",
    "Failure is only an illusion.",
]

# --- Frases de saludo/bienvenida (The Matrix) ---
frases_bienvenida = [
    "Welcome to the rabbit hole. Are you ready to see how deep it goes?",
    "Wake up Neo...",
    "The Matrix has you... or so it thinks. Prove you can break free.",
    "Follow the white rabbit...",
    "Blue pill or red pill? Today, the choice is to answer correctly.",
    "Don't try to bend the spoon, that's impossible. Try to realize the truth... Do you know the Matrix?",
]

# --- Frases de despedida (The Matrix) ---
frases_despedida = [
    "The Matrix awaits... for your next attempt.",
    "Disconnect... for now. But remember, the truth is out there.",
    "See you soon. Remember, all I'm offering is the truth, nothing more.",
    "It's time to go back to the Matrix... or maybe not. You decide!",
    "The future is not written. Come back when you're ready to rewrite it."
]

# --- Frases para empezar el test (The Matrix) ---
frases_empezar = [
    "Are you ready to see if you are The One?",
    "Dare you take the red pill of knowledge?",
    "It's time to break free... or not. Shall we begin?",
    "Ready to challenge the Matrix?",
    "The door to the truth is open. Do you enter?"
]

# --- Frases para continuar (The Matrix)
frases_continuar = [
    "Follow the path, Neo...",
    "The Matrix watches you...",
    "Dont think you are, be sure you are...",
    "Free... your... mind...",
    "Still have time to...",
]


def presentacion():
    print("*" * 40)
    print(random.choice(frases_bienvenida))
    print("*" * 40)
    print("This program will test you, as if you were inside the Matrix itself.")
    print("You decide how many questions you want to face. No AIs here, just cold reality.")
    print("To break free (pass), you'll need at least 75% correct. There are no shortcuts.")
    print()

def solicitar_numero_preguntas(cuestionario):
    while True:
        try:
            num_preguntas = int(input("How many questions do you want to answer? (Maximum " + str(len(cuestionario)) + "): "))
            if 1 <= num_preguntas <= len(cuestionario):
                return num_preguntas
            else:
                print(f"Please enter a number between 1 and {len(cuestionario)}.")
                print()
        except ValueError:
            print("That's not a valid number. Try again.")
            print()


def realizar_test(cuestionario, num_preguntas):
    preguntas_aleatorias = random.sample(cuestionario, num_preguntas)
    respuestas_usuario = []

    for pregunta in preguntas_aleatorias:
        print(pregunta["pregunta"])
        for opcion in pregunta["opciones"]:
            print(opcion)

        respuesta_usuario = input("Your answer (A, B, C, D): ").upper()
        while respuesta_usuario not in ["A", "B", "C", "D"]:
            respuesta_usuario = input("There's no room for typos in the Matrix. Choose A, B, C, or D: ").upper()

        # --- DEBUGGING ---
        #print(f"DEBUG: Respuesta usuario: {respuesta_usuario}, Respuesta correcta: {pregunta['respuesta']}, Son iguales?: {respuesta_usuario == pregunta['respuesta']}")
        #respuestas_usuario.append((pregunta, respuesta_usuario))
        #print()

    return respuestas_usuario


def mostrar_resultados(respuestas_usuario, total_preguntas):
    print("*" * 30)
    print("       FINAL RESULTS")
    print("*" * 30)

    aciertos = 0
    fallos = []

    for pregunta, respuesta_usuario in respuestas_usuario:
        if respuesta_usuario == pregunta["respuesta"]:
            aciertos += 1
        else:
            fallos.append(pregunta)

    print(f"\nYour final score is: {aciertos} / {total_preguntas}")

    nota_minima = total_preguntas * 0.75
    if aciertos >= nota_minima:
        print("\n" + random.choice(frases_aprobado))
    else:
        print("\n" + random.choice(frases_suspenso))

    if fallos:
       print("\n--- Mistakes Made ---")
       for pregunta in fallos:
           print(f"\nQuestion: {pregunta['pregunta']}")
           print(f"Explanation: {pregunta['explicacion']}")



# --- Programa Principal ---
presentacion()
num_preguntas = solicitar_numero_preguntas(cuestionario)
empezar = input(f"{random.choice(frases_empezar)} (Y/N): ").upper()


if empezar == "Y":
    respuestas_finales = realizar_test(cuestionario, num_preguntas)
    mostrar_resultados(respuestas_finales, num_preguntas)
    print("\n" + random.choice(frases_despedida))

else:
    print("\n" + random.choice(frases_despedida))
