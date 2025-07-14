# Security Analysis of UYIKOO Spy Clock Camera 140 HD 1080P

## Overview
A study into the security of a commercially available hidden IP camera and the associated HDlivecam app it interfaces with. The camera is sold under a variety of different brands and is available [here](https://www.amazon.co.uk/Hidden-Camera-UYIKOO-140%C2%B0HD-Support/dp/B08NJQXBL1?crid=UIDV73UE68XY&dib=eyJ2IjoiMSJ9.dqrmB0qN4mv4CMAAQGmduKoCq0MxDxWnod3RHfZJv4ssxGI6U2NYG61AyyyxQUnf1mSMPNABkGJ1jksiOAkHq0WnVQQSuVwmmXe_liQDOKURG08oKTaKIvd1COghWcc2m4ZNoJnzxKw_rkwc80d4n-1V7x9j6yC9cfLzNtsWEQGNEYUmPRaQ5ntsB2owhyVCpmIEgShTHqyQiSusGJzyHU_9fWUG6pmroCkagGIlzv0.un2tnbalP01cE4OoostoSr3q2vYlDfmMzH1UEmBlTaQ&dib_tag=se&keywords=uyikoo+spy+clock+camera&qid=1752493662&sprefix=uyikoo+spy+clock+camer%2Caps%2C75&sr=8-4). A secondary camera was also investigated in less detail to form a comparison point.

## Methodology overview
This project was undertaken using Kali Linux attached to an Alfa network adapter. Wireshark was the primary tool used for analysis to discover vulnerabilities in the communication system along with Python for developing prototype attack scripts. 

For initial investigation a combination of JADX, NMAP and Wireshark were used to profile the camera and its network operations. Subsequent to this, the communication structures used by the camera and app were discovered along with potential weaknesses in the system. Python was then used with scapy to emulate a authorised user and perform several attacks on the camera.

## Results
The camera was found to have significant flaws in its communication system primarily based around JSON data transfers happening in plaintext. As a result commands are able to be captured by a malicious user and furthermore app login details can be captured unencrypted upon signup or login to the app. Moreover, with a combination of packet capturing and new packet construction in Python, an attacker can gain control over the camera commands either from the same network by directly spoofing commands or remotely by forging a connection to the HDLivecam servers.

For more information please see the report under `submission/project.pdf`
