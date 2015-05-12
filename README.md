# Aurora PAM library

Aurora is a PAM library for n-factor authentication.


## Authors

- Cyrille TOULET <cyrille.toulet@linux.com>



## Installation

For ***Debian 7 (Whezzy)*** and ***Debian 8 (Jessie)***:
```sh
apt-get update
apt-get install gcc libpam0g-dev libconfig-dev libcurl3-dev uuid-dev
apt-get install sudo libpam0g libconfig9 libcurl3 libuuid1
make install
sudo cp -r etc/aurora /etc/
```

**Please note:** If your system has a /lib/security/ directory, visit the
Makefile to change the installation path.

You can also uninstall this library by using ```make uninstall``` 
(this command doesn't purge configuration files).



## Configuration

This PAM library has basic configuration:
 - To configure the email module, edit */etc/aurora/email.conf*
 - To configure the user directory, edit */etc/aurora/directory.conf*



### OpenSSH

This module can be usefull for SSH connections.
This section describe how to enable Aurora for OpenSSH.

Enable SSH challenge-response in */etc/ssh/sshd_config*:
```
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication yes
```

Enable the Auroram PAM modules for SSH in */etc/pam.d/sshd*:
```
# Aurora PAM module
auth       required     pam_aurora_email.so
```

And finaly reload the SSH daemon:
```sh
sudo service sshd reload
```

You can test the module in local:
```sh
ssh localhost
```



## More details

Passwords are often seen as a weak link in the security of today’s IT 
infrastructures.

And justifiably so:
 - **Re-usability**, which we’re all guilty of, guarantees that credentials 
   compromised on a system can be leveraged on many others. And given the 
   world we live in, password re-use is inevitable, we just have too many 
   accounts in too many places.
 - **Plain text protocols** are still used to transmit credentials, and the 
   result is that they are exposed to network sniffing. This is worsened by 
   the increase in wireless usage which broadcasts information. 
   Telnet, FTP, HTTP come to mind but they aren’t the only ones.
 - **Lack of encryption on storage** is a flaw that too often makes it way 
   into architecture design. How many databases have we heard about getting 
   hacked & dumped? How many have we not heard about?
 - **Password simplicity & patterns** are also factors weakening us against 
   bruteforce attacks.

One hot solution that is making its way into critical systems (banks, 
sensitive servers) is multi-factor authentication.

A few disadvantages of this two-factor implementation:
 - More steps required to get in.
 - Doesn’t support non TTY based applications.
 - Relying on external services (web service, message delivery), thus adding 
   points of failure. Implementing a fail-safe is to be considered.
 - SSH handles key authentication on its own, meaning a successful key auth 
   does not go through PAM and thus does not get a chance to do the 2nd factor.
   You might want to disable key authentication in sshd’s config.
