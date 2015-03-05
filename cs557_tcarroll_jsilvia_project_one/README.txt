****************************************************
*
* Password Wallet
*
* Written by: Tyler Carroll and James Silvia
* In completion of: CS557 Project 1
*
* A secure wallet to store passwords
*
* README
*
****************************************************

This document provides basic usage for the password 
 wallet application.

To compile the application:
	"make"

To remove the application and existing wallet:
	"make clean"
	
Once the application has been built...
	./pw_wallet
	
We recommend running the application with heightened
 user privilege to avoid untrusted tampering.
	
On a first log on, you will be prompted to enter your
 master password. Do not forget this master password
 -otherwise the data is not recoverable.

The master password must be 5 characters or longer and
 contain at least: (1) upper letter, (1) lower
 letter, and (1) number.
 
On successful log on, you will be given the text:

""""
Welcome to the password wallet!
Remember to back up your wallet.txt file in the event
of a corruption from an untrusted party
Valid commands are:
        add - add a password to the wallet
        list - retrieve a password from the wallet
        remove - remove a password from the wallet
        quit - exit the application
"""

The commands will be provided on each log on, and when
 an incorrect command is entered in to the wallet.
 
Enjoy!

Tyler & James

----------------------------------------------------
Please note this application has been developed and
 tested on CentOS release 6.3 with 'uname -r' of
 2.6.32-279.14.1.el6.x86_64.
 
Also, it has been tested on ccc.wpi.edu.

We do not guarantee operation besides those listed
 above.
----------------------------------------------------