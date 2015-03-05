/**********************************************************************
 *
 * P2P with TLS
 *
 * Written by: Tyler Carroll, James Silvia, Tom Strott
 * In completion of: CS557 Project 2
 *
 * A secure P2P storage system
 *
 * README
 *
 **********************************************************************/

This document provides basic usage for the P2P storage system.

Unzip contents in to directory.

To compile the application:
    "make"

To remove the applcation and associated datastores:
    "make clean"

Once the application has been built...
    ./peer
	
We recommend running the application with heightened
 user privilege to avoid untrusted tampering.

Possible peers for logon:
    atheon, templar, gatekeeper, oracle

You can store an index and value at any of the peers, from any of the
 peers above. Since this is a P2P network, both applcations must be
 up and running for data transmission.

On a first logon, you will be prompted to enter a master password. If
 you forget it, all data will be non-recoverable.

The master password must be 5 characters or longer and contain at the
 least: (1) upper letter, (1) lower letter, and (1) number.

On successful logon, you will be given the text:

"""
Logon Successful!

Valid commands are:
        send - send an index/value pair to another peer
        get  - retrieve a value for a specific index from another peer
        quit - exit the application
"""

The commands will be provided on each logon, and when an incorrect
 command is entered.

Enjoy!

Tyler, James, and Tom


------------------------------------------------------------------------
Please note this application has been developed and tested on CentOS
 release 6.3 with 'uname -r' of 2.6.32-279.14.1.e16.x86_64.

 Also, it has been tested on ccc.wpi.edu

 We do not guarentee operation besides those listed above.
------------------------------------------------------------------------
