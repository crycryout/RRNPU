Overview
========

The enet_rxtx example shows the simplest way to use ENET driver for simple 
frame receive and transmit.

1. This example shows how to initialize the ENET MAC.
2. How to use ENET MAC to receive and transmit frame.

The example transmits 20 number broadcast frame, print the frame length, source MAC address
and destination MAC address when receive frame.

Note, The RMII mode is used for default setting to initialize the ENET interface between MAC and the external PHY. you
can change it to MII mode as you wish. Please make sure the MII Mode setting in the MAC is synchronize to the setting
in TWR-SERIAL board for the external PHY.

SDK version
===========
- Version: 2.16.000

Toolchain supported
===================
- IAR embedded Workbench  9.60.1
- GCC ARM Embedded  13.2.1

Hardware requirements
=====================
- USB Type-C cable
- Loopback network cable RJ45 standard (optional)
- MCIMX93-EVK board
- Personal Computer

Board settings
==============
No special settings are required.

Note
Please run the application in Low Power boot mode (without Linux BSP).
The IP module resource of the application is also used by Linux BSP.
Or, run with Single Boot mode by changing Linux BSP to avoid resource
conflict.

Prepare the Demo
================
1.  Connect a USB cable between the host PC and the OpenSDA USB port on the target board.
2.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control
3.  Download the program to the target board.
4.  Either press the reset button on your board or launch the debugger in your IDE to begin running the demo.

Running the demo
================
When the demo runs, the log would be seen on the terminal like:

ENET example start.

The 1 frame transmitted success.
The 2 frame transmitted success.
The 3 frame transmitted success.
The 4 frame transmitted success.
......
The 20 frame transmitted success.


The transmitted frame is a 1000 length broadcast frame.
When a 1000 length frame is received, the log would be added to the terminal like:
A frame received. the length 1000 Dest Address xx:xx:xx:xx:xx:xx Src Address xx:xx:xx:xx:xx:xx

Optionally, you may use a loop back cable
Make a loopback network cable:
      568B standard 	 Unknowed standard
J1    orange+white       green+white
J2    orange             green
J3    green+white        orange+white
J4    blue               brown+white
J5    blue+white         brown
J6    green              orange
J7    brown+white        blue
J8    brown              blue+white

Connect J1 => J3, J2 => J6, J4 => J7, J5 => J8. 10/100M transfer only requires J1, J2, J3, J6, and 1G transfer requires all 8 pins.
Check your net cable color order and refer to the 568B standard or the other standard. If your cable's color order is not showed in the list,
please connect J1~J8 based on your situation.

1.  Add #define EXAMPLE_USES_LOOPBACK_CABLE 1  into app.h and rebuild the example.
2.  Insert loopback network cable to Ethernet RJ45 port.
3.  Run the demo in the same way as described earlier.
