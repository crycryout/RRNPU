Overview
========
The flexcan_loopback_edma example shows how to use the EDMA version transactional driver to receive
CAN Message from Rx FIFO:

To demonstrates this example, only one board is needed. The example will config one FlexCAN Message
Buffer to Tx Message Buffer and also setup Rx FIFO. After that, the example will send 4 CAN Messages
from Tx Message Buffer to Rx FIFO through internal loopback interconnect and read them out using
EDMA version FlexCAN transactional driver. The Sent and received message will be print out to terminal
at last.

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
- MCIMX93-EVK  board
- JLink Plus
- 12V~20V power supply
- Personal Computer

Board settings
==============
No special is needed.

Prepare the Demo
================
1.  Connect 12V~20V power supply and JLink Plus to the board, switch SW301 to power on the board
2.  Connect a USB Type-C cable between the host PC and the J1401 USB port on the target board.
3.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control
4. Boot Linux BSP to u-boot, and load M core image from SD card to run. (Put the image into SD card before.)
   => load mmc 1:1 0x80000000 /sdk20-app.bin
   => cp.b 0x80000000 0x201e0000 0x20000
   => bootaux 0x1ffe0000 0

Running the demo
================
When the example runs successfully, following information can be seen on the terminal:

~~~~~~~~~~~~~~~~~~~~~

==FlexCAN loopback edma example -- Start.==

Send Msg1 to Rx FIFO: word0 = 0x11111111, word1 = 0x11111111.
Send Msg2 to Rx FIFO: word0 = 0x22222222, word1 = 0x22222222.
Send Msg3 to Rx FIFO: word0 = 0x33333333, word1 = 0x33333333.
Send Msg4 to Rx FIFO: word0 = 0x44444444, word1 = 0x44444444.

Receive Msg1 from FIFO: word0 = 0x11111111, word1 = 0x11111111, ID Filter Hit2.
Receive Msg2 from FIFO: word0 = 0x22222222, word1 = 0x22222222, ID Filter Hit2.
Receive Msg3 from FIFO: word0 = 0x33333333, word1 = 0x33333333, ID Filter Hit2.
Receive Msg4 from FIFO: word0 = 0x44444444, word1 = 0x44444444, ID Filter Hit2.

==FlexCAN loopback EDMA example -- Finish.==
~~~~~~~~~~~~~~~~~~~~~
