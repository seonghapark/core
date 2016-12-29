#!/bin/bash

#download the file 
rm /tmp/wagman_fw.ino.hex
wget http://www.mcs.anl.gov/research/projects/waggle/downloads/wagman/firmware.ino.hex -O /tmp/wagman_fw.ino.hex

#then call coresense flash
./wagmanflash /tmp/wagman_fw.ino.hex
