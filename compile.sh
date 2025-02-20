#/bin/bash
NUM_THREADS=1024

if [ "$EUID" -ne 0 ]
  then echo "Please run this script as root"
  exit
fi

wall reboot_warning.txt
# A helper for compiling the kernel on the NVMM system
make -j${NUM_THREADS} && \
	make modules_install -j${NUM_THREADS} && \
	make install -j${NUM_THREADS} && \
	wall "System is rebooting, goodbye!" && \
	mkpmoreboot

