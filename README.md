# Packet Sender Program

This program sends packets read from a `.pcap` file to a specified IP address and port at a defined speed. It uses the `libpcap` library for packet manipulation and sending.

## Prerequisites

- Ensure you have `libpcap` installed on your system.
- `gcc` should be installed for compilation.
- The source file `send.c` should be ready in your working directory.

## Compilation

To compile the program, open your terminal, navigate to the directory containing `send.c`, and run the following command:

```sh
gcc -o send send.c -lpcap
./send

