Authors: Andrew Badger, Thach Hoang

## Ideas

Done:

- Use poll() in a loop to monitor everything
- Peer objects are collected in CBAssociativeArray
- At the start, actively connect to initial peers (kale.cs.umd.edu)
- Accept incoming connections, create new sockets and save new peers in corresponding peer objects
- Version exchange
- Ping/pong timer (60 seconds)

Pending:

- Send a get-address message to each peer (once), then try to connect to the results

## References

- poll() code from [IBM](http://pic.dhe.ibm.com/infocenter/iseries/v6r1m0/index.jsp?topic=/rzab6/poll.htm)
- [cbitcoin](https://github.com/MatthewLM/cbitcoin)
- [ping/pong specs](https://en.bitcoin.it/wiki/BIP_0031)

## Notes

### Variable length integer

[Source](https://bitcointalk.org/index.php?PHPSESSID=0j57qusrqmvof5lclsre0l4t02&topic=32849.msg410480#msg410480)

Look at the first byte.

If that first byte is less than 253, use the byte literally.

If that first byte is 253, read the next two bytes as a little endian 16-bit number (total bytes read = 3).

If that first byte is 254, read the next four bytes as a little endian 32-bit number (total bytes read = 5).

If that first byte is 255, read the next eight bytes as a little endian 64-bit number (total bytes read = 9).

## Setup

Install libraries:

```
sudo apt-get install libssl-dev
sudo apt-get install libev-dev
```

Add this line to .bashrc (use absolute path to /bitcoin417/bin):

```
export LD_LIBRARY_PATH=~/Documents/project/bitcoin417/bin:$LD_LIBRARY_PATH
```

Finally in /bitcoin417:

```
./configure; make clean; make examples-build
```

