Authors: Andrew Badger, Thach Hoang

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
	
## Ideas

Done:

- Use select() in a loop to monitor everything
- Peer objects are collected in CBAssociativeArray
- At the start, actively connect to initial peers (kale.cs.umd.edu)

Pending:

- Accept incoming connections, create new sockets and save them in corresponding peer objects
- Simple features like versioning will be function calls
- Time-consuming stuff like mining should be in another thread to avoid blocking

## References

- poll() code from [IBM](http://pic.dhe.ibm.com/infocenter/iseries/v6r1m0/index.jsp?topic=/rzab6/poll.htm)
- [cbitcoin](https://github.com/MatthewLM/cbitcoin)

## Notes

### Variable length integer

[Source](https://bitcointalk.org/index.php?PHPSESSID=0j57qusrqmvof5lclsre0l4t02&topic=32849.msg410480#msg410480)

Look at the first byte.

If that first byte is less than 253, use the byte literally.

If that first byte is 253, read the next two bytes as a little endian 16-bit number (total bytes read = 3).

If that first byte is 254, read the next four bytes as a little endian 32-bit number (total bytes read = 5).

If that first byte is 255, read the next eight bytes as a little endian 64-bit number (total bytes read = 9).

