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

- Use select() in a loop to monitor everything
- Simple features like versioning will be function calls
- Time-consuming stuff like mining should be in another thread to avoid blocking
