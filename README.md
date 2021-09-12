# BlockBusters: Using Memory Forensics to Bust Criminals on the Blockchain
![BlockBusters](https://github.com/joezbub/blockchain-forensics/blob/main/images/big-logo.jpeg)

## About
Volatility plugins to extract crypto wallet data from a memory image. The main plugin, `block_busters` in `block-busters.py`, outputs a key pair (public and private key from elliptic curve cryptography) given the PID of the wallet process. It traverses the Python garbage collection generations to find and contextualize data structures from the pyco/cryptography library.

Our experiments were conducted on VirtualBox VMs running Ubuntu 18.04 (image: 5.3.0-62-generic) with 8 GB RAM and Python 3.7.6.


## Usage
Clone this repository into your Volatility directory. Install dependencies for `profileGen.py`:

`pip install pyelftools`

Make sure that the input path in `python-gc-traverse.py` and the output paths in `profileGen.py` are correct. Create a json profile of the python binary running in your target VM. Run `profileGen.py`:

`python3 profileGen.py ./ELFs/*PYTHON BINARY*`

A profile should be generated in `ScriptOutputs`.

To execute plugins, cd into the volatility directory and execute:
<pre><code>$ python vol.py --plugins=./AI-Psychiatry/ --profile=*LINUX PROFILE* -f *PATH TO MEMORY DUMP* *PLUGIN NAME* -p *Python PID*</code></pre>
