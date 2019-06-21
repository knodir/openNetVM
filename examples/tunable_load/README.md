Tunable load
==
This NF is based on Basic Monitor. It generates parameter dependent CPU load
while processing each packet. Specifically, this NF looks at the UDP source port
number (N) and generates up-to-N prime numbers for each packet. For example, if
source port is 50, we run the function to generate first 50 primes for each
packet we receive.

Compilation and Execution
--
```
cd examples
make
cd tunable_load
./go.sh SERVICE_ID [PRINT_DELAY]

OR

./go.sh -F CONFIG_FILE -- -- [-p PRINT_DELAY]

OR

sudo ./build/tunable_load -l CORELIST -n NUM_MEMORY_CHANNELS --proc-type=secondary -- -r SERVICE_ID -- [-p PRINT_DELAY]
```

App Specific Arguments
--
  - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.

Config File Support
--
This NF supports the NF generating arguments from a config file. For
additional reading, see [Examples.md](../../docs/Examples.md)

See `../example_config.json` for all possible options that can be set.
