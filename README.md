# LPOS

Leader selection In Proof of Stake

## Unit test

`python -m unittest test`

## Simulator (Not recommended, recommended to run on the cluster)
1. run discovery server
    
    `python -m src.discovery -l 100 --inst 2 tx-rate 3 -n 1 -t 0 --fan-out 10 -m 5 ` 

    ```
    usage: discovery.py [-h] [--port PORT] [-n [N]] [-t [T]] [-m [M]]
                    [--inst [INST [INST ...]]] [-l LOAD_MEMBER]
                    [--output_dir OUTPUT_DIR] [--fan-out FAN_OUT]

    optional arguments:
    -h, --help            show this help message and exit
    --port PORT           the listener port, default 8123
    -n [N]                the total number of promoters
    -t [T]                the total number of malicious nodes
    -m [M]                the total number of nodes
    --inst [INST [INST ...]]
                            the instruction to send after all nodes are connected
    -l LOAD_MEMBER, --load_member LOAD_MEMBER
                            the first n node will load the member file
    --output_dir OUTPUT_DIR
                            output dir
    --fan-out FAN_OUT     fan-out parameter for gossiping
    ```
2. run several(m) nodes

    `python -m src.node 0 1 0 3 -d --fan-out 10 --ignore-promoter --chain genic &`