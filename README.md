# LPOS

Leader selection In Proof of Stake
# USAGE
Using `virtualenv` is recommended.
## Runing tests
### Unit Test
`python -m unittest test`
## Running manually
* First start the discovery server, and indicates the number of nodes
    * `python -m src.discovery` 
    * For more information, see the help `python -m src.discovery -h`
* Then start nodes
    * `python -m src.node PORT N T POPULATION`
    * port means the bind port for the node, N means the numbers of senate, T means the number of malicious node, POPULATION means the number of nodes.
    *  The arguments N, T and POPULATION must be the same on all the nodes
    * For more information, see the help `python -m src.node -h`

## An example on gumby
* see [My Gumby experiments](https://github.com/LiWeiJie/gumby/tree/testcode/experiments/consensus_wj)  
* The Build Execute shell
    ```
    #!/bin/bash

    set -x

    export WITH_SYSTEMTAP=false

    gumby/scripts/build_virtualenv.sh

    source ~/venv/bin/activate

    env

    export GUMBY_DAS4_NODE_TIMEOUT=600
    #export GUMBY_das4_instances_to_run=500
    export GUMBY_das4_instances_to_run=40
    export GUMBY_das4_node_amount=10

    #export GUMBY_das4_node_amount="$(( GUMBY_das4_instances_to_run / 40 ))"
    # export GUMBY_das4_node_amount=6

    export GUMBY_LOG_LEVEL=DEBUG
    export GUMBY_PROFILE_MEMORY=FALSE

    n=1
    t="$(( n / 4 ))"
    delay=30
    experiment="tx-n-outputs"
    param=20
    # profile='--profile $OUTPUT_DIR\/$RANDOM.stats'
    profile=''


    #chain="genic"
    chain="10_rich_man"
    #chain="100_rich_man"

    OUTPUT_DIR='..\/output'

    node_command="python -m src.node 0 $n $t $GUMBY_das4_instances_to_run -d --discovery $(hostname) --fan-out 10 --chain $chain --output_dir $OUTPUT_DIR --ignore-promoter $profile"
    discovery_command="python -m src.discovery -n $n -t $t -m $GUMBY_das4_instances_to_run -l 100 --fan-out 5 --output_dir $OUTPUT_DIR --inst $delay $experiment $param"

    sed -i "s/NODE_COMMAND/$node_command/" gumby/experiments/consensus_wj/run.sh
    sed -i "s/DISCOVERY_COMMAND/$discovery_command/" gumby/experiments/consensus_wj/run_discovery.sh

    mkdir ./consensus-code/log

    pip install --upgrade protobuf

    ./gumby/run.py gumby/experiments/consensus_wj/consensus_wj_das5.conf
    ```
# About
```
├── README.md
├── config
│   ├── blocks.json
│   ├── config.json
│   └── long_blocks.json
├── data
│   ├── chain_100_rich_man.json
│   ├── chain_10_rich_man.json
│   ├── chain_genic.json
│   └── members
│       └── members.json
├── simulator_chain.py
├── src
│   ├── __init__.py
│   ├── chain
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── config.py
│   │   ├── model
│   │   │   ├── __init__.pyache__
│   │   │   ├── block_model.py
│   │   │   ├── chain_model.py
│   │   │   ├── member_model.py
│   │   │   ├── transaction_model.py
│   ├── discovery.py
│   ├── messages
│   │   ├── __init__.py
│   │   ├── messages.proto
│   │   ├── messages_pb2.py
│   │   └── protoc.sh
│   ├── node.py
│   ├── protobufreceiver.py
│   ├── protobufwrapper.py
│   ├── utils
│   │   ├── __init__.py
│   │   ├── encode_utils.py
│   │   ├── hash_utils.py
│   │   ├── message.py
│   │   ├── network_utils.py
│   │   ├── random_utils.py
│   │   ├── script_utils.py
├── test_chain.py
```
## Summary
This is the summary of the code.
* [src/node.py](src/node.py)
    * about the network connect, network packet send and receive, protocol analysis and handle
* [src/discovery.py](src/discovery.py)
    * store nodes' socket
* [src/messages](src/messages)
    * protocol prototype
    * Protocol Buffers - Google's data interchange format
* [src/chain](src/chain)
    * [src/chain/client.py](src/chain/client.py)
        * chain runner
    * [src/chain/model](src/chain/model)
        * including chain model, block model, transaction model and member model

