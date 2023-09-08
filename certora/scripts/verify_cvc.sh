if [[ "$1" ]]
then
    RULE="--rule $1"
fi

certoraRun ./certora/conf/cvc.conf $RULE