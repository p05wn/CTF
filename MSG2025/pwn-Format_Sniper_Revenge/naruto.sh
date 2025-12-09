#!/bin/bash

SESSION_NAME="python_panels"

start_idx=$1
end_idx=$start_idx+3


tmux new-session -d -s $SESSION_NAME

tmux send-keys -t $SESSION_NAME "python3 exp.py 0; read -p 'Press Enter to close panel...'" C-m

for i in $(seq $start_idx $end_idx); do
    tmux split-window -t $SESSION_NAME -v "python3 exp.py $i; read -p 'Press Enter to close panel...'"
    tmux select-layout -t $SESSION_NAME tiled
done

tmux attach-session -t $SESSION_NAME

