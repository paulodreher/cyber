#!/bin/bash

for word in $(cat $1)
do
	found=$(curl -s -H "User-Agent: DesecTool" -o /dev/null -w "%{http_code}" $2/$word/)
        if [[ $found -eq "200" ]]
        then
            echo "Directory: $2/$word/"
        fi
done

echo "---------------------------------------------------------------------------------------------"

for word in $(cat $1)
do
	reply_folder=$(curl -s -H "User-Agent: DesecTool" -o /dev/null -w "%{http_code}" $2/$word.$3)
        if [[ $reply_folder -eq "200" ]]
        then
            echo "File: $2/$word.$3"
        fi
done



