#!/bin/bash


DECLARATIONFILE=$1
BIGIPMGMTIP=$2
RUNDELETE=$3
DELETEONLY=$4

if [ $RUNDELETE == "DELETE" ];
then
    # remove existing declaration by POST'ing an empty declaration
    echo "DELETE: sending empty declaration to start fresh"
    DELETEDEC=$(curl -k -s -u 'lsimon:f5!@21Pss' -X DELETE https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/declare | jq .results[].message)
    echo -e "DELETE: result.message:\n$DELETEDEC"

    # echo "DELETE: Check if delete was successful"
    # if [[ "$DELETEDEC" == *"Declaration successfully"* ]] || [[ "$DELETEDEC" == *"no change"* ]];
    # then
    #     echo "DELETE: successful, continue"
    # else
    #     echo "DELETE: failed, check"
    # fi
fi

if [ $DELETEONLY == "ONLY" ];
then
    echo "ONLY argument passed in, stopping script"
    exit 0
fi


#sleep 60
#read -p "Press enter to continue"

echo "POST: Sending POST of declaration and getting TASKID"
#POST declaration and get TASK id
TASKID=$(curl -k -s -u 'lsimon:f5!@21Pss' -d @$DECLARATIONFILE https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/declare?async=true | jq .id | tr -d '"')
echo "POST: Here is the TASKID: $TASKID"

echo "POST: Sleeping for 5 seconds"
sleep 5

echo "CHECK POST: do loop until TASK no longer says in progress"
i=0
until [ ! $i -lt 65 ];
do
    COMMON1RESULT=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[0].message | tr -d '"')
    echo "CHECK POST: Is it still in progress? $COMMON1RESULT"
    if [[ $COMMON1RESULT != *"in progress"* ]];
    then
        echo "CHECK POST: Here is current results.message: $COMMON1RESULT"
        break
    else
        echo "CHECK POST: still checking, sleep 5 seconds..."
        sleep 5
        i=`expr $i + 1`
    fi
done

echo "TASK FIN: Now checking for success or failure of each tenant"
i=0
until [ ! $i -lt 65 ];
do
## Do until message says "success" or "no change" or "failed"
    COMMON1RESULT=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[0].message | tr -d '"')
    EXPPROXYRESULT=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[0].message | tr -d '"')
    COMMON2RESULT=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[2].message | tr -d '"')
    if ([[ $COMMON1RESULT == *"success"* ]] || [[ $COMMON1RESULT == *"no change"* ]]) && ([[ $EXPPROXYRESULT == *"success"* ]] || [[ $EXPPROXYRESULT == *"no change"* ]]) && ([[ $COMMON2RESULT == *"success"* ]] || [[ $COMMON2RESULT == *"no change"* ]]);
    then
        echo "Common1-adds Status: $COMMON1RESULT"
        echo "ExplicitProxy Status: $EXPPROXYRESULT"
        echo "Common2-deletes Status: $COMMON2RESULT"
        echo "TASK FIN: POST complete, checking for runTime next"
        break
    else
        echo "TASK FIN: 1st Common result: $COMMON1RESULT"
        echo "TASK FIN: ExpProxy result: $EXPPROXYRESULT"
        echo "TASK FIN: 2nd Common result: $COMMON2RESULT"
        i=`expr $i + 1`
        sleep 5
    fi
done

echo "GET RUNTIME: Getting the runTime of each tenant"
## Get runTime in ms of each tenant
COMMON1RUN=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[0].runTime | tr -d '"')
EXPPROXYRUN=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[1].runTime | tr -d '"')
COMMON2RUN=$(curl -k -s -u 'lsimon:f5!@21Pss' https://$BIGIPMGMTIP:8443/mgmt/shared/appsvcs/task/$TASKID | jq .results[2].runTime | tr -d '"')
echo "GET RUNTIME: runtTime of each"
echo -e "$COMMON1RUN\n$EXPPROXYRUN\n$COMMON2RUN"
