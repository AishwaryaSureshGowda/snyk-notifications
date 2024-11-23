#!/bin/bash
set -e

# shell script to execute snyk security scans (Container)

# function to execute snyk container scans
executeContainerScans() {
    local repoName="$1"
    local scanType='snyk-container'
    local reportDir='snyk-report'
    local resultJSONFile='snyk-result.json'
    local resultTXTFile='snyk-result.txt'
    local resultHTMLFile='snyk-result.html'
    local severity='high'
    local snykOrg='fe66cd5a-ed4d-4b39-881d-d6cfd36ae86d'
    local environment='production-in'
    local dockerfilePath='Dockerfile'
    local containerImage=''

    if [ $repoName == 'scrut-cron-serverless' ]; then
        echo '>>> Ignoring due to absence of docker image'
        return
    fi

    cd $workdDir/$repoName
    
    echo -e '\n>>> Executing Snyk scan of type: Container'
    
    rm -rf $reportDir $metadataFile
    mkdir $reportDir
    reportDirPath=$(readlink -f $reportDir)

    if [ $repoName == 'scrut-ai-orchestrator' ]; then
        dockerfilePath="backend/$dockerfilePath"
    fi
    
    containerImage="$(grep -oP '(?<=REPOSITORY_URI=).+' buildspec.prod.yml):latest"
    scanDate=$(TZ='Asia/Kolkata' date +"%d-%m-%Y %I:%M:%S %p IST")

    echo ">>> Executing snyk scan for container image: $containerImage"
    
    exitCode=$(timeout 5m snyk container test $containerImage --file=$dockerfilePath --exclude-app-vulns --severity-threshold=$severity --json-file-output=$reportDir/$resultJSONFile > $reportDir/$resultTXTFile 2>&1; echo $?)
    echo ">>> Exit code: $exitCode"

    echo '>>> Removing container image from disk'
    docker image rm --force $containerImage || :
    
    if [ $exitCode -eq 0 ]; then
        echo '>>> Snyk scan Completed! No vulnerabilities found!'
        
        jq --null-input --arg scanDate "$scanDate" --arg scanType "$scanType" --arg service "$repoName" --arg reportDir "$reportDirPath" \
        '{
            scan_date: $scanDate,
            scan_type: $scanType,
            service: $service,
            report_dir: $reportDir
        }' > $metadataFile
        
        processJiraTicket $repoName
        return
    fi

    if [ $exitCode -ne 1 ]; then
        echo '>>> Scan failed! Sending error to console and error notification on Slack!'
        echo -e "\n>>> scanType: $scanType - repoName: $repoName - exitCode: $exitCode\n"
        echo -e ">>> Error:\n"
        cat $reportDir/$resultTXTFile
        sendSlackNotification $scanType $repoName "Snyk scan error"
        return
    fi

    echo '>>> Snyk vulnerabilities found!'
    
    echo '>>> Converting scan result to HTML format'
    snyk-to-html --input $reportDir/$resultJSONFile --output $reportDir/$resultHTMLFile
    rm -rf $reportDir/$resultJSONFile

    echo '>>> Create/update Jira ticket'
    jq --null-input --arg scanDate "$scanDate" --arg scanType "$scanType" --arg service "$repoName" --arg reportDir "$reportDirPath" \
    '{
        scan_date: $scanDate,
        scan_type: $scanType,
        service: $service,
        report_dir: $reportDir,
        vulnerabilities: true
    }' > $metadataFile
    
    processJiraTicket $repoName
}

# function to process Jira cloud tickets
processJiraTicket() {
    local repoName="$1"

    echo '>>> Executing Jira python automation'
    cd $workdDir
    python3 jira/execute.py --jira-username $jiraUser --jira-token $jiraPass --jira-store $s3JiraStoreFile --metadata $repoName/$metadataFile
}

# function to send notifications in Slack
sendSlackNotification() {
    local scanType="$1"
    local repoName="$2"
    local error="$3"
    local snsTopic="arn:aws:sns:$region:123456789:devops-snyk-scanner"

    jsonContent=$(jq --null-input --arg message "$scanType - $repoName - $error" \
    '{
        version: "1.0",
        source: "custom",
        content: {
            description: $message
        }
    }')
    
    aws sns publish --topic-arn $snsTopic --message "$jsonContent" --region $region
}

# main function
main() {
    local repoList=$(jq -r '.config[].repo | select(. != null)' $releaseJsonFile)

    echo '>>> Logging in to Amazon ECR'
    aws ecr get-login-password --region $region | docker login --username AWS --password-stdin 123456789.dkr.ecr.$region.amazonaws.com

    for repo in ${repoList[@]}; do
        echo -e '\n>>> -------------------------------------------------------------------------------------------------\n'
        echo ">>> Cloning Github repo: $repo"
        git clone "$repo"
        local repoName=$(basename $repo)
        (
            executeContainerScans $repoName
        )
        rm -rf "$repoName"
    done

    echo '>>> Logging out from Amazon ECR'
    docker logout 123456789.dkr.ecr.$region.amazonaws.com
}

export PATH=$PATH:/usr/local/bin/node/bin

# global settings
releaseJsonFile='../release.json'
metadataFile='metadata.json'
workdDir=$(dirname $(readlink -f $0))

# start execution
main

exit 0
