#!/bin/bash
set -e

# shell script to execute snyk security scans (SAST, SCA)

# function to execute snyk scans
executeSnykScans() {
    local repoName="$1"
    local scanType="$2"

    local reportDir='snyk-report'
    local resultJSONFile='snyk-result.json'
    local resultTXTFile='snyk-result.txt'
    local resultHTMLFile='snyk-result.html'
    local nodeDepFile='package.json'
    local nodeDepDir='node_modules'
    local pythonDepFile='requirements.txt'
    local pythonDepDir='python-venv'
    local poetryDepFile='pyproject.toml'
    local goDepFile='go.mod'
    local severity='high'
    local branch='master'
    local snykOrg='fe66cd5a-ed4d-4b39-881d-d6cfd36ae86d'
    local scanCmd=''
    local extraCmdArgs=''
    local snykProject=''
    local prefixCmdArgs=''

    cd $workdDir/$repoName

    if [ $scanType == 'snyk-open-source' ]; then
        echo -e '\n>>> Executing Snyk scan of type: Open Source (SCA)'
        extraCmdArgs+=" --show-vulnerable-paths=all --policy-path=$workdDir/.snyk"
        if [ -f $nodeDepFile ]; then
            snykProject=$nodeDepFile
            rm -rf $nodeDepDir
            echo '>>> Installing Node dependencies'
            if [ $repoName != 'scrut-webapp-v2' ]; then
                if [ $repoName == 'scrut-trustcenter-webapp-v2' ]; then
                    extraCmdArgs+=' --strict-out-of-sync=false'
                fi
                npmExitCode=$(timeout 5m npm install --no-audit --progress=false >> $workdDir/$errorLogFile 2>&1; echo $?)
                if [ $npmExitCode -ne 0 ]; then
                    echo '>>> Force installing npm packages'
                    rm -rf $nodeDepDir
                    npmExitCode=$(timeout 5m npm install --force --no-audit --progress=false >> $workdDir/$errorLogFile 2>&1; echo $?)
                    if [ $npmExitCode -ne 0 ]; then
                        echo '>>> npm force install failed, sending error to s3 and error notification on Slack!'
                        echo -e "\n>>> scanType: $scanType - repoName: $repoName - exitCode: $npmExitCode\n" >> $workdDir/$errorLogFile
                        sendSlackNotification $scanType $repoName "npm install error"
                        return
                    fi
                fi
            else
                npmExitCode=$(timeout 5m pnpm install --no-frozen-lockfile >> $workdDir/$errorLogFile 2>&1; echo $?)
                if [ $npmExitCode -ne 0 ]; then
                    echo '>>> pnpm install failed, sending error to s3 and error notification on Slack!'
                    echo -e "\n>>> scanType: $scanType - repoName: $repoName - exitCode: $npmExitCode\n" >> $workdDir/$errorLogFile
                    sendSlackNotification $scanType $repoName "pnpm install error"
                    return
                fi
            fi
        elif [ -f $pythonDepFile ]; then
            snykProject=$pythonDepFile
            rm -rf $pythonDepDir
            echo '>>> Installing Python dependencies'
            python3 -m venv $pythonDepDir
            source $pythonDepDir/bin/activate
            python3 -m pip install --upgrade pip > /dev/null 2>&1;
            python3 -m pip install --requirement $pythonDepFile > /dev/null 2>&1;
            extraCmdArgs+=" --file=$pythonDepFile --package-manager=pip --command=python3"
        elif [ -f "backend/$poetryDepFile" ]; then
            snykProject=$poetryDepFile
            mv backend/$poetryDepFile .
            mv backend/poetry.lock .
            echo '>>> Installing Python dependencies'
            poetry install --no-root --only main
            prefixCmdArgs+='poetry run'
        elif [ -f $goDepFile ]; then
            snykProject=$goDepFile
            echo 'No dependency installing required for Go project'
        else
            echo '>>> Snyk project not supported for OpenSource scans!'
            return
        fi
    elif [ $scanType == 'snyk-source-code' ]; then
        echo -e '\n>>> Executing Snyk scan of type: Source Code (SAST)'
        scanCmd='code'
    else
        echo '>>> Snyk scan type not supported'
        return
    fi
    rm -rf $reportDir $metadataFile
    mkdir $reportDir
    reportDirPath=$(readlink -f $reportDir)

    echo '>>> Executing snyk scan'
    scanDate=$(TZ='Asia/Kolkata' date +"%d-%m-%Y %I:%M:%S %p IST")
    exitCode=$(timeout 5m $prefixCmdArgs snyk $scanCmd test --severity-threshold=$severity --json-file-output=$reportDir/$resultJSONFile $extraCmdArgs > $reportDir/$resultTXTFile 2>&1; echo $?)
    echo ">>> Exit code: $exitCode"

    if [ $scanType == 'snyk-open-source' ]; then
        echo '>>> Running snyk monitor'
        timeout 5m snyk monitor --org=$snykOrg --project-name=$snykProject --project-tags=branch=$branch --strict-out-of-sync=false || :
        if [ -d $pythonDepDir ]; then 
            deactivate
        fi
    fi
    
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
        echo '>>> Scan failed! Sending error to s3 and error notification on Slack!'
        echo -e "\n>>> scanType: $scanType - repoName: $repoName - exitCode: $exitCode\n" >> $workdDir/$errorLogFile
        cat $reportDir/$resultTXTFile >> $workdDir/$errorLogFile
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
    local snsTopic="arn:aws:sns:$region:378176467373:devops-snyk-scanner"

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

    for repo in ${repoList[@]}; do
        echo -e '\n>>> -------------------------------------------------------------------------------------------------\n'
        echo ">>> Scanning Github repo using Snyk: $repo"
        git clone "$repo"
        local repoName=$(basename $repo)
        (
            executeSnykScans $repoName 'snyk-open-source'
            executeSnykScans $repoName 'snyk-source-code'
        )
        rm -rf "$repoName"
    done
}

export PATH=$PATH:/usr/local/bin/node/bin:/root/.local/bin

# global settings
releaseJsonFile='../release.json'
metadataFile='metadata.json'
workdDir=$(dirname $(readlink -f $0))

# start execution
main

exit 0
