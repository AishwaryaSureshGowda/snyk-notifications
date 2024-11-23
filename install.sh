#!/bin/bash
set -e

# function to install script dependencies
installDependencies() {
    echo -e '\n>>> Installing snyk scan dependencies'

    echo -e '\n>>> Pre-installed CLI versions:'
    python3 -V
    go version

    echo -e '\n>>> Installing Node v20'
    timeout 5m curl -L https://nodejs.org/dist/v20.16.0/node-v20.16.0-linux-x64.tar.xz -o node.tar.xz
    tar -xf node.tar.xz && rm -rf node.tar.xz
    mv node-v20.16.0-linux-x64 node
    chmod +x node/bin/node node/bin/npm
    rm -rf /usr/local/bin/node /usr/local/bin/npm
    mv node /usr/local/bin
    export PATH=$PATH:/usr/local/bin/node/bin
    echo '>>> node version:'
    node -v
    echo '>>> npm version:'
    npm -v

    echo -e '\n>>> Installing Snyk CLI'
    curl -L https://downloads.snyk.io/cli/stable/snyk-linux -o snyk
    chmod +x snyk
    mv snyk /usr/local/bin
    echo '>>> Snyk version:'
    snyk --version
    snyk config set disableSuggestions=true

    echo -e '\n>>> Installing python3 modules'
    python3 -m pip install --upgrade pip
    python3 -m pip install --upgrade requests
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    
    source ~/.bashrc
    which pipx
    pipx install poetry
    poetry --version
    
    echo -e '\n>>> Installing global npm packages'
    npm install -g snyk-to-html pnpm

    echo -e '\n>>> Downloading Jira store file from s3 bucket'
    aws s3 cp s3://$s3Bucket/$s3JiraStoreFile . --region $s3BucketRegion
}

installDependencies

exit 0
