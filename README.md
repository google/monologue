# Certificate Transparency Log Monitor

[![Build Status](https://travis-ci.org/google/monologue.svg?branch=master)](https://travis-ci.org/google/monologue)

This repository contains the source code for the monitor that checks that
Certificate Transparency Logs are complying with [RFC 6962](https://tools.ietf.org/html/rfc6962)
and the [Chromium Certificate Transparency Log Policy](https://github.com/chromium/ct-policy).

This project is currently in development and so may be subject to significant
change.


## Working on the Code

The [`scripts/presubmit.sh`](scripts/presubmit.sh) script runs various tools
and tests over the codebase.

```bash
# Install golangci-lint
go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
cd $GOPATH/src/github.com/golangci/golangci-lint/cmd/golangci-lint
go install -ldflags "-X 'main.version=$(git describe --tags)' -X 'main.commit=$(git rev-parse --short HEAD)' -X 'main.date=$(date)'"
cd -
# Run build, test and linters
./scripts/presubmit.sh
# Or just run the linters alone
golangci-lint run
```

