#!/bin/bash -

TRUE=0
FALSE=1


function _run
{
    if [[ $1 == fatal ]]; then
        errors_fatal=$TRUE
    else
        errors_fatal=$FALSE
    fi
    shift
    logit "${BOLD}$*${CLR}"
    eval "$*"
    rc=$?
    if [[ $rc != 0 ]]; then
        msg="${BOLD}${RED}$*${CLR}${RED} returned $rc${CLR}"
        if [[ $errors_fatal == $FALSE ]]; then
            msg+=" (error ignored)"
        fi
    else
        msg="${BOLD}${GREEN}$*${CLR}${GREEN} returned $rc${CLR}"
    fi
    logit "${BOLD}$msg${CLR}"
    # fail hard and fast
    if [[ $rc != 0 && $errors_fatal == $TRUE ]]; then
        pwd
        exit 1
    fi
    return $rc
}

function logit
{
    if [[ "${1}" == "FATAL" ]]; then
        fatal="FATAL"
        shift
    fi
    echo -n "$(date '+%b %d %H:%M:%S.%N %Z') $(basename -- $0)[$$]: "
    if [[ "${fatal}" == "FATAL" ]]; then echo -n "${RED}${fatal} "; fi
    echo "$*"
    if [[ "${fatal}" == "FATAL" ]]; then echo -n "${CLR}"; exit 1; fi
}

function run
{
    _run fatal $*
}

function run_ignerr
{
    _run warn $*
}

function all
{
    build_tileserver
    build_containers
}

function install_golang
{
    local ver="1.11"
    logit "Installing golang ${ver}"
    run "curl -o /tmp/golang.tar.gz https://dl.google.com/go/go${ver}.linux-amd64.tar.gz"
    run "sudo tar -C /usr/local -xzf /tmp/golang.tar.gz"
    export PATH=/usr/local/go:$PATH
    export GOROOT=/usr/local/go
    logit "Installing golang ${ver}: done"
}

function deps ()
{
    logit "Installing dependencies"
    run_ignerr "go get -t -v ./..."
    logit "Installing dependencies: done"
}

function test
{
    logit "Running test function"
    logit "Environment:"
    set | perl -pe 's/(CREDS|KEY|CREDENTIALS|encrypted_[^=]+)=(.*)((?:....)(?=$))/$1=XXXXXXXXXXXXXXXXXXX$3/g'
    if [[ "$GOOGLE_CREDS" == "" ]]; then
        logit FATAL "You must specify a valid GOOGLE_CREDS env var for tests to succeed"
    fi
    run "go test ./..."
    logit "Running test function: done"
}

function usage
{
    echo "usage: $(basename $0) <command> [arguments]"
    echo
    echo "Commands:"
    echo
    echo "    test                       Run tests"
    echo
}


#################################
# main
#################################

function main () {
    if [[ "${1}" =~ ^- ]]; then   # if someone passses in an arg like -h, -q, then show usage
      usage
      exit 1
    fi
    func_to_exec=${1:-test}
    type ${func_to_exec} 2>&1 | grep -q 'function' >&/dev/null || {
        logit "$(basename $0): ERROR: function '${func_to_exec}' not found."
        exit 1
    }

    shift
    if [[ "$TRAVIS" == "true" ]]; then
        eval "$(gimme 1.11)"
    fi
    ${func_to_exec} $*
    echo
}

main $*
