#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
fail() { printf 'neo4j-ubi: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) != 0 ]] || fail 'must start as a non-root user'
[[ $# == 1 && $1 == console ]] || fail 'only the console command is supported'
# Reject upstream-image variables instead of silently ignoring security intent.
for variable in ${!NEO4J_@}; do
    case "$variable" in
        NEO4J_UBI_PASSWORD_FILE|NEO4J_UBI_ALLOW_NO_AUTH|NEO4J_UBI_HEAP|NEO4J_UBI_PAGECACHE) ;;
        *) fail "unsupported configuration variable: ${variable}" ;;
    esac
done
for variable in JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS JAVA_OPTS HEAP_SIZE; do
    [[ ! -v $variable ]] || fail "unsupported JVM override: ${variable}"
done

# No VOLUME instruction: Docker must not silently allocate anonymous data storage.
mounted=false
while read -r _ _ _ target options rest; do
    if [[ $target == /data && ,$options, == *,rw,* ]]; then
        [[ $rest != *' - tmpfs '* ]] || fail '/data must be a durable volume, not tmpfs'
        mounted=true
    fi
done < /proc/self/mountinfo
$mounted || fail '/data requires an explicit writable durable volume mount'
[[ -w /data ]] || fail '/data must be writable by the runtime UID'
[[ -d /run/neo4j && -w /run/neo4j && -d /tmp && -w /tmp ]] || fail 'mount writable tmpfs at /run/neo4j and /tmp'

allow=${NEO4J_UBI_ALLOW_NO_AUTH:-false}
[[ $allow == true || $allow == false ]] || fail 'NEO4J_UBI_ALLOW_NO_AUTH must be true or false'
heap=${NEO4J_UBI_HEAP:-512m}
pagecache=${NEO4J_UBI_PAGECACHE:-256m}
[[ $heap =~ ^[1-9][0-9]*[mg]$ ]] || fail 'NEO4J_UBI_HEAP must be a positive integer with m or g suffix'
[[ $pagecache =~ ^[1-9][0-9]*[mg]$ ]] || fail 'NEO4J_UBI_PAGECACHE must be a positive integer with m or g suffix'
export JAVA_HOME=/opt/java NEO4J_HOME=/opt/neo4j NEO4J_CONF=/run/neo4j
export HOME=/run/neo4j
cp /etc/neo4j/neo4j.conf /run/neo4j/neo4j.conf
cp /etc/neo4j/logs.xml /run/neo4j/server-logs.xml
cp /etc/neo4j/logs.xml /run/neo4j/user-logs.xml
printf '\nserver.memory.heap.initial_size=%s\nserver.memory.heap.max_size=%s\nserver.memory.pagecache.size=%s\n' \
    "$heap" "$heap" "$pagecache" >> /run/neo4j/neo4j.conf

if [[ $allow == true ]]; then
    [[ ! -v NEO4J_UBI_PASSWORD_FILE ]] || fail 'password file and unauthenticated opt-out are mutually exclusive'
    printf 'neo4j-ubi: WARNING: authentication explicitly disabled by operator\n' >&2
    printf 'dbms.security.auth_enabled=false\n' >> /run/neo4j/neo4j.conf
else
    secret=${NEO4J_UBI_PASSWORD_FILE:-/run/secrets/neo4j-password}
    [[ $secret == /* && -f $secret && -r $secret ]] || fail 'operator credential required: mount NEO4J_UBI_PASSWORD_FILE read-only'
    [[ ! -L $secret ]] || fail 'credential file must not be a symlink'
    mode=$(stat -c %a "$secret")
    (( (8#$mode & 0007) == 0 )) || fail 'credential file must not be accessible to others (use 0400 or 0440)'
    secret_ro=false
    longest=0
    while read -r _ _ _ target options _; do
        if [[ $secret == "$target" || $secret == "$target/"* || $target == / ]]; then
            if (( ${#target} > longest )); then
                longest=${#target}
                secret_ro=false
                [[ ,$options, != *,ro,* ]] || secret_ro=true
            fi
        fi
    done < /proc/self/mountinfo
    $secret_ro || fail 'credential file must be on a read-only mount'
    [[ $(stat -c %s "$secret") -le 1024 ]] || fail 'credential file exceeds 1024 bytes'
    # One printable ASCII line, optionally terminated by a single LF.
    password=$(cat "$secret")
    LC_ALL=C
    export LC_ALL
    [[ ${#password} -ge 16 && $password != *[!\ -\~]* ]] || fail 'credential must contain at least 16 printable ASCII characters on one line'
    expected_bytes=${#password}
    actual_bytes=$(stat -c %s "$secret")
    (( actual_bytes == expected_bytes || actual_bytes == expected_bytes + 1 )) || fail 'credential file must contain exactly one line'
    printf 'dbms.security.auth_enabled=true\n' >> /run/neo4j/neo4j.conf
    if [[ ! -d /data/databases/system ]]; then
        # Picocli @file expansion keeps the password out of argv and environment.
        escaped=${password//\\/\\\\}
        escaped=${escaped//\"/\\\"}
        printf '"%s"\n' "$escaped" > /run/neo4j/initial-password.args
        unset password escaped
        trap 'rm -f /run/neo4j/initial-password.args' EXIT
        /opt/neo4j/bin/neo4j-admin dbms set-initial-password -- @/run/neo4j/initial-password.args \
            || fail 'initial credential setup failed'
        rm -f /run/neo4j/initial-password.args
        trap - EXIT
    fi
    unset password
fi
exec /opt/neo4j/bin/neo4j console
