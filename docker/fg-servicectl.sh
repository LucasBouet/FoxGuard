#!/usr/bin/env bash
#
# The service manager the agent talks to when there is no systemd.
#
# foxguard-agent does not start dnsmasq or HAProxy itself. It renders their
# configuration, validates it with the daemon's own checker, and then asks an
# init system to make the daemon serve it -- `systemctl is-active`, `reload`,
# `restart`. On a real gateway that is systemd. Inside a container there is no
# init system, so this stands in for one.
#
# It is NOT named `systemctl` on purpose. Shadowing a well-known binary hides
# what is happening from whoever is debugging this at 3am. The agent already
# makes the path configurable -- FOXGUARD_AGENT_SYSTEMCTL_PATH points here --
# so the substitution is visible in the environment rather than in $PATH.
#
#   fg-servicectl is-active|start|stop|restart|reload foxguard-dns|foxguard-proxy
#
# The behaviour it has to reproduce is in the units it replaces:
#   agent/systemd/foxguard-dns.service    -- validate, then SIGHUP to reload
#   agent/systemd/foxguard-proxy.service  -- validate, then SIGUSR2 to reload
#
# SIGUSR2 is the whole reason this is a script and not `docker restart`: it is
# what makes an HAProxy reload seamless. The master keeps the listening sockets,
# hands them to a new worker, and the old worker drains instead of dropping
# connections. Restarting the process would break every passthrough session on
# every policy change.
#
# Exit codes follow systemctl where the agent reads them: 0 active, 3 inactive.
#
# No `set -e`: this tool reports failure through its exit code, and several
# paths below are *expected* to fail.
set -uo pipefail

run_dir=${FOXGUARD_RUN_DIR:-/run/foxguard}
# The same variables the agent itself reads, so the two cannot disagree about
# where the rendered configuration is.
dns_dir=${FOXGUARD_AGENT_DNS_DIR:-/etc/foxguard/dns}
proxy_dir=${FOXGUARD_AGENT_PROXY_DIR:-/etc/foxguard/proxy}
dnsmasq_bin=${FOXGUARD_AGENT_DNSMASQ_PATH:-dnsmasq}
haproxy_bin=${FOXGUARD_AGENT_HAPROXY_PATH:-haproxy}
stop_timeout=${FOXGUARD_SERVICE_STOP_TIMEOUT:-10}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 64
}

[[ $# -ge 2 ]] || usage
verb=$1
unit=${2%.service}

case $unit in
  foxguard-dns)
    pidfile="$run_dir/dnsmasq.pid"
    conf="$dns_dir/dnsmasq.conf"
    ;;
  foxguard-proxy)
    pidfile="$run_dir/haproxy.pid"
    conf="$proxy_dir/haproxy.cfg"
    ;;
  *)
    printf 'fg-servicectl: unknown unit %s\n' "$unit" >&2
    exit 64
    ;;
esac

# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #

unit_pid() {
  local pid
  pid=$(cat "$pidfile" 2>/dev/null) || return 1
  [[ $pid =~ ^[0-9]+$ ]] || return 1
  # A pid file outlives the process it named. Without this check a crashed
  # daemon reads as active for ever and the agent never restarts it -- which is
  # the exact failure the units' own is-active guard exists to catch.
  kill -0 "$pid" 2>/dev/null || return 1
  printf '%s' "$pid"
}

validate() {
  case $unit in
    foxguard-dns)   "$dnsmasq_bin" --test --conf-file="$conf" ;;
    foxguard-proxy) "$haproxy_bin" -c -q -f "$conf" ;;
  esac
}

start_unit() {
  if unit_pid >/dev/null; then return 0; fi
  if [[ ! -f $conf ]]; then
    printf 'fg-servicectl: %s has no configuration yet (%s)\n' "$unit" "$conf" >&2
    return 1
  fi
  # Same order as the units' ExecStartPre: a daemon that dies on a bad file
  # leaves nothing to read the error out of, so the check happens first.
  validate || return 1
  case $unit in
    foxguard-dns)
      # No --keep-in-foreground here, unlike the systemd unit: nothing is
      # supervising this process, so it has to daemonize and record its pid.
      # --conf-file with nothing else, exactly as the unit does, so this
      # instance never reads /etc/dnsmasq.conf or /etc/dnsmasq.d.
      "$dnsmasq_bin" --conf-file="$conf" --pid-file="$pidfile"
      ;;
    foxguard-proxy)
      # -W master-worker (what makes SIGUSR2 a seamless reload), -D daemonize.
      "$haproxy_bin" -W -D -f "$conf" -p "$pidfile"
      ;;
  esac
}

stop_unit() {
  local pid waited
  pid=$(unit_pid) || { rm -f "$pidfile"; return 0; }
  kill -TERM "$pid" 2>/dev/null
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    (( waited >= stop_timeout )) && { kill -KILL "$pid" 2>/dev/null; break; }
    sleep 1
    waited=$((waited + 1))
  done
  rm -f "$pidfile"
  return 0
}

# --------------------------------------------------------------------------- #
# verbs
# --------------------------------------------------------------------------- #

case $verb in
  is-active)
    if unit_pid >/dev/null; then echo active; exit 0; fi
    echo inactive
    exit 3
    ;;

  start)
    start_unit
    ;;

  stop)
    stop_unit
    ;;

  restart)
    stop_unit
    start_unit
    ;;

  reload)
    pid=$(unit_pid) || {
      printf 'fg-servicectl: %s is not running, nothing to reload\n' "$unit" >&2
      exit 3
    }
    validate || exit 1
    case $unit in
      # SIGHUP re-reads the hosts file and flushes the cache without dropping
      # the listening socket. It does NOT re-read the configuration, which is
      # why the agent restarts instead when that file changed.
      foxguard-dns)   kill -HUP "$pid" ;;
      foxguard-proxy) kill -USR2 "$pid" ;;
    esac
    ;;

  status)
    if pid=$(unit_pid); then
      printf '%s: active (pid %s)\n' "$unit" "$pid"
      exit 0
    fi
    printf '%s: inactive\n' "$unit"
    exit 3
    ;;

  enable|disable|daemon-reload)
    # Nothing here persists across a container restart by design: the image is
    # the unit file. Accepted quietly so a stray call is not an error.
    exit 0
    ;;

  *)
    printf 'fg-servicectl: unsupported verb %s\n' "$verb" >&2
    exit 64
    ;;
esac
