# Embedded into preinst/prerm by the package builder; no installed helper needed.
runnerd_require_stopped() {
  snapshot=$(systemctl show neticora-runnerd.service --property=LoadState,ActiveState,MainPID,ControlPID 2>/dev/null) || {
    echo 'Cannot verify Runnerd service state; preserve installation and retry after systemd recovery.' >&2
    return 1
  }
  load= active= main= control=
  while IFS='=' read -r property value; do
    case "$property" in
      LoadState) load=$value ;;
      ActiveState) active=$value ;;
      MainPID) main=$value ;;
      ControlPID) control=$value ;;
    esac
  done <<EOF
$snapshot
EOF
  case "$load/$active/$main/$control" in
    loaded/inactive/0/0|loaded/failed/0/0|not-found/inactive/0/0) ;;
    *)
      echo 'Drain and stop Runnerd explicitly before package changes; service must be stopped with no main/control process.' >&2
      return 1 ;;
  esac
}
