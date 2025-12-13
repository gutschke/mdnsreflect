#!/bin/bash -e
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

SOURCES=(mdnsreflect{,.8,.8.md,.py,.service} {install,uninstall}.sh LICENSE README.md)
DEP='pyroute2 zeroconf'

trap 'rc="$?"
      trap "" INT TERM QUIT HUP EXIT ERR
      [ $rc -eq 0 ] || {
      tput bel
      echo
      echo "Script $0 failed unexpectedly" >&2; }
      exit $rc' INT TERM QUIT HUP EXIT ERR

[ "$(id -u)" -eq 0 ] || {
  echo 'This script must be run as "root"'
  exit 1
}

# Dependency check
missing=""
for cmd in python3 gzip mandb systemctl useradd tput; do
  if ! command -v "$cmd" >&/dev/null; then
    missing="$missing $cmd"
  fi
done

# Check for venv module (common omission on Debian/Ubuntu)
if ! python3 -c 'import venv' >&/dev/null; then
  echo 'Error: Python3 "venv" module is missing.'
  echo '  On Debian/Ubuntu, install it with: apt install python3-venv'
  exit 1
fi

if [ -n "$missing" ]; then
  echo "Error: Missing required system tools:$missing"
  exit 1
fi

script="$(readlink -f "$(type -P "$0")")"
src="${script%/*}"
U="$(tput smul)"
R="$(tput rmul)"

# Choose installation directory
cat <<EOF
${U}mdnsreflect${R} needs to be installed in its own system directory. Common
choices are ${U}/usr/local/lib/mdnsreflect${R} or ${U}/opt/mdnsreflect${R}.
EOF
while :; do
  read -p 'Install path [/usr/local/lib/mdnsreflect]: ' dst
  [ -n "${dst}" ] || dst='/usr/local/lib/mdnsreflect'
  [[ "${dst}" =~ ^/ ]] && break || :
done

# Determine system paths
man='/usr/share/man'
if ! [[ "${dst}" =~ ^'/usr' ]]; then
  [ -d "/bin" ] && sys='/' || sys='/usr'
elif [[ "${dst}" =~ ^'/usr' ]] && ! [[ "${dst}" =~ ^'/usr/local' ]]; then
  sys='/usr'
else
  sys='/usr/local'
  man='/usr/local/share/man'
fi

# Install files
echo -n 'Copying source files...'
mkdir -m0755 -p "${dst}"
for file in "${SOURCES[@]}"; do
  [ ! -e "${src}/${file}" ] || cp "${src}/${file}" "${dst}/"
done
echo ' done.'

# Setup python venv
echo -n 'Setting up Python virtual environment...'
(
  cd "${dst}"
  rm -rf 'venv'
  python3 -m 'venv' 'venv'
  ./venv/bin/pip3 install --upgrade 'pip' >&/dev/null
  ./venv/bin/pip3 install ${DEP} >/dev/null

  # Create the symlink for the process name
  # This ensures 'ps' shows 'mdnsreflect' instead of 'python3'
  ln -sf 'python3' 'venv/bin/mdnsreflect'
)
echo ' done.'

# System integration
echo -n 'Creating symbolic links...'
# Binary
rm -f "${sys}/bin/mdnsreflect"
ln -s "${dst}/mdnsreflect" "${sys}/bin/mdnsreflect"

# Man page
rm -f "${man}/man8/mdnsreflect.8.gz"
mkdir -p "${man}/man8"
gzip -c "${dst}/mdnsreflect.8" >"${man}/man8/mdnsreflect.8.gz"
echo ' done.'

echo -n 'Updating man database...'
mandb -q >&/dev/null || echo " (warning: mandb failed)"
echo ' done.'

# Service & user
echo -n 'Configuring user and storage...'
state_dir="/var/lib/mdnsreflect"
if ! id 'mdnsreflect' >&/dev/null; then
  useradd -d "${state_dir}" -U -M -r -s '/usr/sbin/nologin' 'mdnsreflect'
fi
mkdir -p "${state_dir}"
chown 'mdnsreflect:mdnsreflect' "${state_dir}"
chmod 750 "${state_dir}"
echo ' done.'

echo -n 'Installing systemd service...'
rm -f '/etc/systemd/system/mdnsreflect.service'
# Symlink for "single source of truth" configuration
ln -s "${dst}/mdnsreflect.service" '/etc/systemd/system/mdnsreflect.service'

# Reload
systemctl daemon-reload
systemctl stop mdnsreflect >&/dev/null || :
systemctl enable mdnsreflect >&/dev/null
echo ' done.'

# Finished
cat <<EOF

${U}mdnsreflect${R} is now installed.

1. Edit configuration:   ${U}${dst}/mdnsreflect.service${R}
   (Linked from /etc/systemd/system/mdnsreflect.service)
2. Start service:        ${U}sudo systemctl start mdnsreflect${R}
3. Check status:         ${U}sudo systemctl status mdnsreflect${R}
4. Interact              ${U}mdnsreflect {--list-services,--resolve-host,--status}${R}
5. Examine log messages: ${U}sudo journalctl -xeu mdnsreflect${R}
6. Read manual:          ${U}man mdnsreflect${R}
7. Uninstall:            ${U}${dst}/uninstall.sh${R}

EOF
