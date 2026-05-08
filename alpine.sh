#!/bin/bash
# =============================================================================
# STIG CAT I & CAT II Verification - Alpine Linux Container (FIPS)
# Container-applicable checks only. Binary PASS/FAIL with remediation.
# Run with: sh stig_check_alpine_fips.sh
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
REPORT="/tmp/stig_alpine_fips_$(date +%Y%m%d_%H%M%S).txt"

log()    { echo -e "$1" | tee -a "$REPORT"; }
pass()   { log "${GREEN}[PASS]${NC} [$1] $2"; PASS=$((PASS + 1)); }
fail()   { log "${RED}[FAIL]${NC} [$1] $2"; FAIL=$((FAIL + 1)); }
fix()    { log "${CYAN}  FIX : $1${NC}"; }
header() { log "\n${BLUE}${BOLD}=== $1 ===${NC}"; }

log "${BOLD}"
log "========================================================"
log "  STIG CAT I & II - Alpine FIPS Container Verification"
log "  Date    : $(date)"
log "  OS      : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')"
log "  Kernel  : $(uname -r)"
log "  User    : $(id)"
log "========================================================"
log "${NC}"

# =============================================================================
header "CAT I - FIPS VERIFICATION"
# =============================================================================

# FIPS kernel flag
if [ -f /proc/sys/crypto/fips_enabled ]; then
    FIPS=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)
    if [ "$FIPS" = "1" ]; then
        pass "CAT-I SRG-OS-000120" "FIPS mode enabled (/proc/sys/crypto/fips_enabled = 1)"
    else
        fail "CAT-I SRG-OS-000120" "FIPS mode not enabled (value=$FIPS)"
        fix "Boot host kernel with fips=1 in kernel cmdline"
        fix "Or run container on a FIPS-enabled host"
    fi
else
    fail "CAT-I SRG-OS-000120" "/proc/sys/crypto/fips_enabled not available"
    fix "Ensure container has access to /proc/sys/crypto - run on a FIPS-enabled host"
fi

# OpenSSL FIPS provider installed
if command -v openssl > /dev/null 2>&1; then
    OPENSSL_VER=$(openssl version 2>/dev/null)
    pass "CAT-I SRG-OS-000120" "OpenSSL present: $OPENSSL_VER"

    # Check FIPS provider is available
    FIPS_PROVIDER=$(openssl list -providers 2>/dev/null | grep -i fips)
    if [ -n "$FIPS_PROVIDER" ]; then
        pass "CAT-I SRG-OS-000120" "FIPS provider loaded: $FIPS_PROVIDER"
    else
        fail "CAT-I SRG-OS-000120" "FIPS provider not listed in openssl providers"
        fix "Install: apk add openssl-fips-provider"
        fix "Ensure /etc/ssl/fips_enabled or openssl.cnf references the FIPS provider"
    fi

    # Check FIPS self-test passes
    FIPS_TEST=$(openssl fips_self_test 2>&1)
    if echo "$FIPS_TEST" | grep -qi "passed\|ok\|success"; then
        pass "CAT-I SRG-OS-000120" "OpenSSL FIPS self-test passed"
    elif echo "$FIPS_TEST" | grep -qi "failed\|error"; then
        fail "CAT-I SRG-OS-000120" "OpenSSL FIPS self-test failed: $FIPS_TEST"
        fix "Reinstall FIPS provider: apk add --force openssl-fips-provider"
    else
        # fips_self_test subcommand may not exist - try alternate check
        FIPS_ALT=$(openssl md5 /dev/null 2>&1)
        if echo "$FIPS_ALT" | grep -qi "disabled\|not allowed\|fips"; then
            pass "CAT-I SRG-OS-000120" "MD5 disabled in FIPS mode (expected)"
        else
            fail "CAT-I SRG-OS-000120" "MD5 not disabled - FIPS mode may not be enforced"
            fix "Ensure FIPS provider is active and MD5/RC4 are disabled"
        fi
    fi
else
    fail "CAT-I SRG-OS-000120" "openssl not installed"
    fix "Install: apk add openssl"
fi

# Check openssl.cnf references FIPS
OPENSSL_CNF=$(openssl version -d 2>/dev/null | awk '{print $2}' | tr -d '"')
OPENSSL_CNF="${OPENSSL_CNF}/openssl.cnf"
if [ -f "$OPENSSL_CNF" ]; then
    if grep -qi "fips" "$OPENSSL_CNF" 2>/dev/null; then
        pass "CAT-I SRG-OS-000120" "openssl.cnf references FIPS configuration"
    else
        fail "CAT-I SRG-OS-000120" "openssl.cnf does not reference FIPS"
        fix "Add FIPS provider section to $OPENSSL_CNF"
        fix "Or set OPENSSL_CONF env var to point to a FIPS-enabled config"
    fi
else
    fail "CAT-I SRG-OS-000120" "openssl.cnf not found at $OPENSSL_CNF"
    fix "Ensure openssl is properly installed: apk add openssl"
fi

# Weak algorithms disabled
for algo in md5 rc4 des sha1; do
    RESULT=$(echo "test" | openssl dgst -$algo 2>&1)
    if echo "$RESULT" | grep -qi "disabled\|unknown\|not allowed\|error\|fips"; then
        pass "CAT-I SRG-OS-000120" "Algorithm $algo is disabled in FIPS mode"
    else
        fail "CAT-I SRG-OS-000120" "Algorithm $algo may not be disabled (FIPS not enforcing)"
        fix "Ensure FIPS provider is active - weak algorithms must be unavailable"
    fi
done

# =============================================================================
header "CAT I - ACCOUNTS"
# =============================================================================

# No non-root UID 0 - SRG-OS-000104
UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
if [ -z "$UID0" ]; then
    pass "CAT-I SRG-OS-000104" "No non-root accounts with UID 0"
else
    fail "CAT-I SRG-OS-000104" "Non-root accounts with UID 0: $UID0"
    fix "Run: usermod -u <new_uid> <username>"
fi

# No empty passwords - SRG-OS-000106
EMPTY=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$EMPTY" ]; then
    pass "CAT-I SRG-OS-000106" "No accounts with empty or null passwords"
else
    fail "CAT-I SRG-OS-000106" "Accounts with empty/null passwords: $EMPTY"
    fix "Lock account: passwd -l <username>"
fi

# Root shell restricted - SRG-OS-000109
ROOT_SHELL=$(grep "^root:" /etc/passwd | cut -d: -f7)
if [ "$ROOT_SHELL" = "/sbin/nologin" ] || [ "$ROOT_SHELL" = "/usr/sbin/nologin" ] || [ "$ROOT_SHELL" = "/bin/false" ]; then
    pass "CAT-I SRG-OS-000109" "Root shell is restricted: $ROOT_SHELL"
else
    fail "CAT-I SRG-OS-000109" "Root shell is $ROOT_SHELL (must be /sbin/nologin or /bin/false)"
    fix "Run: usermod -s /sbin/nologin root"
fi

# No NIS entries - SRG-OS-000104
for f in /etc/passwd /etc/shadow /etc/group; do
    if [ -f "$f" ]; then
        if grep -q '^+' "$f" 2>/dev/null; then
            fail "CAT-I SRG-OS-000104" "NIS '+' entries in $f"
            fix "Remove all lines beginning with '+' from $f"
        else
            pass "CAT-I SRG-OS-000104" "No NIS '+' entries in $f"
        fi
    fi
done

# No .rhosts/.netrc/.shosts - SRG-OS-000015
BADFILES=$(find /home /root -maxdepth 2 \( -name ".rhosts" -o -name ".netrc" -o -name ".shosts" \) 2>/dev/null)
if [ -z "$BADFILES" ]; then
    pass "CAT-I SRG-OS-000015" "No .rhosts/.netrc/.shosts files found"
else
    fail "CAT-I SRG-OS-000015" "Dangerous files found: $BADFILES"
    fix "Remove each: rm -f <file>"
fi

# =============================================================================
header "CAT I - FILE PERMISSIONS"
# =============================================================================



# World-writable files - SRG-OS-000258
log "  Scanning for world-writable files..."
WW=$(find / -xdev -type f -perm -0002 \
    ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" 2>/dev/null)
if [ -z "$WW" ]; then
    pass "CAT-I SRG-OS-000258" "No world-writable files found"
else
    fail "CAT-I SRG-OS-000258" "World-writable files:\n$WW"
    fix "For each file: chmod o-w <file>"
fi

# Unowned files - SRG-OS-000258
log "  Scanning for unowned files..."
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null)
if [ -z "$UNOWNED" ]; then
    pass "CAT-I SRG-OS-000258" "No unowned files or directories"
else
    fail "CAT-I SRG-OS-000258" "Unowned files/dirs:\n$UNOWNED"
    fix "Assign ownership: chown root:root <file>  OR  remove if unnecessary"
fi

# SUID/SGID - SRG-OS-000326
log "  Scanning for SUID/SGID binaries..."
SUID=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null)
if [ -z "$SUID" ]; then
    pass "CAT-I SRG-OS-000326" "No SUID/SGID binaries found"
else
    fail "CAT-I SRG-OS-000326" "SUID/SGID binaries found:\n$SUID"
    fix "For each unauthorized binary: chmod -s <file>  OR  remove from image"
fi

# /tmp sticky bit - SRG-OS-000368
if [ -d /tmp ]; then
    TMP_PERM=$(stat -c "%a" /tmp 2>/dev/null)
    if [ "$TMP_PERM" = "1777" ]; then
        pass "CAT-I SRG-OS-000368" "/tmp sticky bit set (1777)"
    else
        fail "CAT-I SRG-OS-000368" "/tmp permissions: $TMP_PERM (expected 1777)"
        fix "Run: chmod 1777 /tmp"
    fi
else
    fail "CAT-I SRG-OS-000368" "/tmp does not exist"
    fix "Add to Dockerfile: RUN mkdir -p /tmp && chmod 1777 /tmp"
fi

# =============================================================================
header "CAT I - DANGEROUS SERVICES"
# =============================================================================

ALL_CLEAN=1
for svc in telnet rsh rlogin rexec ftp vsftpd xinetd rpcbind; do
    if command -v "$svc" > /dev/null 2>&1; then
        fail "CAT-I SRG-OS-000095" "Dangerous service installed: $svc"
        fix "Remove from Dockerfile: do not install $svc"
        ALL_CLEAN=0
    fi
done
[ "$ALL_CLEAN" = "1" ] && pass "CAT-I SRG-OS-000095" "No dangerous services installed"

# =============================================================================
header "CAT I - SYSTEM BANNERS"
# =============================================================================

DOD_BANNER="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to monitoring and auditing."

check_banner() {
    local file=$1 stig=$2
    if [ ! -f "$file" ]; then
        fail "CAT-I $stig" "$file missing"
        fix "Add to Dockerfile: RUN echo '$DOD_BANNER' > $file"
        return
    fi
    local content
    content=$(cat "$file" 2>/dev/null)
    if [ -z "$content" ]; then
        fail "CAT-I $stig" "$file is empty"
        fix "Add to Dockerfile: RUN echo '$DOD_BANNER' > $file"
    elif echo "$content" | grep -qiE "authorized|official use|monitored|consent|warning|unauthorized"; then
        pass "CAT-I $stig" "$file contains required warning banner"
    else
        fail "CAT-I $stig" "$file missing DoD warning language. Current: $content"
        fix "Add to Dockerfile: RUN echo '$DOD_BANNER' > $file"
    fi
}

check_banner "/etc/issue"     "SRG-OS-000023"
check_banner "/etc/issue.net" "SRG-OS-000024"

# =============================================================================
header "CAT I - IMAGE PROVENANCE"
# =============================================================================

if [ -f /etc/os-release ]; then
    pass "CAT-I SRG-OS-000257" "OS provenance: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
else
    fail "CAT-I SRG-OS-000257" "/etc/os-release missing - cannot confirm image provenance"
    fix "Ensure image is built from official alpine base"
fi

# Check no unauthorized binaries in system dirs (Alpine uses apk)
if command -v apk > /dev/null 2>&1; then
    log "  Checking for binaries not owned by any apk package..."
    UNEXPECTED=""
    for dir in /usr/bin /usr/sbin /bin /sbin; do
        if [ -d "$dir" ]; then
            for f in "$dir"/*; do
                [ -f "$f" ] || continue
                if ! apk info --who-owns "$f" > /dev/null 2>&1; then
                    UNEXPECTED="$UNEXPECTED\n$f"
                fi
            done
        fi
    done
    if [ -z "$UNEXPECTED" ]; then
        pass "CAT-I SRG-OS-000257" "All system binaries owned by known apk packages"
    else
        fail "CAT-I SRG-OS-000257" "Binaries not owned by any package:$UNEXPECTED"
        fix "Remove unauthorized binaries or add them via apk in Dockerfile"
    fi
else
    fail "CAT-I SRG-OS-000257" "apk not available - cannot verify package provenance"
    fix "Ensure apk is present in image for integrity verification"
fi

# =============================================================================
header "CAT II - PASSWORD POLICY"
# =============================================================================

# Alpine uses /etc/login.defs if shadow-utils installed, otherwise check /etc/passwd directly
LOGIN_DEFS="/etc/login.defs"
if [ ! -f "$LOGIN_DEFS" ]; then
    fail "CAT-II SRG-OS-000076" "/etc/login.defs missing"
    fix "Install shadow: apk add shadow"
    fix "Then configure /etc/login.defs with required values"
else
    get_login() { grep -E "^$1\s" "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}'; }

    VAL=$(get_login "PASS_MAX_DAYS")
    if [ -z "$VAL" ]; then
        fail "CAT-II SRG-OS-000076" "PASS_MAX_DAYS not set"
        fix "Add to /etc/login.defs: PASS_MAX_DAYS 60"
    elif [ "$VAL" -le 60 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000076" "PASS_MAX_DAYS = $VAL (<= 60)"
    else
        fail "CAT-II SRG-OS-000076" "PASS_MAX_DAYS = $VAL (must be <= 60)"
        fix "In /etc/login.defs set: PASS_MAX_DAYS 60"
    fi

    VAL=$(get_login "PASS_MIN_DAYS")
    if [ -z "$VAL" ]; then
        fail "CAT-II SRG-OS-000075" "PASS_MIN_DAYS not set"
        fix "Add to /etc/login.defs: PASS_MIN_DAYS 1"
    elif [ "$VAL" -ge 1 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000075" "PASS_MIN_DAYS = $VAL (>= 1)"
    else
        fail "CAT-II SRG-OS-000075" "PASS_MIN_DAYS = $VAL (must be >= 1)"
        fix "In /etc/login.defs set: PASS_MIN_DAYS 1"
    fi

    VAL=$(get_login "PASS_MIN_LEN")
    if [ -z "$VAL" ]; then
        fail "CAT-II SRG-OS-000078" "PASS_MIN_LEN not set"
        fix "Add to /etc/login.defs: PASS_MIN_LEN 15"
    elif [ "$VAL" -ge 15 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000078" "PASS_MIN_LEN = $VAL (>= 15)"
    else
        fail "CAT-II SRG-OS-000078" "PASS_MIN_LEN = $VAL (must be >= 15)"
        fix "In /etc/login.defs set: PASS_MIN_LEN 15"
    fi

    VAL=$(get_login "PASS_WARN_AGE")
    if [ -z "$VAL" ]; then
        fail "CAT-II SRG-OS-000343" "PASS_WARN_AGE not set"
        fix "Add to /etc/login.defs: PASS_WARN_AGE 7"
    elif [ "$VAL" -ge 7 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000343" "PASS_WARN_AGE = $VAL (>= 7)"
    else
        fail "CAT-II SRG-OS-000343" "PASS_WARN_AGE = $VAL (must be >= 7)"
        fix "In /etc/login.defs set: PASS_WARN_AGE 7"
    fi

    HASH=$(get_login "ENCRYPT_METHOD")
    if [ "$HASH" = "SHA512" ]; then
        pass "CAT-II SRG-OS-000073" "ENCRYPT_METHOD = $HASH"
    else
        fail "CAT-II SRG-OS-000073" "ENCRYPT_METHOD = '$HASH' (must be SHA512 for FIPS)"
        fix "In /etc/login.defs set: ENCRYPT_METHOD SHA512"
        fix "Note: yescrypt is not FIPS-approved - use SHA512 on FIPS systems"
    fi

    VAL=$(get_login "SHA_CRYPT_MIN_ROUNDS")
    if [ -z "$VAL" ]; then
        fail "CAT-II SRG-OS-000073" "SHA_CRYPT_MIN_ROUNDS not set"
        fix "Add to /etc/login.defs: SHA_CRYPT_MIN_ROUNDS 5000"
    elif [ "$VAL" -ge 5000 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000073" "SHA_CRYPT_MIN_ROUNDS = $VAL (>= 5000)"
    else
        fail "CAT-II SRG-OS-000073" "SHA_CRYPT_MIN_ROUNDS = $VAL (must be >= 5000)"
        fix "In /etc/login.defs set: SHA_CRYPT_MIN_ROUNDS 5000"
    fi
fi

# =============================================================================
header "CAT II - PAM CONFIGURATION"
# =============================================================================

# Alpine may use PAM optionally - check if installed
if [ ! -d /etc/pam.d ]; then
    fail "CAT-II SRG-OS-000069" "/etc/pam.d missing - PAM not configured"
    fix "Install PAM: apk add linux-pam"
    fix "Then configure /etc/pam.d/common-auth and /etc/pam.d/common-password"
else
    # Account lockout
    if grep -rq "pam_faillock\|pam_tally2\|pam_faildelay" /etc/pam.d/ 2>/dev/null; then
        pass "CAT-II SRG-OS-000021" "Account lockout module configured"
        DENY=$(grep -r "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null \
            | grep -o "deny=[0-9]*" | head -1 | cut -d= -f2)
        if [ -z "$DENY" ]; then
            fail "CAT-II SRG-OS-000021" "Lockout deny value not found"
            fix "Add deny=3 to pam_faillock line in /etc/pam.d/common-auth"
        elif [ "$DENY" -le 3 ] 2>/dev/null; then
            pass "CAT-II SRG-OS-000021" "Lockout deny = $DENY (<= 3)"
        else
            fail "CAT-II SRG-OS-000021" "Lockout deny = $DENY (must be <= 3)"
            fix "Set deny=3 in pam_faillock line in /etc/pam.d/common-auth"
        fi
    else
        fail "CAT-II SRG-OS-000021" "No account lockout PAM module configured"
        fix "Add to /etc/pam.d/common-auth: auth required pam_faillock.so deny=3 unlock_time=900"
    fi

    # Password complexity
    if grep -rq "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
        pass "CAT-II SRG-OS-000069" "Password complexity module configured"
    else
        fail "CAT-II SRG-OS-000069" "No password complexity module configured"
        fix "Install: apk add linux-pam-dev"
        fix "Add to /etc/pam.d/common-password: password requisite pam_pwquality.so retry=3"
    fi

    PWQCONF="/etc/security/pwquality.conf"
    PAMFILES=$(grep -rl "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null)

    get_credit() {
        grep -h "$1" $PWQCONF $PAMFILES 2>/dev/null | grep -v "^#" \
            | grep -o "${1}=-*[0-9]*" | head -1 | cut -d= -f2
    }

    VAL=$(get_credit "ucredit")
    if [ -n "$VAL" ] && [ "$VAL" -le -1 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000069" "ucredit = $VAL (uppercase required)"
    else
        fail "CAT-II SRG-OS-000069" "ucredit = '$VAL' (must be <= -1)"
        fix "In /etc/security/pwquality.conf set: ucredit = -1"
    fi

    VAL=$(get_credit "lcredit")
    if [ -n "$VAL" ] && [ "$VAL" -le -1 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000070" "lcredit = $VAL (lowercase required)"
    else
        fail "CAT-II SRG-OS-000070" "lcredit = '$VAL' (must be <= -1)"
        fix "In /etc/security/pwquality.conf set: lcredit = -1"
    fi

    VAL=$(get_credit "dcredit")
    if [ -n "$VAL" ] && [ "$VAL" -le -1 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000071" "dcredit = $VAL (digit required)"
    else
        fail "CAT-II SRG-OS-000071" "dcredit = '$VAL' (must be <= -1)"
        fix "In /etc/security/pwquality.conf set: dcredit = -1"
    fi

    VAL=$(get_credit "ocredit")
    if [ -n "$VAL" ] && [ "$VAL" -le -1 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000072" "ocredit = $VAL (special char required)"
    else
        fail "CAT-II SRG-OS-000072" "ocredit = '$VAL' (must be <= -1)"
        fix "In /etc/security/pwquality.conf set: ocredit = -1"
    fi

    REMEMBER=$(grep -r "remember=" /etc/pam.d/ 2>/dev/null \
        | grep -o "remember=[0-9]*" | head -1 | cut -d= -f2)
    if [ -z "$REMEMBER" ]; then
        fail "CAT-II SRG-OS-000077" "Password history not configured"
        fix "Add remember=5 to pam_pwhistory or pam_unix line in /etc/pam.d/common-password"
    elif [ "$REMEMBER" -ge 5 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000077" "Password history remember = $REMEMBER (>= 5)"
    else
        fail "CAT-II SRG-OS-000077" "Password history remember = $REMEMBER (must be >= 5)"
        fix "Set remember=5 in /etc/pam.d/common-password"
    fi
fi

# =============================================================================
header "CAT II - LOGGING"
# =============================================================================

if [ -d /var/log ]; then
    OWN=$(stat -c "%U:%G" /var/log 2>/dev/null)
    PERM=$(stat -c "%a" /var/log 2>/dev/null)
    if [ "$OWN" = "root:root" ]; then
        pass "CAT-II SRG-OS-000057" "/var/log owner: $OWN"
    else
        fail "CAT-II SRG-OS-000057" "/var/log owner: $OWN (expected root:root)"
        fix "Run: chown root:root /var/log"
    fi
    if [ "$PERM" -le 755 ] 2>/dev/null; then
        pass "CAT-II SRG-OS-000057" "/var/log permissions: $PERM"
    else
        fail "CAT-II SRG-OS-000057" "/var/log permissions: $PERM (must be <= 755)"
        fix "Run: chmod 755 /var/log"
    fi
else
    fail "CAT-II SRG-OS-000479" "/var/log directory missing"
    fix "Add to Dockerfile: RUN mkdir -p /var/log && chmod 755 /var/log"
fi

WORLD_LOGS=$(find /var/log -type f -perm /o+r 2>/dev/null)
if [ -z "$WORLD_LOGS" ]; then
    pass "CAT-II SRG-OS-000057" "No world-readable log files in /var/log"
else
    fail "CAT-II SRG-OS-000057" "World-readable log files:\n$WORLD_LOGS"
    fix "For each file: chmod o-r <file>"
fi

# Alpine uses syslog-ng or busybox syslog
if command -v syslog-ng > /dev/null 2>&1 || \
   command -v syslogd > /dev/null 2>&1 || \
   [ -f /etc/syslog.conf ] || [ -f /etc/syslog-ng/syslog-ng.conf ]; then
    pass "CAT-II SRG-OS-000479" "Syslog daemon present"
else
    fail "CAT-II SRG-OS-000479" "No syslog daemon found"
    fix "Install: apk add syslog-ng  OR  apk add busybox-syslogd"
    fix "Or ensure container runtime captures stdout/stderr logs"
fi

# =============================================================================
header "CAT II - CRON PERMISSIONS"
# =============================================================================

FOUND_CRON=0
for cronpath in /etc/crontabs /etc/cron.d /etc/periodic; do
    if [ -e "$cronpath" ]; then
        FOUND_CRON=1
        OWN=$(stat -c "%U:%G" "$cronpath" 2>/dev/null)
        PERM=$(stat -c "%a" "$cronpath" 2>/dev/null)
        if [ "$OWN" = "root:root" ]; then
            pass "CAT-II SRG-OS-000480" "$cronpath owner: $OWN"
        else
            fail "CAT-II SRG-OS-000480" "$cronpath owner: $OWN (expected root:root)"
            fix "Run: chown root:root $cronpath"
        fi
        if [ "$PERM" -le 755 ] 2>/dev/null; then
            pass "CAT-II SRG-OS-000480" "$cronpath permissions: $PERM"
        else
            fail "CAT-II SRG-OS-000480" "$cronpath permissions: $PERM (must be <= 755)"
            fix "Run: chmod 700 $cronpath"
        fi
    fi
done
[ "$FOUND_CRON" = "0" ] && pass "CAT-II SRG-OS-000480" "No cron directories present (minimal image)"

# =============================================================================
header "CAT II - HOME DIRECTORY PERMISSIONS"
# =============================================================================

FOUND_HOMES=0
while IFS=: read -r user _ uid _ _ homedir _; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ -n "$homedir" ] && [ "$homedir" != "/" ] && [ -d "$homedir" ]; then
        FOUND_HOMES=1
        PERM=$(stat -c "%a" "$homedir" 2>/dev/null)
        OWN=$(stat -c "%U" "$homedir" 2>/dev/null)
        if [ "$PERM" -le 750 ] 2>/dev/null; then
            pass "CAT-II SRG-OS-000480" "Home $homedir ($user) permissions: $PERM"
        else
            fail "CAT-II SRG-OS-000480" "Home $homedir ($user) permissions: $PERM (must be <= 750)"
            fix "Run: chmod 750 $homedir"
        fi
        if [ "$OWN" = "$user" ]; then
            pass "CAT-II SRG-OS-000480" "Home $homedir owned by: $user"
        else
            fail "CAT-II SRG-OS-000480" "Home $homedir owned by $OWN (expected $user)"
            fix "Run: chown $user $homedir"
        fi
    fi
done < /etc/passwd
[ "$FOUND_HOMES" = "0" ] && pass "CAT-II SRG-OS-000480" "No user home directories present (minimal image)"

# =============================================================================
header "CAT II - CONTAINER SPECIFIC"
# =============================================================================

# Non-root
CUR_UID=$(id -u)
if [ "$CUR_UID" -ne 0 ]; then
    pass "CAT-II CONTAINER" "Running as non-root UID: $CUR_UID"
else
    fail "CAT-II CONTAINER" "Running as root (UID 0)"
    fix "Add to Dockerfile: RUN adduser -D -s /sbin/nologin appuser && USER appuser"
fi

# No package managers
PM_FOUND=""
for pm in apk apt apt-get yum dnf pip pip3 npm yarn; do
    if command -v "$pm" > /dev/null 2>&1; then PM_FOUND="$PM_FOUND $pm"; fi
done
if [ -z "$PM_FOUND" ]; then
    pass "CAT-II CONTAINER" "No package managers present"
else
    fail "CAT-II CONTAINER" "Package managers found: $PM_FOUND"
    fix "Use multi-stage build - copy only required binaries to final FROM scratch or alpine image"
    fix "Or accept apk presence if required and document as operational necessity"
fi

# No compilers
COMPILERS=""
for tool in gcc g++ cc make cmake; do
    if command -v "$tool" > /dev/null 2>&1; then COMPILERS="$COMPILERS $tool"; fi
done
if [ -z "$COMPILERS" ]; then
    pass "CAT-II CONTAINER" "No compilers present"
else
    fail "CAT-II CONTAINER" "Compilers found: $COMPILERS"
    fix "Use multi-stage build: compile in builder stage, copy only artifacts to final image"
fi

# Package count
if command -v apk > /dev/null 2>&1; then
    PKG_COUNT=$(apk list --installed 2>/dev/null | wc -l)
    if [ "$PKG_COUNT" -lt 50 ]; then
        pass "CAT-II CONTAINER" "Minimal package count: $PKG_COUNT"
    else
        fail "CAT-II CONTAINER" "Package count $PKG_COUNT is too high (must be < 50 for hardened Alpine)"
        fix "Review with 'apk list --installed' and remove unnecessary packages in Dockerfile"
    fi
fi

# Read-only root filesystem
if touch /test_rofs_$$ 2>/dev/null; then
    rm -f /test_rofs_$$
    fail "CAT-II CONTAINER" "Root filesystem is writable"
    fix "Run container with: docker run --read-only ..."
    fix "Or in Kubernetes: securityContext.readOnlyRootFilesystem: true"
else
    pass "CAT-II CONTAINER" "Root filesystem is read-only"
fi

# No listening ports
if command -v ss > /dev/null 2>&1; then
    LISTEN=$(ss -tlnp 2>/dev/null | grep -c "LISTEN" || echo "0")
    if [ "$LISTEN" -eq 0 ]; then
        pass "CAT-II SRG-OS-000095" "No listening TCP ports"
    else
        fail "CAT-II SRG-OS-000095" "$LISTEN listening TCP port(s) found"
        ss -tlnp 2>/dev/null | tee -a "$REPORT"
        fix "Remove or disable services not required by the application"
    fi
elif command -v netstat > /dev/null 2>&1; then
    LISTEN=$(netstat -tlnp 2>/dev/null | grep -c "LISTEN" || echo "0")
    if [ "$LISTEN" -eq 0 ]; then
        pass "CAT-II SRG-OS-000095" "No listening TCP ports"
    else
        fail "CAT-II SRG-OS-000095" "$LISTEN listening TCP port(s) found"
        netstat -tlnp 2>/dev/null | tee -a "$REPORT"
        fix "Remove or disable services not required by the application"
    fi
else
    fail "CAT-II SRG-OS-000095" "ss/netstat not available - cannot verify listening ports"
    fix "Install: apk add iproute2  OR  apk add net-tools"
fi

# Container capabilities
if [ -f /proc/self/status ]; then
    CAP_EFF=$(grep "^CapEff:" /proc/self/status 2>/dev/null | awk '{print $2}')
    if [ "$CAP_EFF" = "0000000000000000" ]; then
        pass "CAT-II CONTAINER" "No effective capabilities (fully dropped)"
    else
        fail "CAT-II CONTAINER" "Effective capabilities: $CAP_EFF"
        fix "Run with: docker run --cap-drop=ALL --cap-add=<only_needed> ..."
        fix "Or in Kubernetes: securityContext.capabilities.drop: [ALL]"
    fi
fi

# /etc/os-release
if [ -f /etc/os-release ]; then
    pass "CAT-II CONTAINER" "/etc/os-release present"
else
    fail "CAT-II CONTAINER" "/etc/os-release missing"
    fix "Ensure image is built from official alpine base which includes /etc/os-release"
fi

# =============================================================================
header "SUMMARY"
# =============================================================================

TOTAL=$((PASS + FAIL))
log ""
log "${BOLD}========================================================"
log "  Results"
log "========================================================"
log "${GREEN}  PASS : $PASS${NC}"
log "${RED}  FAIL : $FAIL${NC}"
log "${BOLD}  ──────────────────────────────────────"
log "  TOTAL: $TOTAL"
if [ "$TOTAL" -gt 0 ]; then
    SCORE=$(( (PASS * 100) / TOTAL ))
    log "  Score: ${SCORE}%"
fi
log ""
log "  Report saved to: $REPORT"
log "========================================================${NC}"

[ "$FAIL" -eq 0 ] && exit 0 || exit 2
