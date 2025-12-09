#!/bin/bash
# This script will reset the SED password to the default one

SED_DEFAULT_PASSWORD="eGN8W0VlNGtYKmFcYy82ViY1N2ReZVAhelVPS10tKjAK"

source /usr/local/bin/sed_pw_util.sh

default_pw=$(echo "$SED_DEFAULT_PASSWORD" | base64 -d)
if [ -z "$default_pw" ]; then
    log_error "Default SED password is not defined"
    exit 1
fi

find_disk_name
res_find_disk=$?
if [ $res_find_disk != 0 ]; then
    log_warn "Block device cannot be determined"
    exit 1
fi

if ! check_sed_ready; then
    log_warn "SED is not ready for operations"
    exit 1
fi

validate_sed_pw $default_pw
res_val_default=$?
if [ $res_val_default = 0 ]; then
    log_info "SED default password is the existing one"
    exit 0
else
    log_info "Resetting SED password to the default"
    /usr/local/bin/sed_pw_change.sh -p $default_pw
    if [ $? -ne 0 ]; then
        log_error "SED password change failed"
        exit 1
    else
        log_info "SED password change succeed"
        exit 0
    fi
fi
