#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#############################################################################
# Mellanox
#
# Module contains an implementation of new platform api
#
#############################################################################


try:
    from functools import wraps
    import sys
    import importlib.util
    import os
    import filelock
    from sonic_platform.component import ComponentBMC
    from sonic_platform_base.bmc_base import BMCBase
    from sonic_py_common import device_info
    from sonic_py_common.logger import Logger
    from sonic_platform_base.redfish_client import RedfishClient
except ImportError as e:
    raise ImportError (str(e) + "- required module not found")


logger = Logger('bmc')


HW_MGMT_REDFISH_CLIENT_PATH = '/usr/bin/hw_management_redfish_client.py'
HW_MGMT_REDFISH_CLIENT_NAME = 'hw_management_redfish_client'


def under_lock(lockfile, timeout=2):
    """ Execute operations under lock. """
    def _under_lock(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            with filelock.FileLock(lockfile, timeout):
                return func(*args, **kwargs)

        return wrapped_function
    return _under_lock


def _get_hw_mgmt_redfish_client():
    if HW_MGMT_REDFISH_CLIENT_NAME in sys.modules:
        return sys.modules[HW_MGMT_REDFISH_CLIENT_NAME]
    if not os.path.exists(HW_MGMT_REDFISH_CLIENT_PATH):
        raise ImportError(f"{HW_MGMT_REDFISH_CLIENT_NAME} not found at {HW_MGMT_REDFISH_CLIENT_PATH}")
    spec = importlib.util.spec_from_file_location(HW_MGMT_REDFISH_CLIENT_NAME, HW_MGMT_REDFISH_CLIENT_PATH)
    hw_mgmt_redfish_client = importlib.util.module_from_spec(spec)
    sys.modules[HW_MGMT_REDFISH_CLIENT_NAME] = hw_mgmt_redfish_client
    spec.loader.exec_module(hw_mgmt_redfish_client)
    return hw_mgmt_redfish_client


def with_credential_restore(api_func):
    @wraps(api_func)
    def wrapper(self, *args, **kwargs):
        if self.rf_client is None:
            raise Exception('Redfish instance initialization failure')
        if not self.rf_client.has_login():
            self._login()
        ret, data = api_func(self, *args, **kwargs)
        if ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            logger.log_notice(f'{api_func.__name__}() returns bad credential. ' \
                              'Trigger BMC TPM based password recovery flow')
            restored = self._restore_tpm_credential()
            if restored:
                logger.log_notice(f'BMC TPM based password recovered. Retry {api_func.__name__}()')
                ret, data = api_func(self, *args, **kwargs)
            else:
                self._logout()
                logger.log_notice(f'Fail to recover BMC based password')
                return (RedfishClient.ERR_CODE_AUTH_FAILURE, data)
        self._logout()
        return (ret, data)
    return wrapper


class BMC(BMCBase):

    """
    BMC encapsulates BMC device functionality.
    It also acts as wrapper of RedfishClient.
    """

    BMC_NOS_ACCOUNT = 'yormnAnb'
    BMC_NOS_ACCOUNT_DEFAULT_PASSWORD = "ABYX12#14artb51"

    _instance = None

    def __init__(self, addr):
        # Call BMCBase ctor which sets self.addr and self.rf_client
        super().__init__(addr)
        self.__using_tpm_password = True

    @staticmethod
    def get_instance():
        if BMC._instance is None:
            bmc_data = device_info.get_bmc_data()
            if not bmc_data:
                return None
            BMC._instance = BMC(bmc_data['bmc_addr'])
        return BMC._instance

    def _get_login_user_callback(self):
        return BMC.BMC_NOS_ACCOUNT

    def _get_login_password_callback(self):
        if self.__using_tpm_password:
            return self._get_tpm_password()
        else:
            return BMC.BMC_NOS_ACCOUNT_DEFAULT_PASSWORD

    def _get_tpm_password(self):
        try:
            return _get_hw_mgmt_redfish_client().BMCAccessor().get_login_password()
        except Exception as e:
            logger.log_error(f"Error getting TPM password from hw_management_redfish_client.py: {str(e)}")
            raise

    @under_lock(lockfile='/var/run/bmc_restore_tpm_credential.lock', timeout=5)
    def _restore_tpm_credential(self):
        logger.log_notice(f'Start BMC TPM password recovery flow')
        # We are not good with TPM password here, Try to login with default password
        logger.log_notice(f'Try to login with BMC default password')
        # Indicate password callback function to switch to default password temporarily
        self.__using_tpm_password = False
        ret = self.rf_client.login()
        if ret != RedfishClient.ERR_CODE_OK:
            logger.log_error(f'Bad credential: Fail to login BMC with both TPM based and default passwords')
            # Resume to TPM password
            self.__using_tpm_password = True
            return False

        # Indicate RedfishClient to switch to TPM password
        self.__using_tpm_password = True
        logger.log_notice(f'Login successfully with BMC default password')
        try:
            password = self._get_tpm_password()
        except Exception as e:
            self.rf_client.invalidate_session()
            logger.log_error(f'Fail to get TPM password: {str(e)}')
            return False

        logger.log_notice(f'Try to apply TPM based password to BMC NOS account')
        ret, msg = self._change_login_password(password)
        if ret != RedfishClient.ERR_CODE_OK:
            self.rf_client.invalidate_session()
            logger.log_error(f'Fail to apply TPM based password to BMC NOS account: {msg}')
            return False
        else:
            logger.log_notice(f'TPM password is successfully applied to BMC NOS account')

        return True

    def _get_component_list(self):
        return [ComponentBMC()]

    def _login(self):
        logger.log_notice(f'Try login to BMC using the NOS account')
        if self.rf_client.has_login():
            return RedfishClient.ERR_CODE_OK
        ret = self.rf_client.login()
        if ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            logger.log_notice(f'Fail to login BMC with TPM password. Trigger password recovery flow')
            restored = self._restore_tpm_credential()
            if restored:
                ret = RedfishClient.ERR_CODE_OK
        elif ret == RedfishClient.ERR_CODE_PASSWORD_UNAVAILABLE:
            logger.log_notice(f'Fail to generate TPM password')
        return ret
    
    def _logout(self):
        if self.rf_client.has_login():
            return self.rf_client.logout()
        return RedfishClient.ERR_CODE_OK
    
    @with_credential_restore
    def _request_bmc_reset(self, graceful=True):
        return super()._request_bmc_reset(graceful)

    @with_credential_restore
    def _get_firmware_version(self, fw_id):
        return super()._get_firmware_version(fw_id)

    @with_credential_restore
    def _get_eeprom_info(self, eeprom_id):
        return super()._get_eeprom_info(eeprom_id)
    
    @with_credential_restore
    def update_firmware(self, fw_image):
        return super().update_firmware(fw_image)
    
    @with_credential_restore
    def trigger_bmc_debug_log_dump(self):
        return super().trigger_bmc_debug_log_dump()

    @with_credential_restore
    def get_bmc_debug_log_dump(self, task_id, filename, path, timeout = 120):
        return super().get_bmc_debug_log_dump(task_id, filename, path, timeout)
    
    def reset_root_password(self):
        '''
        There is no with_credential_restore wrapper here
        for preventing infinite loop with _change_login_password
        '''
        try:
            self._login()
            (ret, msg) = super().reset_root_password()
            self._logout()
            return (ret, msg)
        except Exception as e:
            logger.log_error(f'Failed to reset BMC root password: {str(e)}')
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, str(e))
