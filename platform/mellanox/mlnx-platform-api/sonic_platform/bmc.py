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
    import subprocess
    import filelock
    from sonic_platform.component import ComponentBMC
    from sonic_platform_base.bmc_base import BMCBase
    from sonic_py_common import device_info
    from sonic_py_common.logger import Logger
    from .redfish_client import RedfishClient
    from . import utils
except ImportError as e:
    raise ImportError (str(e) + "- required module not found")


HW_MGMT_REDFISH_CLIENT_PATH = '/usr/bin/hw_management_redfish_client.py'
HW_MGMT_REDFISH_CLIENT_NAME = 'hw_management_redfish_client'


logger = Logger()


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


def ping(host):
    # -c 1: Send only one packet
    # -W 1: Wait 1 second for a response
    command = ['/usr/bin/ping', '-c', '1', '-W', '1', host]
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def with_credential_restore(api_func):
    @wraps(api_func)
    def wrapper(self, *args, **kwargs):
        if self.rf_client is None:
            raise Exception('Redfish instance initialization failure')

        if not self.rf_client.has_login():
            self._login()
        elif api_func.__name__ == 'update_firmware':
            # Create new token before running update_firmware API
            self._logout()
            self._login()

        ret, data = api_func(self, *args, **kwargs)
        if ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            # Trigger credential restore flow
            logger.log_notice(f'{api_func.__name__}() returns bad credential. ' \
                              'Trigger BMC TPM based password recovery flow')
            restored = self._restore_tpm_credential()
            if restored:
                # Execute again
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

    '''
    BMC encapsulates BMC device details such as IP address, credential management.
    It also acts as wrapper of RedfishClient.
    '''

    CURL_PATH = '/usr/bin/curl'
    BMC_NOS_ACCOUNT = 'yormnAnb'
    BMC_NOS_ACCOUNT_DEFAULT_PASSWORD = "ABYX12#14artb51"
    ROOT_ACCOUNT = 'root'
    ROOT_ACCOUNT_DEFAULT_PASSWORD = '0penBmcTempPass!'
    BMC_DIR = "/host/bmc"
    MAX_LOGIN_ERROR_PROBE_CNT = 5

    _instance = None

    def __init__(self, addr):

        self.addr = addr
        self.using_tpm_password = True
        self.probe_cnt = 0

        self.rf_client = RedfishClient(BMC.CURL_PATH,
                                        addr,
                                        BMC.BMC_NOS_ACCOUNT,
                                        self._get_password_callback,
                                        logger)

    @staticmethod
    def get_instance():
        if BMC._instance is None:
            bmc_data = device_info.get_bmc_data()
            if not bmc_data:
                return None
            BMC._instance = BMC(bmc_data['bmc_addr'])
        return BMC._instance

    def _get_ip_addr(self):
        return self.addr

    # Password callback function passed to RedfishClient
    def _get_password_callback(self):
        if self.using_tpm_password:
            return self._get_login_password()
        else:
            return BMC.BMC_NOS_ACCOUNT_DEFAULT_PASSWORD

    def _get_login_password(self):
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
        self.using_tpm_password = False
        ret = self.rf_client.login()

        if ret != RedfishClient.ERR_CODE_OK:
            logger.log_error(f'Bad credential: Fail to login BMC with both TPM based and default passwords')
            if self.probe_cnt < BMC.MAX_LOGIN_ERROR_PROBE_CNT:
                # Log the exact failure reason since the login API does not return anything
                # Trigger a GET request using user/password instead of token, then BMC will report the failure details
                self.rf_client.probe_login_error()
                self.probe_cnt += 1
            # Resume to TPM password
            self.using_tpm_password = True
            return False

        # Indicate RedfishClient to switch to TPM password
        self.using_tpm_password = True

        logger.log_notice(f'Login successfully with BMC default password')
        try:
            password = self._get_login_password()
        except Exception as e:
            self.rf_client.invalidate_login_token()
            logger.log_error(f'Fail to get login password from TPM: {str(e)}')
            return False

        # Apply TPM password to NOS account.
        logger.log_notice(f'Try to apply TPM based password to BMC NOS account')
        ret, msg = self._change_login_password(password)
        if ret != RedfishClient.ERR_CODE_OK:
            self.rf_client.invalidate_login_token()
            logger.log_error(f'Fail to apply TPM based password to BMC NOS account')
            return False
        else:
            logger.log_notice(f'TPM password is successfully applied to BMC NOS account')

        return True

    def _get_eeprom_id(self):
        return 'BMC_eeprom'
    
    def _get_id(self):
        return 'MGX_FW_BMC_0'
    
    def _get_component_list(self):
        return [ComponentBMC()]

    def _login(self):
        logger.log_notice(f'Try login to BMC using the NOS account')
        if self.rf_client is None:
            return RedfishClient.ERR_CODE_AUTH_FAILURE

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
        if self.rf_client and self.rf_client.has_login():
            return self.rf_client.logout()
        else:
            return RedfishClient.ERR_CODE_OK

    # There is no with_credential_restore wrapper here for preventing infinite loop
    def _change_login_password(self, password, user=None):
        if self.rf_client is None:
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, "")

        return self.rf_client.redfish_api_change_login_password(password, user)
    
    def _is_bmc_eeprom_content_valid(self, eeprom_info):
        if None == eeprom_info or 0 == len(eeprom_info):
            return False
        got_error = eeprom_info.get('error')
        if got_error:
            logger.log_error(f'Got error when quering eeprom: {got_error}')
            return False
        return True

    @with_credential_restore
    def _get_firmware_list(self):
        return self.rf_client.redfish_api_get_firmware_list()

    @with_credential_restore
    def _get_firmware_version(self, fw_id):
        return self.rf_client.redfish_api_get_firmware_version(fw_id)

    @with_credential_restore
    def _get_eeprom_list(self):
        return self.rf_client.redfish_api_get_eeprom_list()

    @with_credential_restore
    def _get_eeprom_info(self, eeprom_id):
        return self.rf_client.redfish_api_get_eeprom_info(eeprom_id)

    @with_credential_restore
    def _request_bmc_reset(self, graceful=True):
        bmc_reset_type = RedfishClient.BMC_RESET_TYPE_GRACEFUL_RESTART if graceful else RedfishClient.BMC_RESET_TYPE_FORCE_RESTART
        return self.rf_client.redfish_api_request_bmc_reset(bmc_reset_type=bmc_reset_type)

    @with_credential_restore
    def _update_components_firmware(self, fw_image, fw_ids=None, force_update=False, progress_callback=None, timeout=1800):
        logger.log_notice(f'Installing BMC firmware image {fw_image}')
        ret, msg = self.rf_client.redfish_api_update_firmware(fw_image,
                                                            fw_ids,
                                                            force_update,
                                                            timeout,
                                                            progress_callback)
        logger.log_notice(f'Firmware update result: {ret}')
        if force_update == False and ret == RedfishClient.ERR_CODE_LOWER_VERSION:
            logger.log_notice(f'Firmware image timestamp is lower than the current timestamp')
        if force_update == False and ret == RedfishClient.ERR_CODE_IDENTICAL_VERSION:
            logger.log_notice(f'Firmware image version is identical to the current version')
        if msg:
            logger.log_notice(f'{msg}')
        return (ret, msg)

    def get_name(self):
        return 'BMC'
    
    def get_presence(self):
        platform_path = device_info.get_path_to_platform_dir()
        bmc_json_path = \
            os.path.join(platform_path, 'bmc.json')
        bmc_data = utils.load_json_file(bmc_json_path)
        if bmc_data and bmc_data.get('bmc_addr'):
            return True
        return False
    
    def get_model(self):
        eeprom_info = self.get_eeprom()
        if False == self._is_bmc_eeprom_content_valid(eeprom_info):
            return None
        return eeprom_info.get('Model')
    
    def get_serial(self):
        eeprom_info = self.get_eeprom()
        if False == self._is_bmc_eeprom_content_valid(eeprom_info):
            return None
        return eeprom_info.get('SerialNumber')

    def get_revision(self):
        return 'N/A'
    
    def get_status(self):
        if not self.get_presence():
            return False
        if not ping(self.addr):
            return False
        return True
    
    def is_replaceable(self):
        return False

    def get_eeprom(self):
        try:
            eeprom_id = self._get_eeprom_id()
            if not eeprom_id:
                logger.log_error('BMC EEPROM ID is not defined')
                return {}
            ret, eeprom_info = self._get_eeprom_info(eeprom_id)
            if ret != RedfishClient.ERR_CODE_OK:
                logger.log_error(f'Failed to get BMC EEPROM info: {ret}')
            return eeprom_info
        except Exception as e:
            logger.log_error(f'Failed to get BMC EEPROM info: {str(e)}')
            return {}
    
    def get_version(self):
        ret = 0
        version = 'N/A'
        try:
            fw_id = self._get_id()
            if not fw_id:
                logger.log_error('BMC firmware ID is not defined')
                return 'N/A'
            ret, version =  self._get_firmware_version(fw_id)
        except Exception as e:
            logger.log_error(f'Failed to get BMC firmware version: {str(e)}')
        if ret != RedfishClient.ERR_CODE_OK:
            return 'N/A'
        return version
    
    def reset_root_password(self):
        try:
            self._login()
            (ret, msg) = self._change_login_password(BMC.ROOT_ACCOUNT_DEFAULT_PASSWORD, BMC.ROOT_ACCOUNT)
            self._logout()
            return (ret, msg)
        except Exception as e:
            logger.log_error(f'Failed to reset BMC root password: {str(e)}')
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, str(e))
    
    @with_credential_restore
    def trigger_bmc_debug_log_dump(self):
        return self.rf_client.redfish_api_trigger_bmc_debug_log_dump()

    @with_credential_restore
    def get_bmc_debug_log_dump(self, task_id, filename, path, timeout = 120):
        return self.rf_client.redfish_api_get_bmc_debug_log_dump(task_id, filename, path, timeout)
    
    def update_firmware(self, fw_image):
        fw_id = self._get_id()
        if not fw_id:
            logger.log_error('BMC firmware ID is not defined')
            return (RedfishClient.ERR_CODE_GENERIC_ERROR, 'BMC firmware ID is not defined')
        ret, msg = self._update_components_firmware(fw_image, fw_ids=[fw_id])
        if ret == RedfishClient.ERR_CODE_LOWER_VERSION:
            logger.log_notice(f'Try to update BMC firmware with force_update for downgrade')
            ret, msg = self._update_components_firmware(fw_image, fw_ids=[fw_id], force_update=True)
        elif ret == RedfishClient.ERR_CODE_IDENTICAL_VERSION:
            logger.log_notice(f'Try to update BMC firmware with force_update for installing identical version')
            ret, msg = self._update_components_firmware(fw_image, fw_ids=[fw_id], force_update=True)
        return (ret, msg)
