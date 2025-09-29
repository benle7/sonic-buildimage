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
# Module contains an implementation of RedFish client which provides
# firmware upgrade and sensor retrieval functionality
#
#############################################################################


import subprocess
import json
import time
import re
import shlex
from datetime import datetime


'''
cURL wrapper for Redfish client access
'''
class RedfishClient:

    DEFAULT_TIMEOUT = 3
    DEFAULT_LOGIN_TIMEOUT = 4

    REDFISH_URI_FW_INVENTORY = '/redfish/v1/UpdateService/FirmwareInventory'
    REDFISH_URI_CHASSIS_INVENTORY = '/redfish/v1/Chassis'
    REDFISH_URI_TASKS = '/redfish/v1/TaskService/Tasks'
    REDFISH_URI_UPDATE_SERVICE_UPDATE_MULTIPART = '/redfish/v1/UpdateService/update-multipart'
    REDFISH_URI_UPDATE_SERVICE = '/redfish/v1/UpdateService'
    REDFISH_URI_ACCOUNTS = '/redfish/v1/AccountService/Accounts'
    REDFISH_BMC_LOG_DUMP = '/redfish/v1/Managers/BMC_0/LogServices/Dump/Actions'
    REDFISH_REQUEST_SYSTEM_RESET = '/redfish/v1/Systems/System_0/Actions/ComputerSystem.Reset'
    REDFISH_REQUEST_BMC_RESET = '/redfish/v1/Managers/BMC_0/Actions/Manager.Reset'

    ERR_CODE_OK = 0
    ERR_CODE_AUTH_FAILURE = -1
    ERR_CODE_INVALID_JSON_FORMAT = -2
    ERR_CODE_UNEXPECTED_RESPONSE = -3
    ERR_CODE_CURL_FAILURE = -4
    ERR_CODE_NOT_LOGIN = -5
    ERR_CODE_TIMEOUT = -6
    ERR_CODE_LOWER_VERSION = -7
    ERR_CODE_PASSWORD_UNAVAILABLE = -8
    ERR_CODE_URI_NOT_FOUND = -9
    ERR_CODE_SERVER_UNREACHABLE = -10
    ERR_CODE_UNSUPPORTED_PARAMETER = -11
    ERR_CODE_GENERIC_ERROR = -12
    ERR_CODE_IDENTICAL_VERSION = -13

    CURL_ERR_OK = 0
    CURL_ERR_OPERATION_TIMEDOUT = 28
    CURL_ERR_COULDNT_RESOLVE_HOST = 6
    CURL_ERR_FAILED_CONNECT_TO_HOST = 7
    CURL_ERR_SSL_CONNECT_ERROR = 35

    CURL_TO_REDFISH_ERROR_MAP = \
    {
        CURL_ERR_COULDNT_RESOLVE_HOST :   ERR_CODE_SERVER_UNREACHABLE,
        CURL_ERR_FAILED_CONNECT_TO_HOST : ERR_CODE_SERVER_UNREACHABLE,
        CURL_ERR_SSL_CONNECT_ERROR :      ERR_CODE_SERVER_UNREACHABLE,
        CURL_ERR_OPERATION_TIMEDOUT :     ERR_CODE_TIMEOUT,
        CURL_ERR_OK :                     ERR_CODE_OK
    }

    REDFISH_BMC_GRACEFUL_RESTART = 'GracefulRestart'
    REDFISH_BMC_FORCE_RESTART = 'ForceRestart'

    BMC_RESET_TYPE_GRACEFUL_RESTART = 0
    BMC_RESET_TYPE_FORCE_RESTART = 1

    BMC_RESET_TYPE_MAP = [
        'GracefulRestart',
        'ForceRestart'
    ]

    '''
    Constructor
    A password_callback parameter is provoided because:
    1. Password is not allowed to be saved for security concern.
    2. If token expires or becomes invalid for some reason (for example, being
    revoked from BMC web interface), RedfishClient will do login retry in which
    password is required anyway. It will get password from an external password
    provider, for example class BMC which holds the responsibility of generating
    password from TPM.
    '''
    def __init__(self, curl_path, ip_addr, user, password_callback, logger):
        self.__curl_path = curl_path
        self.__svr_ip = ip_addr
        self.__user = user
        self.__password_callback = password_callback
        self.__token = None
        self.__logger = logger

        self.__task_status_event_handlers = {}
        self.register_task_status_event_handlers()

        self.__logger.log_notice(f'[Redfish Client] RedfishClient instance (to {self.__svr_ip}) is created\n')

    def register_task_status_event_handlers(self):
        self.__task_status_event_handlers = {
            'UpdateSuccessful': self.__update_successful_handler,
            'ResourceErrorsDetected': self.__resource_errors_detected_handler,
            'ComponentUpdateSkipped': self.__component_update_skipped_handler,
            'TaskAborted': self.__task_aborted_handler
        }

    def get_login_token(self):
        return self.__token

    def curl_errors_to_redfish_erros_translation(self, curl_error):
        return self.CURL_TO_REDFISH_ERROR_MAP.get(
                    curl_error, RedfishClient.ERR_CODE_CURL_FAILURE)

    def invalidate_login_token(self):
        self.__logger.log_notice(f'[Redfish Client] Invalidate login token')
        self.__token = None

    '''
    Build the POST command to login and get bearer token
    '''
    def __build_login_cmd(self, password):
        cmd = f'{self.__curl_path} -m {RedfishClient.DEFAULT_LOGIN_TIMEOUT} -k ' \
              f'-H "Content-Type: application/json" ' \
              f'-X POST https://{self.__svr_ip}/login ' \
              f'-d \'{{"username" : "{self.__user}", "password" : "{password}"}}\''
        return cmd

    '''
    Build the POST command to logout and release the token
    '''
    def __build_logout_cmd(self):
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-X POST https://{self.__svr_ip}/logout'

        return cmd

    '''
    Build the GET command
    '''
    def __build_get_cmd(self, uri, output_file = None):
        output_str = '' if not output_file else f'--output {output_file}'
        cmd = f'{self.__curl_path} -m {RedfishClient.DEFAULT_TIMEOUT} -k ' \
              f'-H "X-Auth-Token: {self.__token}" --request GET ' \
              f'--location https://{self.__svr_ip}{uri} ' \
              f'{output_str}'
        return cmd

    '''
    Build a GET command using user/password to probe login account error
    '''
    def __build_login_probe_cmd(self):
        uri = RedfishClient.REDFISH_URI_ACCOUNTS
        password = self.__password_callback()
        cmd = f'{self.__curl_path} -m {RedfishClient.DEFAULT_TIMEOUT} -k ' \
              f'-u {self.__user}:{password} --request GET ' \
              f'--location https://{self.__svr_ip}{uri} '
        return cmd

    '''
    Build the POST command to do firmware upgdate-multipart
    '''
    def __build_fw_update_multipart_cmd(self, fw_image, fw_ids = None, force_update=False):
        if fw_ids: # fw_ids is not empty
            targets = [f'"{RedfishClient.REDFISH_URI_FW_INVENTORY}/{fw_id}"' \
                for fw_id in fw_ids]
            targets_str = ', '.join(targets)
            targets_str =  f', "Targets":[{targets_str}]'
        else: # None or empty
            targets_str = ''
        force_update_str = 'true' if force_update else 'false'
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_URI_UPDATE_SERVICE_UPDATE_MULTIPART} ' \
              f"--form 'UpdateParameters={{\"ForceUpdate\":{force_update_str}" \
              f"{targets_str}}};type=application/json' " \
              f'--form "UpdateFile=@{fw_image};type=application/octet-stream"'
        return cmd

    '''
    Build the POST command to request BMC reset
    '''
    def __build_request_bmc_reset_cmd(self, bmc_reset_type):
        if bmc_reset_type == RedfishClient.BMC_RESET_TYPE_FORCE_RESTART:
            reset_type = RedfishClient.REDFISH_BMC_FORCE_RESTART
        else:
            reset_type = RedfishClient.REDFISH_BMC_GRACEFUL_RESTART
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-H "Content-Type: application/json" ' \
              f'-X POST https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_REQUEST_BMC_RESET} ' \
              f'-d \'{{"ResetType": "{reset_type}"}}\''
        return cmd

    '''
    Build the PATCH command to change login password
    '''
    def __build_change_password_cmd(self, new_password, user):
        if user is None:
            user = self.__user

        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-H "Content-Type: application/json" -X PATCH ' \
              f'https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_URI_ACCOUNTS}/{user} ' \
              f'-d \'{{"Password" : "{new_password}"}}\''
        return cmd

    '''
    Build the POST command to start BMC debug dump request Redfish Task
    '''
    def __build_bmc_debug_log_dump_cmd(self):
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-H "Content-Type: application/json" ' \
              f'-X POST https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_BMC_LOG_DUMP}/LogService.CollectDiagnosticData ' \
              '-d \'{"DiagnosticDataType":"Manager"}\''
        return cmd

    '''
    Obfuscate username in logout response
    '''
    def __obfuscate_user_name(self, response):
        # Obfuscate 'username' in the payload
        # For example: login
        pattern = r"User '[^']+'"
        replacement = "User '******'"
        obfuscation_response = re.sub(pattern, replacement, response)
        return obfuscation_response

    '''
    Obfuscate username and password while asking for bearer token
    '''
    def __obfuscate_user_password(self, cmd):
        # Obfuscate 'username' and 'password' in the payload
        # For example: login
        pattern = r'"username" : "[^"]*", "password" : "[^"]*"'
        replacement = '"username" : "******", "password" : "******"'
        obfuscation_cmd = re.sub(pattern, replacement, cmd)
        # Obfuscate username and password in the command line parameter
        # For example: use user:password directly in the command to do
        # login failure probe
        pattern =  r'-u [!-~]+:[!-~]+'
        replacement = '-u ******:******'
        obfuscation_cmd = re.sub(pattern, replacement, obfuscation_cmd)
        return obfuscation_cmd

    '''
    Obfuscate bearer token in the response string
    '''
    def __obfuscate_token_response(self, response):
        # Credential obfuscation
        pattern = r'"token": "[^"]*"'
        replacement = '"token": "******"'
        obfuscation_response = re.sub(pattern,
                                        replacement,
                                        response)
        return obfuscation_response

    '''
    Obfuscate bearer token passed to cURL
    '''
    def __obfuscate_auth_token(self, cmd):
        pattern = r'X-Auth-Token: [^"]+'
        replacement = 'X-Auth-Token: ******'
        obfuscation_cmd = re.sub(pattern, replacement, cmd)
        return obfuscation_cmd

    '''
    Obfuscate password while aksing for password change
    '''
    def __obfuscate_password(self, cmd):
        pattern = r'"Password" : "[^"]*"'
        replacement = '"Password" : "******"'
        obfuscation_cmd = re.sub(pattern, replacement, cmd)
        return obfuscation_cmd

    '''
    Obfuscate username in URLs
    '''
    def __obfuscate_username_in_url(self, cmd):
        # Obfuscate username in AccountService URLs
        # For example: /redfish/v1/AccountService/Accounts/yormnAnb
        pattern = r'/AccountService/Accounts/[^/\s]+'
        replacement = '/AccountService/Accounts/******'
        obfuscation_cmd = re.sub(pattern, replacement, cmd)
        return obfuscation_cmd

    '''
    Parse cURL output to extract response and HTTP status code
    Return value:
        Tuple of JSON response and HTTP status code
    '''
    def __parse_curl_output(self, curl_output):
        response_str = None
        http_status_code = None
        pattern = r'([\s\S]*?)(?:\n)?HTTP Status Code: (\d+)$'
        match = re.search(pattern, curl_output, re.MULTILINE)
        if match:
            response_str = match.group(1)     # The JSON part
            http_status_code = match.group(2) # The HTTP status code
        # response_str 'None' means format error
        return (response_str, http_status_code)

    '''
    Execute cURL command and return the output and error messages
    '''
    def __exec_curl_cmd_internal(self, cmd):
        # Flag to indicate if the command is for task status checking
        task_mon = (RedfishClient.REDFISH_URI_TASKS in cmd)
        # Flag to indicate if the command is for login
        login_cmd = ('/login ' in cmd)
        # Flag to indicate if the command is for logout
        logout_cmd = ('/logout' in cmd)
        # Flag to indicate if the command is for password change
        password_change = (RedfishClient.REDFISH_URI_ACCOUNTS in cmd)
        # Credential obfuscation
        obfuscation_cmd = self.__obfuscate_user_password(cmd)
        obfuscation_cmd = self.__obfuscate_auth_token(obfuscation_cmd)

        if password_change:
            obfuscation_cmd = self.__obfuscate_username_in_url(obfuscation_cmd)
            obfuscation_cmd = self.__obfuscate_password(obfuscation_cmd)

        cmd_str = obfuscation_cmd
        exec_cmd_msg = f'Execute cURL command: {cmd_str}'
        if not task_mon:
            self.__logger.log_notice(f'[Redfish Client] {exec_cmd_msg}')

        # Instruct cURL to append HTTP status code after JSON response
        cmd += ' -w "\nHTTP Status Code: %{http_code}"'
        process = subprocess.Popen(shlex.split(cmd),
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        output_str, http_status_code = self.__parse_curl_output(output.decode('utf-8'))
        error_str = error.decode('utf-8')
        ret = process.returncode

        if (ret == RedfishClient.CURL_ERR_OK):
            # cURL will print r/x statistics on stderr.
            # Ignore it
            error_str = ''

        if (ret == RedfishClient.CURL_ERR_OK): # cURL retuns ok
            ret = RedfishClient.ERR_CODE_OK

            # For login/logout command, obfuscate the response
            if login_cmd:
                obfuscation_output_str = \
                    self.__obfuscate_token_response(output_str)
            elif logout_cmd:
                obfuscation_output_str = \
                    self.__obfuscate_user_name(output_str)
            else:
                obfuscation_output_str = output_str

            # No HTTP status code found, return immediately. This is unlikely to happen.
            if http_status_code is None:
                self.__logger.log_error(f'[Redfish Client] HTTP status code not found')
                self.__logger.log_notice(f'[Redfish Client] cURL output:')
                self.log_multi_line_str(obfuscation_output_str)
                ret = RedfishClient.ERR_CODE_CURL_FAILURE
                error_str = 'Unexpected curl output'
                return (ret, http_status_code, output_str, error_str)

            if not task_mon:
                self.__logger.log_notice(f'[Redfish Client] HTTP status code: {http_status_code}')
                self.__logger.log_notice(f'[Redfish Client] cURL output:')
                self.log_multi_line_str(obfuscation_output_str)
        else: # cURL returns error
            self.__logger.log_notice(f'[Redfish Client] cURL error:')
            self.log_multi_line_str(error_str)

            ret = self.curl_errors_to_redfish_erros_translation(ret)

        return (ret, http_status_code, output_str, error_str)

    '''
    Extract URI from the job response
    '''
    def __get_uri_from_response(self, response):
        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg, None)

        if "Payload" not in json_response:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            err_msg = "Error: Missing 'Payload' field"
            return (ret, err_msg, None)

        payload = json_response["Payload"]
        if "HttpHeaders" not in payload:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            err_msg = "Error: Missing 'HttpHeaders' field"
            return (ret, err_msg, None)

        http_headers = payload["HttpHeaders"]
        uri = None
        for header in http_headers:
            if "Location" in header:
                uri = header.split()[-1]

        if not uri:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            err_msg = "Error: Missing 'Location' field"
            return (ret, err_msg, None)

        return (RedfishClient.ERR_CODE_OK, "", uri)

    '''
    Log multi-line string
    '''
    def log_multi_line_str(self, msg):
        if msg is None:
            return
        lines = msg.splitlines()
        for line in lines:
            self.__logger.log_notice(f'[Redfish Client] {line}')

    '''
    Replace old token in the command. This happens in case token becomes invalid and re-login is triggered.
    '''
    def __update_token_in_command(self, cmd):
        pattern = r'X-Auth-Token:\s*[^\s\"\']+'
        new_cmd = re.sub(pattern, 'X-Auth-Token: ' + self.__token, cmd)
        return new_cmd

    '''
    Wrapper function to execute the given cURL command which can deal with invalid bearer token case.
    '''
    def exec_curl_cmd(self, cmd, max_retries=2):
        is_login_cmd = ('/login ' in cmd)

        # Not login, return
        if (not self.has_login()) and (not is_login_cmd):
            self.__logger.log_error('[Redfish Client] Need to login first before executing cURL command')
            return (RedfishClient.ERR_CODE_NOT_LOGIN, None, 'Not login', 'Not login')

        ret, http_status_code, output_str, error_str \
            = self.__exec_curl_cmd_internal(cmd)

        # cURL execution timeout, try again
        i = 0
        while (i < max_retries) and (ret == RedfishClient.ERR_CODE_TIMEOUT):
            # Increase timeout temporarily
            timeout = None
            match = re.search(r'-m\s*(\d+)', cmd)
            if match:
                timeout = int(match.group(1))
                timeout += 2
                cmd = re.sub(r'-m\s*\d+', f'-m {timeout}', cmd)

            ret, http_status_code, output_str, error_str \
                = self.__exec_curl_cmd_internal(cmd)

            i += 1

        # Authentication failure might happen in case of:
        #   - Incorrect password
        #   - Invalid token (Token may become invalid for some reason.
        #     For example, remote side may clear the session table or change password.
        #   - Account locked
        if not http_status_code == '401':
            return (ret, http_status_code, output_str, error_str)

        # Authentication failure on login, report error.
        if is_login_cmd:
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, http_status_code, 'Authentication failure', 'Authentication failed')

        # Authentication failure for other commands.
        # We can't differentiate various scenarios that may cause authentication failure.
        # Just do a re-login and retry the command and expect to recover.

        # Re-login and retry the command
        self.__logger.log_notice('[Redfish Client] Re-login and retry last command...')
        self.invalidate_login_token()
        ret = self.login()
        if ret == RedfishClient.ERR_CODE_OK:
            self.__logger.log_notice('[Redfish Client] Login successfully. Rerun last command\n')
            cmd = self.__update_token_in_command(cmd)
            ret, http_status_code, output_str, error_str = self.__exec_curl_cmd_internal(cmd)
            if ret != RedfishClient.ERR_CODE_OK:
                self.__logger.log_notice(f'[Redfish Client] Command rerun returns error {ret}\n')
            elif http_status_code == '401':
                self.__logger.log_notice('[Redfish Client] Command rerun fails as authentication failure\n')
                self.invalidate_login_token()
                ret = RedfishClient.ERR_CODE_AUTH_FAILURE
                output_str = error_str = 'Authentication failure'
            return (ret, http_status_code, output_str, error_str)
        elif ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            # Login fails, invalidate token.
            self.__logger.log_notice('[Redfish Client] Failed to login. Return as authentication failure\n')
            self.invalidate_login_token()
            return (ret, http_status_code, 'Authentication failure', 'Authentication failure')
        else:
            # Login fails for whatever reason, invalidate token.
            self.__logger.log_notice(f'[Redfish Client] Failed to login, error : {ret}\n')
            self.invalidate_login_token()
            return (ret, http_status_code, 'Login failure', 'Login failure')

    '''
    Check if already login
    '''
    def has_login(self):
        return self.__token is not None

    '''
    Login Redfish server and get bearer token
    '''
    def login(self):
        if self.has_login():
            return RedfishClient.ERR_CODE_OK

        try:
            password = self.__password_callback()
        except Exception as e:
            self.__logger.log_error(f'[Redfish Client] {str(e)}')
            return RedfishClient.ERR_CODE_PASSWORD_UNAVAILABLE

        cmd = self.__build_login_cmd(password)
        ret = 0
        response = ''
        error = ''
        ret, _, response, error = self.exec_curl_cmd(cmd)

        if (ret != 0):
            msg = f'Login failure: code {ret}, {error}'
            self.__logger.log_error(f'[Redfish Client] {msg}')
            return ret

        if len(response) == 0:
            msg = 'Got empty Redfish login response'
            self.__logger.log_error(f'[Redfish Client] {msg}')
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            return ret

        try:
            json_response = json.loads(response)
            if 'error' in json_response:
                msg = json_response['error']['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            elif 'token' in json_response:
                token = json_response['token']
                if token is not None:
                    ret = RedfishClient.ERR_CODE_OK
                    self.__token = token
                    self.__logger.log_notice('[Redfish Client] Redfish login successfully and session token updated')
                else:
                    msg = 'Login failure: empty "token" field found\n'
                    self.__logger.log_error(f'[Redfish Client] {msg}')
                    ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            else:
                msg = 'Login failure: no "token" field found\n'
                self.__logger.log_error(f'[Redfish Client] {msg}')
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
        except Exception as e:
            msg = 'Login failure: invalid json format\n'
            self.__logger.log_error(f'[Redfish Client] {msg}')
            self.log_multi_line_str(response)
            ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT

        return ret

    '''
    Logout Redfish server
    '''
    def logout(self):
        if not self.has_login():
            return RedfishClient.ERR_CODE_OK

        self.__logger.log_notice('[Redfish Client] Logout redfish session')

        cmd = self.__build_logout_cmd()
        ret = 0
        response = ''
        error = ''
        ret, _, response, error = self.exec_curl_cmd(cmd)

        # Invalidate token anyway
        self.__token = None

        if (ret != 0): # cURL execution error
            msg = 'Logout failure: curl command returns error\n'
            self.__logger.log_notice(f'[Redfish Client] {msg}')
            return ret

        if len(response) == 0: # Invalid token
            msg = 'Got empty Redfish logout response. It indicates an invalid token\n'
            self.__logger.log_notice(f'[Redfish Client] {msg}')
            return ret

        try:
            json_response = json.loads(response)

            if 'status' in json_response:
                status = json_response['status']
                if status != 'ok':
                    self.__logger.log_notice('[Redfish Client] Redfish response for logout failure: \n')
                    self.log_multi_line_str(response)
        except Exception as e:
            msg = 'Logout failure: invalid json format\n'
            self.__logger.log_error(f'[Redfish Client] {msg}')
            ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT

        return ret

    '''
    Use GET command with user/password to probe the exact error reason in case of login failure
    '''
    def probe_login_error(self):
        cmd = self.__build_login_probe_cmd()
        ret, _, response, error = self.__exec_curl_cmd_internal(cmd)

        if (ret != 0): # cURL execution error
            msg = 'Probe login failure: curl command returns error'
            self.__logger.log_notice(f'[Redfish Client] {msg}')
            return (RedfishClient.ERR_CODE_GENERIC_ERROR, response)

        if len(response) == 0:
            msg = 'Got empty response'
            self.__logger.log_notice(f'[Redfish Client] {msg}')
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, msg)

        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Probe login failure: invalid json format'
            self.__logger.log_error(f'[Redfish Client] {msg}')
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg)

        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'code' in err:
                err_code = err['code']
                if 'ResourceAtUriUnauthorized' in err_code:
                    ret = RedfishClient.ERR_CODE_AUTH_FAILURE
                    err_msg = "Account is locked or wrong password"
                else:
                    ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                    err_msg = f"Not expected error code: {err_code}"
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'error code' field"

            return (ret, f'Error: {err_msg}')

        return (RedfishClient.ERR_CODE_OK, response)

    '''
    Get firmware inventory

    Parameters:   None
    Return value:  (ret, firmware_list)
      ret               return code
      firmware_list     list of tuple (fw_id, version)
    '''
    def redfish_api_get_firmware_list(self):
        cmd = self.__build_get_cmd(RedfishClient.REDFISH_URI_FW_INVENTORY)
        ret, _, response, error = self.exec_curl_cmd(cmd)
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, [])
        try:
            json_response = json.loads(response)
            item_list = json_response["Members"]
        except json.JSONDecodeError as e:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, [])
        except Exception as e:
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, [])
        fw_list = []
        for item in item_list:
            fw_id = item["@odata.id"].split('/')[-1]
            ret, version = self.redfish_api_get_firmware_version(fw_id)
            if (ret != RedfishClient.ERR_CODE_OK):
                version = "N/A"
            fw_list.append((fw_id, version))
        return (RedfishClient.ERR_CODE_OK, fw_list)

    '''
    Get firmware version by given ID

    Parameters:
      fw_id       firmware ID
    Return value:  (ret, version)
      ret         return code
      version     firmware version string
    '''
    def redfish_api_get_firmware_version(self, fw_id):
        version = 'N/A'
        uri = f'{RedfishClient.REDFISH_URI_FW_INVENTORY}/{fw_id}'
        cmd = self.__build_get_cmd(uri)
        ret, _, response, error_msg = self.exec_curl_cmd(cmd)
        if (ret == RedfishClient.ERR_CODE_OK):
            try:
                json_response = json.loads(response)
                if 'Version' in json_response:
                    version = json_response['Version']
                else:
                    msg = 'Error: Version not found in Redfish response'
                    self.__logger.log_error(f'[Redfish Client] {msg}')
            except json.JSONDecodeError as e:
                msg = f'Error: Invalid Redfish response JSON format on querying {fw_id} version'
                self.__logger.log_notice(f'[Redfish Client] {msg}')
                ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
            except Exception as e:
                msg = f'Error: Exception {str(e)} caught on querying {fw_id} version'
                self.__logger.log_notice(f'[Redfish Client] {msg}')
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
        else:
            msg = f'Got error {ret} on querying {fw_id} version: {error_msg}'
            self.__logger.log_error(f'[Redfish Client] {msg}')
        return (ret, version)

    '''
    Update firmware

    Parameters:
      fw_image    firmware image path
      timeout     timeout value in seconds
    Return value:  (ret, error_msg)
      ret                  return code
      error_msg            error message string
    '''
    def redfish_api_update_firmware(self, fw_image, fw_ids = None, \
            force_update=False, timeout=1800, progress_callback=None):

        # Trigger FW upgrade
        cmd = self.__build_fw_update_multipart_cmd(fw_image,
                                                   fw_ids=fw_ids,
                                                   force_update=force_update)
        ret, _, response, error_msg = self.exec_curl_cmd(cmd)
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, f'Error: {error_msg}', [], [])

        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg, [], [])

        # Retrieve task id from response
        task_id = ''
        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'message' in err:
                err_msg = err['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'message' field"
            return (ret, f'Error: {err_msg}', [], [])
        elif 'TaskStatus' in json_response:
            status = json_response['TaskStatus']
            if status == 'OK':
                task_id = json_response['Id']
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                return (ret, f'Error: Return status is {status}', [], [])

        # Wait for completion
        result = self.__wait_task_completion(task_id, timeout, progress_callback)
        lower_version = result.get('lower_version', False)
        identical_version = result.get('identical_version', False)
        err_detected = result.get('err_detected', False)

        if lower_version:
           result['ret_code'] = RedfishClient.ERR_CODE_LOWER_VERSION
        elif identical_version and not err_detected:
           result['ret_code'] = RedfishClient.ERR_CODE_IDENTICAL_VERSION
           # identical version comes with an 'aborted' message. Clear it.
           result['ret_msg'] = ''

        ret = result['ret_code']
        error_msg = result['ret_msg']

        return (ret, error_msg)

    '''

    Trigger BMC debug log dump file

    Return value:  (ret, (task_id, error_msg))
      ret         return code
      task_id     Redfish task-id to monitor
      error_msg   error message string
    '''
    def redfish_api_trigger_bmc_debug_log_dump(self):
        task_id = '-1'
        # Trigger debug log dump service
        cmd = self.__build_bmc_debug_log_dump_cmd()
        ret, _, response, error_msg = self.exec_curl_cmd(cmd)
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, (task_id, f'Error: {error_msg}'))

        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, (task_id, msg))

        # Retrieve task id from response
        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'message' in err:
                err_msg = err['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'message' field"
            return (ret, (task_id, f'Error: {err_msg}'))
        elif 'TaskStatus' in json_response:
            status = json_response['TaskStatus']
            if status == 'OK':
                task_id = json_response.get('Id', '')
                ret = RedfishClient.ERR_CODE_OK
                return (ret, (task_id, None))
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                return (ret, (task_id, f'Error: Return status is {status}'))

    '''
    Get BMC debug log dump file

    Parameters:
      filename    new file name
      file_path   location of the new file
      timeout     timeout value in seconds
    Return value:  (ret, error_msg)
      ret         return code
      error_msg   error message string
    '''
    def redfish_api_get_bmc_debug_log_dump(self, task_id, filename, file_path, timeout = 120):
        # Wait for completion
        result = self.__wait_task_completion(task_id, timeout)
        ret = result['ret_code']
        error_msg = result['ret_msg']
        response = result['response']

        if ret != RedfishClient.ERR_CODE_OK:
            return (ret, error_msg)

        # Fetch the file
        ret, error_msg, uri = self.__get_uri_from_response(response)
        if ret != RedfishClient.ERR_CODE_OK:
            return (ret, error_msg)

        if not uri:
            ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            return (ret, error_msg)

        output_file = f'{file_path}/{filename}'
        uri += '/attachment'
        cmd = self.__build_get_cmd(uri, output_file=output_file)
        ret, _, response, error_msg = self.exec_curl_cmd(cmd)

        return (ret, error_msg)

    '''
    Reads all the eeproms of the bmc

    Parameters:   None
    Return value:  (ret, eeprom_list)
      ret               return code
      eeprom_list     list of tuple (component_name, eeprom_data)
      eeprom_data     return value from redfish_api_get_eeprom_info called with component_name
    '''
    def redfish_api_get_eeprom_list(self):
        cmd = self.__build_get_cmd(RedfishClient.REDFISH_URI_CHASSIS_INVENTORY)
        ret, _, response, error = self.exec_curl_cmd(cmd)

        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, [])

        try:
            json_response = json.loads(response)
            item_list = json_response["Members"]
        except json.JSONDecodeError as e:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, [])
        except Exception as e:
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, [])

        eeprom_list = []
        for item in item_list:
            component_url = item.get("@odata.id")
            if not component_url:
                continue
            component_name = component_url.split('/')[-1]
            if 'eeprom' not in component_name:
                continue
            ret, eeprom_values = self.redfish_api_get_eeprom_info(component_name)

            eeprom_list.append((component_name, eeprom_values))

        return (RedfishClient.ERR_CODE_OK, eeprom_list)

    '''
    Get eeprom values for a given component

    Parameters:
      component_name       component name
    Return value:  (ret, eeprom_data)
      ret         return code
      eeprom_data     dictionary containing eeprom data
    '''
    def redfish_api_get_eeprom_info(self, component_name):
        uri = f'{RedfishClient.REDFISH_URI_CHASSIS_INVENTORY}/{component_name}'
        cmd = self.__build_get_cmd(uri)
        ret, _, response, err_msg = self.exec_curl_cmd(cmd)

        bad_eeprom_info = {'State': 'Fail'}
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, bad_eeprom_info)

        try:
            json_response = json.loads(response)
        except json.JSONDecodeError as e:
            ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
            return (ret, bad_eeprom_info)
        except Exception as e:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            return (ret, bad_eeprom_info)

        if 'error' in json_response: # Error found
            err = json_response['error']
            if ('code' in err) and ('ResourceNotFound' in err['code']):
                ret = RedfishClient.ERR_CODE_URI_NOT_FOUND
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            self.__logger.log_error(f'[Redfish Client] Got redfish error response for {component_name} query')
            return (ret, bad_eeprom_info)

        eeprom_info = {}
        for key,value in json_response.items():
            # Remove information that is not the eeprom content itself.
            # But part of the redfish protocol
            if '@odata' in str(value) or '@odata' in str(key):
                continue
            # Don't add the status, we will parse it and add it later
            if key == 'Status':
                continue
            eeprom_info[str(key)] = str(value)

        status = json_response.get('Status',{})
        eeprom_info['State'] = status.get('State', 'Ok')
        eeprom_info['Health'] = status.get('Health', 'Ok')
        eeprom_info['HealthRollup'] = status.get('HealthRollup', 'Ok')

        return (RedfishClient.ERR_CODE_OK, eeprom_info)

    '''
    Validate message arguments for some task status event handlers
    '''
    def __validate_message_args(self, event_msg):
        msg_id = event_msg['MessageId']
        if 'MessageArgs' not in event_msg:
            err_msg = f"Error: Missing 'MessageArgs' field for {msg_id}"
            return (False, err_msg)
        if len(event_msg['MessageArgs']) < 2:
            err_msg = f"Error: 'MessageArgs' field for {msg_id} has less than 2 elements"
            return (False, err_msg)
        return (True, '')

    '''
    Handler of ResourceEvent.1.0.UpdateSuccessful
    '''
    def __update_successful_handler(self, event_msg, context):
        valid, err_msg = self.__validate_message_args(event_msg)
        if not valid:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, err_msg)
        return (RedfishClient.ERR_CODE_OK, '')

    '''
    Handler of ResourceEvent.1.0.ComponentUpdateSkipped
    '''
    def __component_update_skipped_handler(self, event_msg, context):
        valid, err_msg = self.__validate_message_args(event_msg)
        if not valid:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, err_msg)
        context['identical_version'] = True
        return (RedfishClient.ERR_CODE_OK, '')

    '''
    Handler of ResourceEvent.1.0.ResourceErrorsDetected
    '''
    def __resource_errors_detected_handler(self, event_msg, context):
        valid, err_msg = self.__validate_message_args(event_msg)
        if not valid:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, err_msg)

        LOWER_VER_STR = 'lower than the firmware component comparison stamp'
        IDENTICAL_VER_STR = 'Component image is identical'

        args = event_msg['MessageArgs']
        comp_id = args[0]
        err_str = args[1]

        # Identical version detected
        if IDENTICAL_VER_STR in err_str:
            context['identical_version'] = True

            return (RedfishClient.ERR_CODE_OK, '')

        err_msg = f'Error: {err_str}'

        # Version downgrade detected
        if LOWER_VER_STR in err_str:
            context['lower_version'] = True
            err_msg = 'Error: The target image has lower version\n'

        if 'ret_msg' not in context:
            context['ret_msg'] = err_msg
        else:
            if err_msg not in context['ret_msg']:
                context['ret_msg'] = context['ret_msg'] + err_msg + '\n'

        context['err_detected'] = True

        return (RedfishClient.ERR_CODE_OK, '')

    '''
    Handler of ResourceEvent.1.0.TaskAborted
    '''
    def __task_aborted_handler(self, event_msg, context):
        context['aborted'] = True
        return (RedfishClient.ERR_CODE_OK, '')

    '''
    Dispatch task status event to the corresponding handler
    '''
    def __dispatch_event(self, event_msg, context):
        if 'MessageId' not in event_msg:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, f"Error: Missing 'MessageId' field")
        msg_id = event_msg['MessageId']
        event_name = msg_id.split('.')[-1]
        handler = self.__task_status_event_handlers.get(event_name)
        if not handler:
            return (RedfishClient.ERR_CODE_OK, '')
        return handler(event_msg, context)

    '''
    Wait for given task to complete
    '''
    def __wait_task_completion(self, task_id, timeout = 1800, progress_callback = None, sleep_timeout = 2):
        # Construct the command to poll task status by given task id
        uri = f'{RedfishClient.REDFISH_URI_TASKS}/{task_id}'
        cmd = self.__build_get_cmd(uri)
        obfuscation_cmd = self.__obfuscate_auth_token(cmd)

        prev_status = None
        prev_percent = None
        start_tm = time.time()
        timeout_cnt = 0

        while True:
            # 'result' is a dictionary which may vary with messages received.
            # At least it will have the following 3 fields: the return code,
            # the return message and the response from the server.
            result = {
                'ret_code': RedfishClient.ERR_CODE_OK,
                'ret_msg': '',
                'response': ''
            }

            now = datetime.now()
            timestamp = now.strftime("%H:%M:%S.%f")

            ret, http_status_code, response, err_msg = self.exec_curl_cmd(cmd)
            result['response'] = response

            # If timeout occurred, check if we exceeded the overall timeout counter
            # Otherwise continue polling
            if (ret == RedfishClient.ERR_CODE_TIMEOUT and (timeout_cnt < 10)):
                timeout_cnt += 1
                self.__logger.log_notice(f'[Redfish Client] Timeout on checking task {task_id} status, retry count {timeout_cnt}')
                time.sleep(sleep_timeout)
                continue
            timeout_cnt = 0

            if (ret != RedfishClient.ERR_CODE_OK):
                result['ret_code'] = ret
                result['ret_msg'] = f"Error: {err_msg}"
                return result

            # Parse JSON response
            try:
                json_response = json.loads(response)
            except Exception as e:
                result['ret_code'] = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
                result['ret_msg'] = 'Error: Invalid JSON format'
                return result

            # Basic format validation
            attrs = ['PercentComplete', 'TaskStatus', 'Messages']
            for attr in attrs:
                if attr not in json_response:
                    result['ret_code'] = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
                    result['ret_msg'] = f"Error: Missing '{attr}' field in task status response"
                    return result

            # Go through all the messages in the response
            for msg in json_response['Messages']:
                ret, ret_msg = self.__dispatch_event(msg, result)

            status = json_response["TaskStatus"]
            percent = json_response['PercentComplete']

            # Log cURL command and response only if status or percent changed
            if (prev_status != status or prev_percent != percent):
                self.__logger.log_notice(f'[Redfish Client] Execute cURL command at {timestamp}: {obfuscation_cmd}')
                self.__logger.log_notice(f'[Redfish Client] HTTP status code: {http_status_code}')
                self.__logger.log_notice('[Redfish Client] cURL output:')
                self.log_multi_line_str(response)

                prev_status = status
                prev_percent = percent

            # Progress reporting
            if progress_callback and percent:
                progress_data = {
                    # Put here more data if needed
                    'percent': percent
                }
                progress_callback(progress_data)

            # If status is not OK, return immediately
            if (status != 'OK'):
                error_detected = result.get('err_detected', False)
                aborted = result.get('aborted', False)

                result['ret_code'] = RedfishClient.ERR_CODE_GENERIC_ERROR
                if not error_detected:
                    # Usually resource error will come with aborted flag.
                    # But there are cases with no resource error, while
                    # aborted flag is set
                    if aborted:
                        result['ret_msg'] += 'Error: The task has been aborted\n'
                    else:  # No resource error, no abort, but task is not completed
                        result['ret_msg'] = f'Error: Fail to execute the task - '\
                                            f'Taskstatus={status}'
                result['ret_msg'] = result['ret_msg'].strip()
                return result

            if percent is None:
                continue

            # Return if task is completed
            if (percent == 100):
                return result

            # Check if we have timeout
            if (time.time() - start_tm > timeout):
                result['ret_code'] = RedfishClient.ERR_CODE_TIMEOUT
                result['ret_msg'] += 'Error: Wait task completion timeout\n'
                self.__logger.log_notice(f'[Redfish Client] Task {task_id} status polling timeout after {timeout} seconds')
                return result

            time.sleep(sleep_timeout)

    '''
    Change login password

    Parameters:
      new_password    new password to change
    Return value:  (ret, error_msg)
      ret         return code
      error_msg   error message string
    '''
    def redfish_api_change_login_password(self, new_password, user=None):
        self.__logger.log_notice('[Redfish Client] Changing BMC password\n')
        cmd = self.__build_change_password_cmd(new_password, user)
        ret = RedfishClient.ERR_CODE_OK
        response = ''
        error = ''
        ret, _, response, error = self.exec_curl_cmd(cmd)

        if (ret != RedfishClient.ERR_CODE_OK):
            self.__logger.log_error(f'[Redfish Client] Fail to change login password: {error}')
            return (ret, f'Error: {error}')
        else:
            try:
                json_response = json.loads(response)
                if 'error' in json_response:
                    msg = json_response['error']['message']
                    self.__logger.log_error(f'[Redfish Client] Fail to change login password: {msg}')

                    ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                    return (ret, msg)

                if 'Password@Message.ExtendedInfo' in json_response:
                    for info in json_response['Password@Message.ExtendedInfo']:
                        if info['MessageId'].endswith('Error'):
                            msg = info['Message']
                            self.__logger.log_error(f'[Redfish Client] Fail to change login password: {msg}')
                            resolution = info['Resolution']
                            self.__logger.log_error(f'[Redfish Client] Resolution: {resolution}')

                            ret = RedfishClient.ERR_CODE_GENERIC_ERROR

                            return (ret, msg)

                if '@Message.ExtendedInfo' in json_response:
                    for info in json_response['@Message.ExtendedInfo']:
                        if info['MessageId'].endswith('Success'):
                            self.__logger.log_notice('[Redfish Client] Password changed sucessfully')
                            # Logout and re-login if changing password of itself.
                            # Do not care about the result. Logout will
                            # invalidate token. If it doesn't login successully,
                            # Redfish API call later on will do retry anyway.
                            if user is None or user == self.__user:
                                self.logout()
                                self.login()
                            return (RedfishClient.ERR_CODE_OK, '')

                msg = 'Error: Unexpected response format'
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                self.__logger.log_error(f'[Redfish Client] Fail to change login password. {msg}')
                return (ret, msg)
            except json.JSONDecodeError as e:
                ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
                return (ret, 'Error: Invalid JSON format')
            except Exception as e:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                return (ret, 'Error: Unexpected response format')


    '''
    Request BMC to reset itself

    Parameters:
      bmc_reset_type    BMC_RESET_TYPE_GRACEFUL_RESTART or BMC_RESET_TYPE_FORCE_RESTART

    Return value:  (ret, error_msg)
      ret         return code
      error_msg   error message string
    '''
    def redfish_api_request_bmc_reset(self, bmc_reset_type=None):
        if bmc_reset_type is None:
            bmc_reset_type = RedfishClient.BMC_RESET_TYPE_GRACEFUL_RESTART

        cmd = self.__build_request_bmc_reset_cmd(bmc_reset_type)
        ret, _, response, err_msg = self.exec_curl_cmd(cmd)
        json_response = None

        if (ret != RedfishClient.ERR_CODE_OK):
            self.__logger.log_notice(f'[Redfish Client] Reset BMC return not OK, ret {ret}, response {response}, err msg {err_msg}')
            return (ret, err_msg)

        # When action succeds, doesn't return any response.
        # If we got a response, probably it is an error.
        # Try to parse it
        if response is None or len(response) == 0:
            self.__logger.log_notice(f'[Redfish Client] Reset BMC return OK, ret {ret}, err msg {err_msg}')
            return (RedfishClient.ERR_CODE_OK, '')

        reset_type = RedfishClient.BMC_RESET_TYPE_MAP[bmc_reset_type]
        self.__logger.log_notice(f"[Redfish Client] After requesting BMC {reset_type}, got response {response} and error {err_msg}")

        try:
            json_response = json.loads(response)
        except json.JSONDecodeError as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg)
        except Exception as e:
            msg = 'Error: unexpected response'
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, msg)

        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'message' in err:
                err_msg = err['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR

                if 'ActionParameterUnknown' in err.get('code', ''):
                    ret = RedfishClient.ERR_CODE_UNSUPPORTED_PARAMETER
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'message' field"

        return (ret, err_msg)
