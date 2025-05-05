# general imports
from __future__ import annotations

import os.path
import time
from enum import Enum
from datetime import datetime
import re
from typing import List, Optional, Union

# netmiko imports
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException
from netmiko.exceptions import NetmikoTimeoutException
from netmiko.exceptions import NetmikoBaseException
from netmiko.exceptions import ReadException, ReadTimeout, WriteException
import sys
import paramiko
from scp import SCPClient
from collections import OrderedDict

INTERFACE_REGEX = r'\bge\d+-\d+/\d+/\d+\b'

class SSH_Conn:
    # Internal decorators for exception handling - future dev
    class __Decorators(object):
        @staticmethod
        def exec_exception_handler(func):
            # here we can do logic pre func runtime
            def new_func(self, *args, **kwargs):
                # calling func->
                cur_mitigation = 0
                cur_connection = 0
                main_loop = True
                while main_loop is True:
                    try:
                        # we need to check if we come from connect...?
                        # this is not connect operation so we can resolve it by connect
                        if self._isOpen:
                            func(self, *args, **kwargs)
                            main_loop = False
                        else:
                            cur_connection += 1
                            self.connect()
                    except (ReadTimeout, ReadException, WriteException) as error:
                        # we got a timeout on our exec... do we need to mitigate?
                        if self.__mitigate_retry > cur_mitigation:
                            cur_mitigation += 1
                            pass
                        else:
                            main_loop = False
                            # we tried our best just return nothing
                            return None
                    except NetmikoBaseException as error:
                        # we got exception from underlay - Paramiko side, we will retry if asked to
                        if self.__mitigate_retry > cur_mitigation:
                            cur_mitigation += 1
                            pass
                        else:
                            # we tried our best just return nothing
                            main_loop = False
                            raise error
                    except Exception as error:
                        main_loop = False
                        # Unhandled exception occurred we raise it
                        raise error
                # after func

            # return new func for execution
            return new_func

    # region local SSH_CON Enums/classes
    class SSH_ENUMS:
        # Interactive response enum
        class INTERACTIVE_RESPONSE(Enum):
            QUIT = 'q'
            YES = 'yes'
            NO = 'no'
            ABORT = 'abort'
            CONTINUE = 'c'
            EMPTY = ''
            NONE = None

        # public EXEC_MODE enum
        class EXEC_MODE(Enum):
            SHOW = 1
            CFG = 2
            SHELL = 3
            HOST = 3
            NETNS = 3
            GDB = 4

        # public CLI_MODE enum
        class CLI_MODE(str, Enum):
            cli_id: int
            category: str

            def __new__(cls, cli_id: int, category: str):
                obj = str.__new__(cls, cli_id)
                obj._value_ = cli_id

                obj.category = category
                return obj

            NOT_CONNECTED = 'NOT_CONNECTED', 'CLOSED'
            DNOS_SHOW = 'DNOS_SHOW', 'DNOS'
            DNOS_CFG = 'DNOS_CFG', 'DNOS'
            SHELL = 'SHELL', 'SHELL'
            HOST = 'HOST', 'SHELL'
            NETNS = 'NETNS', 'SHELL'
            RESCUE = 'RESCUE', 'DEBUG'
            GDB = 'GDB', 'DEBUG'

    # output object class
    class __private_exec_output:

        def __init__(self, return_obj_type: type = str):
            self._exec_output = {}
            if return_obj_type is str or return_obj_type is list or return_obj_type is dict:
                self._return_obj_type = return_obj_type
            else:
                self.return_obj_type = str
            self._exec_index = 0

        def add_entry(self, cmd: str = None, single_output: str = None):
            # do we have params for entry?
            if cmd is not None and single_output is not None:
                # params not None
                if isinstance(cmd, str) and isinstance(single_output, str):
                    # params are of type string so all good
                    # create_sub a xray_cmd/output tuple
                    my_tuple = [cmd, single_output]
                    self._exec_output[self._exec_index] = my_tuple

                    # increment internal index
                    self._exec_index += 1

        def get_output_object(self):
            output = None

            if self._return_obj_type is str:
                output = self.__get_output_as_string()
                # if output is None make empty output
                if output is None:
                    output = ''
            elif self._return_obj_type is list:
                output = self.__get_output_as_list()
                # if output is None make empty output
                if output is None:
                    output = []
            elif self._return_obj_type is dict:
                output = self.__get_output_as_dict()
                # if output is None make empty output
                if output is None:
                    output = {}

            return output

        def __get_output_as_string(self):
            output_as_string = ''
            # do we have any output for return?
            if len(self._exec_output) > 0:
                # iterate on all entries:
                for i in range(self._exec_index):
                    # we append the value
                    output_as_string += self._exec_output[i][1] + '\n'
                return output_as_string
            else:
                return None

        def __get_output_as_list(self):
            output_as_list = []
            # do we have any output for return?
            if len(self._exec_output) > 0:
                # iterate on all entries:
                for i in range(self._exec_index):
                    # we append the value
                    output_as_list.append(self._exec_output[i][1])
                return output_as_list
            else:
                return None

        def __get_output_as_dict(self):
            output_as_dict = {}
            # do we have any output for return?
            if len(self._exec_output) > 0:
                # iterate on all entries:
                for i in range(self._exec_index):
                    key = self._exec_output[i][0]
                    value = self._exec_output[i][1]
                    # check if key already exists?
                    if key in output_as_dict.keys():
                        # we have a value so add output
                        output_as_dict[key].append(value)
                    else:
                        # we don't have key so create_sub entry
                        value = [value]
                        output_as_dict[key] = value
                return output_as_dict
            else:
                return None

    # Authentication class
    class ssh_auth:
        class ROLE(Enum):
            RW = 1
            RO = 0

        def __init__(self, auth_list: list = None, role: ROLE = ROLE.RW, add_defaults: bool = True):
            self.default_auth = ['dnroot', 'dnroot', 'dnroot', None]
            self.default_tacacs = ['iadmin', 'iadmin', 'iadmin', None]

            self.__local_cfg_file = None
            self.__rw_auth_list = []
            self.__active_rw_auth_list = []
            self.__ro_auth_list = []
            self.__active_ro_auth_list = []
            self.__current_auth_entry = None

            if self.__local_cfg_file is not None:
                # TODO try to load cfg
                pass

            # add default if asked to
            if add_defaults:
                self.add_credentials(self.default_auth, self.ROLE.RW)
                self.add_credentials(self.default_tacacs, self.ROLE.RW)

            if role is not None or isinstance(role, self.ROLE):
                self.add_credentials(auth_object=auth_list, role=role)

            self.reset_credentials()

        def add_credentials(self, auth_object: list = None, role: ROLE = None):

            tmp_usr = None
            tmp_pass = None
            tmp_shell = None
            tmp_host = None

            if role is not None or not isinstance(role, self.ROLE):
                role = self.ROLE.RW

            if isinstance(auth_object, list) or isinstance(auth_object, dict):
                if len(auth_object) >= 2:
                    if isinstance(auth_object, list):
                        tmp_usr = auth_object[0]
                        tmp_pass = auth_object[1]
                        if len(auth_object) == 3:
                            tmp_shell = auth_object[2]
                        elif len(auth_object) == 4:
                            tmp_shell = auth_object[2]
                            tmp_host = auth_object[3]

                    if isinstance(auth_object, dict):
                        tmp_usr = auth_object["username"]
                        tmp_pass = auth_object["password"]
                        tmp_shell = auth_object["shell_password"]
                        tmp_host = auth_object["host_password"]
                else:
                    auth_object = None
            else:
                auth_object = None

            if auth_object is not None:

                # fill back shell password with default user password
                if tmp_shell is None or tmp_shell == '':
                    tmp_shell = tmp_pass

                # rebuild as list properly
                auth_object = [tmp_usr, tmp_pass, tmp_shell, tmp_host]

                is_duplicate = False
                is_update = False

                if role is self.ROLE.RW:
                    # check if authentication exists in stored list
                    for i in self.__rw_auth_list:
                        if i == auth_object:
                            is_duplicate = True
                        # check if update
                        elif i[0] == auth_object[0] and i[1] == auth_object[1]:
                            if i[2] != auth_object[3] or i[3] != auth_object[3]:
                                # update entry
                                i = auth_object
                                is_update = True

                else:
                    for i in self.__ro_auth_list:
                        if i == self.__rw_auth_list:
                            is_duplicate = True
                        # check if update
                        elif i[0] == auth_object[0] and i[1] == auth_object[1]:
                            if i[2] != auth_object[3] or i[3] != auth_object[3]:
                                # update entry
                                i = auth_object
                                is_update = True

                if not is_update and not is_duplicate:
                    if role is self.ROLE.RW:
                        self.__rw_auth_list.append(auth_object)
                        self.__active_rw_auth_list.append(auth_object)
                    else:
                        self.__ro_auth_list.append(auth_object)
                        self.__active_ro_auth_list.append(auth_object)

        def get_current_credentials(self) -> list:
            if self.__current_auth_entry is None:
                self.__current_auth_entry = self.get_next_credentials()

            return self.__current_auth_entry

        def get_next_credentials(self) -> list:
            # update __current_auth_entry and return it
            if len(self.__active_rw_auth_list) > 0:
                self.__current_auth_entry = self.__active_rw_auth_list.pop()
            elif len(self.__active_ro_auth_list) > 0:
                self.__current_auth_entry = self.__active_ro_auth_list.pop()
            else:
                self.__current_auth_entry = []

            return self.__current_auth_entry

        def save_authentication(self, path: str = None):
            done = False
            if path is not None:
                if isinstance(path, str):
                    # TODO save to file
                    done = True
            elif self.__local_cfg_file is not None:
                # TODO replace existing cfg file
                done = True
            return done

        def reset_credentials(self):
            self.__active_rw_auth_list = self.__rw_auth_list.copy()
            self.__active_ro_auth_list = self.__ro_auth_list.copy()
            self.__current_auth_entry = None

    # endregion

    # region SSH_Conn constructor
    def __init__(self, host,
                 authentication: ssh_auth | list = None,
                 change_mode_retry: int = 3,
                 session_log: str = 'filename',
                 localized_exec: bool = True,
                 reconnect: bool = True,
                 reconnect_retry: int = 3,
                 mitigate_retry: int = 3,
                 icmp_test: bool = True,
                 icmp_fast: bool = True,
                 icmp_vars: list | dict = None,
                 cfg_commit_on_exit: bool = False,
                 output_obj_type: type = str):

        if isinstance(authentication, self.ssh_auth):
            # import deep copy and create a copy of the passed object,
            # needed so single auth stack can serve multiple ssh_con instances
            from copy import deepcopy
            self.auth = deepcopy(authentication)
        elif isinstance(authentication, list):
            self.auth = self.ssh_auth(auth_list=authentication, role=self.ssh_auth.ROLE.RW)
        else:
            self.auth = self.ssh_auth()

        if not self.__try_next_auth():
            # we have no auth from object, we will go with ssh_con default
            self.__user = 'dnroot'
            self.__pass = 'dnroot'
            self.__shell_password = 'dnroot'
            self.__host_password = None
        self.__host = host
        self.__session_log = session_log
        self.__change_mode_retry = change_mode_retry
        self.__cfg_commit_on_exit = cfg_commit_on_exit
        self.__localized_exec = localized_exec
        # object type variable, default str
        if output_obj_type is list or output_obj_type is dict:
            self.__return_obj_type = output_obj_type
        else:
            self.__return_obj_type = str

        # init local instance variables TODO-add cfg file loading option
        self._isOpen = False
        self._net_connect: ConnectHandler = None
        self._hostname = None
        self._hw_serial = None
        # cli related vars
        self._cli_lvl = self.SSH_ENUMS.CLI_MODE.NOT_CONNECTED
        self._cli_cur_node = None
        self._cli_cur_node_id = None
        self._cli_cur_container = None
        self._cli_last_container = None
        self._cli_cur_netns = None
        self._cli_cur_docker_netns_lvl = 0
        self._cli_cur_host_netns_lvl = 0
        self._cli_cur_prompt = None
        # default prompt to expect
        self._cli_expect_prompt = r'#'
        # files related vars
        self._file_cfg_loc = None
        self._file_log__loc = None
        # reconnection related vars
        self.__reconnect = reconnect
        self.__reconnect_retry = reconnect_retry
        self.__mitigate_retry = mitigate_retry
        self.__icmp_test = icmp_test
        self.__icmp_fast = icmp_fast

        set_icmp_defaults = True
        if self.__icmp_test is True:
            if icmp_vars is not None:
                if isinstance(icmp_vars, list):
                    if len(icmp_vars) == 3:
                        self.__icmp_retry_count = icmp_vars[0]
                        self.__icmp_timeout = icmp_vars[1]
                        self.__icmp_retry_wait_timer = icmp_vars[2]
                        set_icmp_defaults = False
                elif isinstance(icmp_vars, dict):
                    self.__icmp_retry_count = icmp_vars["retry_count"]
                    self.__icmp_timeout = icmp_vars["timeout"]
                    self.__icmp_retry_wait_timer = icmp_vars["retry_wait_timer"]
                    set_icmp_defaults = False

        if set_icmp_defaults:
            self.__icmp_retry_count = 3
            self.__icmp_timeout = 0
            self.__icmp_retry_wait_timer = 0

    # endregion

    # region SSH_Conn destructor
    def __del__(self):
        try:
            # on destructor validate connection was closed, if not close the connection
            if self._cli_lvl != self.SSH_ENUMS.CLI_MODE.NOT_CONNECTED:
                self.disconnect()
        except Exception as e:
            pass

    # endregion

    # region get/set info func section
    def get_status(self) -> bool:
        if self._isOpen:
            return True
        else:
            return False

    def get_current_prompt(self, pattern: str = None):
        # check we're connected
        if self.__int_sync_con_status():

            __tmp_prompt = None
            non_standart_prompt = False

            # try to repeat upto 3 times to get prompt
            for _iter in range(3):
                prompt_pattern = r"[\$\#]"
                if pattern is not None and isinstance(pattern, str):
                    prompt_pattern = pattern
                try:
                    __tmp_prompt = self._net_connect.find_prompt(pattern=prompt_pattern)
                except:
                    # we have a different prompt here
                    non_standart_prompt = True
                    prompt_pattern = r"[\$\#\)]"
                    __tmp_prompt = self._net_connect.find_prompt(pattern=prompt_pattern)
                    pass

                # stop in case we have a VALID prompt
                if __tmp_prompt is not None and __tmp_prompt != '#':
                    break

            __tmp_prompt = self.__int_strip_ansi(line=__tmp_prompt)
            # need to check if dynamic timestamp is present and remove if it is
            if not non_standart_prompt:
                # testing for datatime regex and remove accordingly (can be cli_lvl 1/2/-1)
                if re.search(r"\(\d\d-[A-Z][a-z]+-\d\d\d\d-\d\d:\d\d:\d\d\)", __tmp_prompt):
                    __tmp_prompt = re.sub(r"\(\d\d-[A-Z][a-z]+-\d\d\d\d-\d\d:\d\d:\d\d\)", "", __tmp_prompt)
                elif re.search(r"\s\d\d-[A-Z][a-z]+-\d\d\d\d-\d\d:\d\d:\d\d", __tmp_prompt):
                    __tmp_prompt = re.sub(r"\s\d\d-[A-Z][a-z]+-\d\d\d\d-\d\d:\d\d:\d\d", "", __tmp_prompt)
                elif re.search(r"\[\d+-\d\d-\d\d\s\d\d:\d\d:\d\d\]", __tmp_prompt):
                    __tmp_prompt = re.sub(r"\[\d+-\d\d-\d\d\s\d\d:\d\d:\d\d\]", "", __tmp_prompt)

            # verify existing prompt matches and sync
            if self._cli_cur_prompt != __tmp_prompt:
                # remediate sync mismatch
                self._cli_cur_prompt = __tmp_prompt

            return self._cli_cur_prompt

    def get_active_ncc_id(self) -> str:
        return self.__int_get_ncc_active_id()

    def get_bfd_master_id(self) -> str:
        return self.__int_get_bfd_master_id()

    def get_current_cli_lvl(self):
        return self._cli_lvl

    def get_hostname(self):
        if self._isOpen:

            if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_SHOW or self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                self._hostname = re.match(r"(.*)#",
                                          self.__int_strip_ansi(self._net_connect.find_prompt())).groups()[0]
                # remove potential date-time logging added (anything in brackets will be removed)
                self._hostname = re.sub(r"\(.*\)", "", self._hostname)
                # remove linux command preamble code
                self._hostname = re.sub(r"\\x1b\[F", "", self._hostname)
            return self._hostname

    def get_current_netns(self):
        if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL or self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
            return self._cli_cur_netns
        else:
            return None

    def set_shell_password(self, new_password: str):
        if new_password is not None:
            self.__shell_password = new_password

    def set_host_password(self, new_password: str):
        if new_password is not None:
            self.__host_password = new_password

    def set_localized_execution(self, value: bool):
        if isinstance(value, bool):
            if self.__localized_exec != value:
                self.__localized_exec = value

    # endregion

    # region cmd_exec func section
    def exec_command(self, cmd, exec_mode: SSH_ENUMS.EXEC_MODE = None, netns: str = None,
                     timeout: int = 10, one_screen_only: bool = False,
                     output_object_type: type = None, location_target: dict = None,
                     interactive: SSH_ENUMS.INTERACTIVE_RESPONSE = None, interactive_pass: str = None):
        # Check if connection is open
        if self._isOpen:
            # can try to execute command there is a connection
            # check if location object is provided?
            if location_target is not None and isinstance(location_target, dict):
                # we have a dict
                tmp_cli_mode = location_target.get('CLI_MODE')
                if not isinstance(tmp_cli_mode, self.SSH_ENUMS.CLI_MODE):
                    tmp_cli_mode = None
                tmp_node = location_target.get('node')
                tmp_node_id = location_target.get('node_id')
                tmp_container = location_target.get('container')
                tmp_netns = location_target.get('netns')
                tmp_shell_pass = location_target.get('shell_password')
                tmp_host_pass = location_target.get('host_password')

                cli_ready = self.change_mode(requested_cli=tmp_cli_mode, node=tmp_node, node_id=tmp_node_id,
                                             container=tmp_container, netns=tmp_netns, shell_password=tmp_shell_pass,
                                             host_password=tmp_host_pass)
                if not cli_ready:
                    # we failed to move return None
                    return None

                # check exec_mode
            if exec_mode is None or not isinstance(exec_mode, self.SSH_ENUMS.EXEC_MODE):
                exec_mode = self.SSH_ENUMS.EXEC_MODE.SHOW
            # was localized execution enabled
            if self.__localized_exec:
                # do we have a supported location
                if self._cli_lvl.category == 'DEBUG' or self._cli_lvl.category == 'CLOSED':
                    # add support for GDB execution
                    if self._cli_lvl != self.SSH_ENUMS.CLI_MODE.GDB:
                        # our current cli lvl has no command execution...
                        return None

                if netns is not None:
                    exec_mode = self.SSH_ENUMS.EXEC_MODE.NETNS
                else:
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
                        exec_mode = self.SSH_ENUMS.EXEC_MODE.SHELL
                    elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
                        exec_mode = self.SSH_ENUMS.EXEC_MODE.HOST
                    elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_SHOW:
                        exec_mode = self.SSH_ENUMS.EXEC_MODE.SHOW
                    elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                        exec_mode = self.SSH_ENUMS.EXEC_MODE.CFG
                    elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.GDB:
                        exec_mode = self.SSH_ENUMS.EXEC_MODE.GDB
                    else:
                        # couldn't match any cli_lvl
                        return None

            _exec_output = ''
            # check if dnos mode command
            if exec_mode is self.SSH_ENUMS.EXEC_MODE.CFG or exec_mode is self.SSH_ENUMS.EXEC_MODE.SHOW:
                # check if show execution is required
                if exec_mode is self.SSH_ENUMS.EXEC_MODE.SHOW:
                    if one_screen_only is False:
                        # show command can be executed at cfg or regular level, so we need to be aware of the prompt
                        # sync prompt dynamically as we are going to use it as expected
                        tmp_exp_cli = re.escape(self.get_current_prompt())
                        # need to check for interactive command mode?
                        # execute the command (we pass interactive object)
                        _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout, exp_prompt=tmp_exp_cli,
                                                                  verify=False, interactive=interactive,
                                                                  interactive_pass=interactive_pass,
                                                                  output_object_type=output_object_type,
                                                                  check_no_more=True)

                    else:
                        tmp_exp_cli = re.escape(self.get_current_prompt())
                        int_response = self.SSH_ENUMS.INTERACTIVE_RESPONSE.QUIT
                        # read and return first screen only until more prompt, expect a more prompt.
                        _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout, exp_prompt=tmp_exp_cli,
                                                                  interactive_pass=interactive_pass,
                                                                  verify=False, interactive=int_response,
                                                                  output_object_type=output_object_type)
                else:
                    # cfg is required, we pass the xray_cmd value to the exec function
                    _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout,
                                                              interactive_pass=interactive_pass,
                                                              interactive=interactive,
                                                              verify=False,
                                                              exp_prompt=self._cli_expect_prompt,
                                                              output_object_type=output_object_type)

                    # in any case we should execute top once all configs are done
                    self.__exec_single_or_bulk(cmd_list='top', timeout=timeout, verify=False,
                                               exp_prompt=self._cli_expect_prompt,
                                               output_object_type=output_object_type)
            else:
                # do we need netns command?
                if netns is not None and exec_mode is self.SSH_ENUMS.EXEC_MODE.NETNS:
                    # check if netns commands are allowed in our mode type
                    if self._cli_lvl.category == "SHELL":
                        # check we are not in the requested netns already
                        if self._cli_cur_netns != netns:
                            # do we have a single xray_cmd or a list
                            if isinstance(cmd, str):
                                cmd = f"ip netns exec {netns} {cmd}"
                            elif isinstance(cmd, List):
                                for i in range(len(cmd)):
                                    cmd[i] = f"ip netns exec {netns} {cmd[i]}"

                        # we are receiving a single response with # no need to get fancy
                        _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout,
                                                                  interactive_pass=interactive_pass,
                                                                  interactive=interactive,
                                                                  exp_prompt=self._cli_expect_prompt,
                                                                  output_object_type=output_object_type)
                    else:
                        # we can't execute netns command in current session location so return None
                        return None
                elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL or self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
                    if exec_mode is self.SSH_ENUMS.EXEC_MODE.SHELL:
                        # execute shell command
                        # we are receiving a single response with # no need to get fancy
                        _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout,
                                                                  interactive_pass=interactive_pass,
                                                                  interactive=interactive,
                                                                  exp_prompt=self._cli_expect_prompt,
                                                                  output_object_type=output_object_type)
                    elif exec_mode is self.SSH_ENUMS.EXEC_MODE.HOST:
                        # execute host command
                        # we are receiving a single response with # no need to get fancy
                        _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout,
                                                                  interactive_pass=interactive_pass,
                                                                  interactive=interactive,
                                                                  exp_prompt=self._cli_expect_prompt,
                                                                  output_object_type=output_object_type)
                elif exec_mode is self.SSH_ENUMS.EXEC_MODE.GDB:
                    tmp_prompt = "(gdb)"
                    # execute commands in GDB prompt
                    _exec_output = self.__exec_single_or_bulk(cmd_list=cmd, timeout=timeout,
                                                              interactive_pass=interactive_pass,
                                                              interactive=interactive,
                                                              exp_prompt=tmp_prompt,
                                                              output_object_type=output_object_type)
                else:
                    # we can't execute shell/host type command in current cli position so return None
                    return None

            return _exec_output

    def commit_cfg(self, commit_name: str = "auto_datetime", timeout: int = 30, commit_check: bool = True):
        # If commit name is default, generate name with datetime
        if commit_name == "auto_datetime":
            commit_name = "auto_" + datetime.now().strftime("%m/%d/%YT%H_%M_%S")

        # Check if connection is open
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
            # can try to commit the cfg

            commit_done = True
            tmp_prompt = self._hostname + "\(cfg\)" + self._cli_expect_prompt
            # we should run commit check, we wait for 30sec for potential large commit
            if commit_check is True:
                __output = self._net_connect.send_command("commit check",
                                                          expect_string=tmp_prompt,
                                                          cmd_verify=False,
                                                          read_timeout=timeout)
            else:
                __output = 'ok'
            # is commit needed?
            if not re.search("NOTICE: commit action is not applicable", __output):
                # we have commit, check if no error was seen in the validation
                if not re.search("ERROR:", __output):
                    # we have no error commit can be made
                    # try to commit, it should not fail -> try/except just in case of commit timeout
                    tmp_prompt = 'Commit succeeded'
                    try:
                        __output = self._net_connect.send_command("commit log " + commit_name,
                                                                  cmd_verify=False,
                                                                  read_timeout=timeout)
                    except:
                        commit_done = False
                else:
                    # we can't commit so return False as commit not performed
                    commit_done = False


            # we are done, return output
            return commit_done

    # region private exec funcs
    def __exec_single_or_bulk(self, cmd_list, timeout, exp_prompt, verify: bool = True,
                              interactive: SSH_ENUMS.INTERACTIVE_RESPONSE = None, output_object_type: type = None,
                              check_no_more: bool = False, interactive_pass=None):
        # create_sub an output object, overwrite if requested for single execution
        if output_object_type is not None:
            _exec_output = self.__private_exec_output(return_obj_type=output_object_type)
        else:
            _exec_output = self.__private_exec_output(return_obj_type=self.__return_obj_type)

        # handle interactive inputs
        if interactive_pass and isinstance(interactive_pass, str):
            # we have an inter password, so we need interactive mode check if we have some interactive response
            if interactive is not None and not isinstance(interactive, self.SSH_ENUMS.INTERACTIVE_RESPONSE):
                interactive = self.SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY

        elif interactive is not None and not isinstance(interactive, self.SSH_ENUMS.INTERACTIVE_RESPONSE):
            interactive = self.SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY

        # do we have multiple commands to execute?
        if isinstance(cmd_list, list):
            # list of commands is provided
            for i in cmd_list:
                # do we have anything interactive to do?
                if interactive is not None:  # we need something interactive
                    _single_output = self.__exec_inter_single_cmd(cmd=i, timeout=timeout, exp_prompt=exp_prompt,
                                                                  verify=verify, interact_response=interactive,
                                                                  interact_pass=interactive_pass,
                                                                  output_obj=_exec_output)
                else:
                    # get output for single xray_cmd in not interactive way
                    # check if no more is needed?
                    if check_no_more:
                        # check and add no-more to the end of xray_cmd
                        if re.search(r"\|\sno-more", i) is None:
                            i = f"{i} | no-more"

                    _single_output = self.__exec_single_cmd(cmd=i, timeout=timeout, exp_prompt=exp_prompt,
                                                            verify=verify,
                                                            output_obj=_exec_output)

        elif isinstance(cmd_list, str):
            # single string command for execution
            if interactive is not None:
                _single_output = self.__exec_inter_single_cmd(cmd=cmd_list, timeout=timeout, exp_prompt=exp_prompt,
                                                              verify=verify, interact_response=interactive,
                                                              interact_pass=interactive_pass,
                                                              output_obj=_exec_output)
            else:
                # execute single command
                # check if no more needed?
                if check_no_more:
                    if re.search(r"\|\sno-more", cmd_list) is None:
                        cmd_list = f"{cmd_list} | no-more"

                _single_output = self.__exec_single_cmd(cmd=cmd_list, timeout=timeout, exp_prompt=exp_prompt,
                                                        verify=verify, output_obj=_exec_output)

        # get the return object
        _output_obj = _exec_output.get_output_object()
        # we don't validate if anything was done, because we don't care...
        return _output_obj

    def __exec_inter_single_cmd(self, cmd, timeout, exp_prompt, verify: bool = True,
                                interact_response: SSH_ENUMS.INTERACTIVE_RESPONSE = SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY,
                                interact_pass: str = None,
                                output_obj: __private_exec_output = None):
        if output_obj is None:
            output_obj = self.__private_exec_output(return_obj_type=self.__return_obj_type)

        # do we have a xray_cmd to run?
        if cmd is None or not isinstance(cmd, str):
            return ''

        # do we have exp_prompt?
        if exp_prompt is None or not isinstance(cmd, str):
            return ''

        # check we have an answer for interactive execution
        if interact_response is None or not isinstance(interact_response, self.SSH_ENUMS.INTERACTIVE_RESPONSE):
            interact_response = self.SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY

        # define interactive prompts
        re_int_prompt_list = [r"\(?.*\[.*?\]\)?\?",
                              r"-- More -- \(Press q to quit\)",
                              r"(?:P|p)assword",
                              r"--Type \<RET\> for more, q to quit, c to continue without paging--",
                              r"\(y or n\)",
                              r"\(y/N\)"]
        # build the interactive exp_prompt
        int_prompt = ''
        for i in re_int_prompt_list:
            int_prompt += f"(?:{i})|"

        # add predefined expected prompt
        # check if predifined has brackets:
        if re.search(r"\(|\)", exp_prompt):
            tmp_prompt = re.escape(exp_prompt)
            int_prompt += f"(?:{tmp_prompt})|"
        else:
            int_prompt += f"(?:{exp_prompt})|"
        # add generic dnos/unix prompts
        int_prompt += r"(?:.*?\@.*?\:.*?\$)"

        # Check for verify?
        if verify:
            # single string command for execution
            _exec_output = self._net_connect.send_command(cmd, expect_string=int_prompt,
                                                          read_timeout=timeout)
        else:
            # single string command for execution
            _exec_output = self._net_connect.send_command(cmd, expect_string=int_prompt,
                                                          read_timeout=timeout,
                                                          cmd_verify=False)

        # save output up to this point
        _tmp_output = _exec_output
        # start count for repeated interactive prompts, we might have a few in a row, we will try 3 times
        repeat = True
        completed = False
        repeat_count = 3

        while repeat:
            # check counter
            if repeat_count <= 0:
                repeat = False
            else:
                repeat_count -= 1

                # check if interactive response was prompted??
                if _exec_output is not None:
                    # get last line and the matched interactive prompt pattern:
                    matched_pattern = None
                    matched_value = None
                    # do we have lines?
                    if _exec_output.rfind('\n') != -1:
                        last_line: str = _exec_output.splitlines()[-1]
                        for i in re_int_prompt_list:
                            if re.search(i, last_line):
                                matched_pattern = i
                                matched_value = re.search(rf"({matched_pattern})", last_line).groups()[0]
                    else:
                        # we only have a single line of output
                        last_line = _exec_output
                        for i in re_int_prompt_list:
                            if re.search(i, last_line):
                                matched_pattern = i
                                matched_value = re.search(rf"({matched_pattern})", last_line).groups()[0]

                    # set default before changes
                    int_response = interact_response.value

                    if matched_pattern is not None:
                        # we should check our interactive response is matching the prompt we got
                        if matched_pattern == re_int_prompt_list[0]:
                            # generic response, we try to match the pattern for the value
                            if not re.search(rf"{interact_response.value}", matched_value, re.IGNORECASE):
                                # we don't have this required option, send enter for CLI default
                                int_response = self.SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY.value
                        elif matched_pattern == re_int_prompt_list[1]:
                            # we are prompted for more, a quit is expected
                            if interact_response is not self.SSH_ENUMS.INTERACTIVE_RESPONSE.QUIT:
                                # we should support quit only here...
                                int_response = self.SSH_ENUMS.INTERACTIVE_RESPONSE.QUIT.value
                        elif matched_pattern == re_int_prompt_list[2]:
                            # we were prompted for password by previous command
                            if interact_pass and isinstance(interact_pass, str):
                                # we are provided a password to respond
                                int_response = interact_pass
                            else:
                                # we were not provided a valid str password, go for empty enter
                                int_response = self.SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY.value
                        elif matched_pattern == re_int_prompt_list[3]:
                            # we were prompted for q/c/enter
                            if interact_response is not self.SSH_ENUMS.INTERACTIVE_RESPONSE.QUIT:
                                if interact_response is not self.SSH_ENUMS.INTERACTIVE_RESPONSE.CONTINUE:
                                    if interact_response is not self.SSH_ENUMS.INTERACTIVE_RESPONSE.EMPTY:
                                        # we are not provided correct option, set continue as default
                                        int_response = self.SSH_ENUMS.INTERACTIVE_RESPONSE.CONTINUE.value
                        elif matched_pattern == re_int_prompt_list[4]:
                            # we were prompted for default (y or n)
                            if interact_response is self.SSH_ENUMS.INTERACTIVE_RESPONSE.YES:
                                # correct yes -> y
                                int_response = 'y'
                            else:
                                # default value for option is no
                                int_response = 'n'
                        elif matched_pattern == re_int_prompt_list[5]:
                            # we were prompted for default (y or n)
                            if interact_response is self.SSH_ENUMS.INTERACTIVE_RESPONSE.YES:
                                # correct yes -> y
                                int_response = 'y'
                            else:
                                # default value for option is no
                                int_response = 'N'

                        # we should respond with interactive answer
                        _exec_output = self._net_connect.send_command(str(int_response),
                                                                      expect_string=int_prompt, read_timeout=timeout,
                                                                      cmd_verify=False)
                    else:
                        # no interactive prompt found
                        repeat = False
                        completed = True

                    _tmp_output = _exec_output

                    # crop all the not needed trailing bs
                    if matched_pattern is not None:
                        re_pattern = r"(.*?)" + matched_pattern
                        # match with dot all flag as we seek to find anything before the first iteration of pattern
                        match = re.search(re_pattern, _tmp_output, re.DOTALL)
                        if match is not None and len(match.groups()) > 0:
                            # we have a match and at least 1 group, we need the first
                            _tmp_output = match.groups()[0]
                    else:
                        # crop only the last line from output if multiple lines are detected
                        if _tmp_output.rfind('\n') != -1:
                            _tmp_output = _tmp_output[:_tmp_output.rfind('\n')] + '\n'
                        # remove ansi bs from response to user
                        _tmp_output = self.__int_strip_ansi(_tmp_output)

                    # we did our best... pass output
                    output_obj.add_entry(cmd=cmd, single_output=_tmp_output)

        # check if we passed counter or we are done
        if not completed and not repeat:
            # we are stuck in interactive prompt loop -> send CTRL+C
            self._net_connect.write_channel(chr(3))
            _exec_output = self._net_connect.send_command('',
                                                          expect_string=int_prompt, read_timeout=timeout,
                                                          cmd_verify=False)

    def __exec_single_cmd(self, cmd: str, timeout, exp_prompt: str, verify: bool = True,
                          output_obj: __private_exec_output = None):
        if output_obj is None:
            output_obj = self.__private_exec_output(return_obj_type=self.__return_obj_type)

        # do we have a xray_cmd to run?
        if cmd is None or not isinstance(cmd, str):
            return ''

        # do we have exp_prompt?
        if exp_prompt is None or not isinstance(cmd, str):
            return ''

        # Check for verify?
        if verify:
            # single string command for execution
            _exec_output = self._net_connect.send_command(cmd, expect_string=exp_prompt,
                                                          read_timeout=timeout)
        else:
            # single string command for execution
            _exec_output = self._net_connect.send_command(cmd, expect_string=exp_prompt,
                                                          read_timeout=timeout,
                                                          cmd_verify=False)
        if _exec_output is not None:
            # remove ansi bs from response to user
            _exec_output = self.__int_strip_ansi(_exec_output)

            # crop prompt from last line from output if multiple lines are detected
            if _exec_output.rfind('\n') != -1:
                last_line = _exec_output.splitlines()[-1]

                # check if we are in shell/host
                if not self._cli_lvl.category == 'SHELL':
                    # we are in DNOS type, we can just remove last line
                    last_line = '\n'
                else:
                    # we are in SHELL type we need to check for prompt
                    tmp_prompt = self.get_current_prompt()
                    re_pattern = r"(^.*)@"
                    match = re.search(re_pattern, tmp_prompt)
                    if match is not None and len(match.groups()) == 1:
                        tmp_prompt = match.groups()[0]
                    else:
                        tmp_prompt = None

                    if tmp_prompt is not None:
                        re_pattern = rf"(^.*){re.escape(tmp_prompt)}"
                        match = re.search(re_pattern, last_line)
                        if match is not None and len(match.groups()) == 1:
                            if len(match.groups()[0]) > 0:
                                last_line = '\n' + match.groups()[0] + '\n'
                            else:
                                last_line = '\n'
                        else:
                            last_line = '\n'

                # reassemble output with cropped last line
                _exec_output = _exec_output[:_exec_output.rfind('\n')] + last_line
            else:
                # we have a single line string
                prompt_pattern = rf"(^.*){re.escape(self.get_current_prompt())}"

                match = re.search(prompt_pattern, _exec_output)
                if match is not None and len(match.groups()) == 1:
                    output = match.groups()[0]
                else:
                    output = _exec_output

        # we did our best... pass output
        output_obj.add_entry(cmd=cmd, single_output=_exec_output)

    # endregion
    # endregion

    # region session func section
    # establishing connection with internal exception handling for Auth/Timeout
    def connect(self, task_id: int = 0):
        try:
            # Check if init is needed
            if self._net_connect is None:

                # do we need to icmp to check network reachability?
                if self.__icmp_test:
                    # check if the node is unreachable
                    if not self.__icmp_ping(host=self.__host, count=1,
                                            retry_wait_timer=self.__icmp_retry_wait_timer,
                                            retry_count=self.__icmp_retry_count, timeout=self.__icmp_timeout,
                                            fast_ping=self.__icmp_fast):
                        # we could not reach the device raise exception
                        raise Exception(f"ERROR: Node {self.__host} is network unreachable!")

                # try initiate a connection

                if self.__session_log == 'filename':
                    # no session log requested
                    self._net_connect = ConnectHandler(
                        device_type="linux",
                        host=self.__host,
                        username=self.__user,
                        password=self.__pass,
                        banner_timeout=120,
                        conn_timeout=120,
                        auth_timeout=120,
                        blocking_timeout=120,
                        read_timeout_override=60,
                        global_delay_factor=0.10,
                        fast_cli=True,
                        auto_connect=True
                    )
                else:
                    # session log requested
                    self._net_connect = ConnectHandler(
                        device_type="linux",
                        host=self.__host,
                        username=self.__user,
                        password=self.__pass,
                        session_log=self.__session_log,
                        banner_timeout=120,
                        conn_timeout=120,
                        auth_timeout=120,
                        blocking_timeout=120,
                        read_timeout_override=60,
                        global_delay_factor=0.10,
                        fast_cli=True,
                        auto_connect=True
                    )
                    # we've set high read_timeout_overwrite on connection to support the loading screen -> disable
                    self._net_connect.read_timeout_override = None
                # Update isOpen state
                self._isOpen = True

                # Update cli_lvl to read_mode
                self._cli_lvl = self.SSH_ENUMS.CLI_MODE.DNOS_SHOW

                self.get_hostname()

        except NetmikoAuthenticationException as error:
            # we got bad authentication, swap to next available
            # debug
            if self.__try_next_auth():
                self.connect()
            else:
                # no More auth to try
                raise Exception("ERROR: All SSH authentication options exhausted!")

        except NetmikoTimeoutException:
            if self.__reconnect:
                # increase task_id to track reconnecting and avoid a loop
                task_id += 1
                if self.__reconnect_retry > task_id:
                    self.connect(task_id=task_id)
                else:
                    raise Exception(f"ERROR: Timeout in connection to Node - {self.__host}, tried {str(task_id)} times")
            else:
                raise Exception(f"ERROR: Timeout in connection to Node - {self.__host}")

    def disconnect(self):
        if self._isOpen:
            try:
                # self._net_connect.disconnect()
                # close network socket
                self._net_connect.sock.close()
                self._isOpen = False
            except:
                self._isOpen = False
                pass

    def refresh(self):
        is_alive = self._net_connect.is_alive()
        # sync and update state with netmiko
        if self._isOpen and not is_alive:
            self._isOpen = False
        else:
            self._isOpen = True

        if self._isOpen and is_alive:
            # send empty command over netmiko
            self._net_connect.send_command(" ", expect_string=self._cli_expect_prompt, cmd_verify=False)

    # endregion

    # region change modes func section
    # global single function:
    def change_mode(self, requested_cli: SSH_ENUMS.CLI_MODE = None, node: str = 'ncc',
                    node_id: str = 'active', container: str = '', netns: str = '',
                    shell_password: str = None, host_password: str = None):

        # print(f"CH_MODE: IAM -> requested_cli={self._cli_lvl}, node={self._cli_cur_node}, node_id={self._cli_cur_node_id}, container={self._cli_cur_container},netns={self._cli_cur_netns}")
        # print(f"CH_MODE: GOT -> requested_cli={requested_cli}, node={node}, node_id={node_id}, container={container},netns={netns}")


        # lower all input vars
        node = self.__int_var_lower(node)
        node_id = self.__int_var_lower(node_id)
        container = self.__int_var_lower(container)
        netns = self.__int_var_lower(netns)

        # exit gdb first if we are in GDB
        # check if node move is required?
        if node is not None and node_id is not None:
            # are we in shell? if so we need to check on what node? if not we don't care
            if self._cli_lvl.category == 'SHELL' or self._cli_lvl is self.SSH_ENUMS.CLI_MODE.GDB:
                # node and node_id were provided, are we in different node?
                if self._cli_cur_node != node or self._cli_cur_node_id != node_id:
                    # exit if we are in GDB because we need to move
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.GDB:
                        if not self.__exit_gdb_mode():
                            return False
                    # handle cases for requested cli
                    if requested_cli is None:
                        # we are in a different node shell/host level, need to get out first
                        if not self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
                            # failed to exit to show
                            return False

                        # we didn't receive requested CLI we need to derive dynamically
                        if netns is not None and netns != '':
                            # netns is provided
                            requested_cli = self.SSH_ENUMS.CLI_MODE.NETNS
                        else:
                            if container is not None and container != '':
                                # container provided we are need shell mode
                                requested_cli = self.SSH_ENUMS.CLI_MODE.SHELL
                            else:
                                requested_cli = self.SSH_ENUMS.CLI_MODE.HOST
                    else:
                        if requested_cli.category != 'DNOS':
                            # we are in a different node, need to get out first
                            if not self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
                                # failed to exit to show
                                return False

                            # we will proceed from show mode here with function logic

        # If only netns was asked for we should support it first
        if requested_cli is None or requested_cli is self.SSH_ENUMS.CLI_MODE.NETNS:
            # record cli movement
            cli_ready = True

            # derive target location
            if node is not None and node_id is not None:
                if container is None or container == '':
                    # container not provided, host is requested, move to shell
                    if self._cli_lvl != self.SSH_ENUMS.CLI_MODE.HOST:
                        cli_ready = self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.HOST,
                                                     node=node, node_id=node_id, container=container, netns='',
                                                     shell_password=shell_password, host_password=host_password)

                elif container != self._cli_cur_container:
                    cli_ready = self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.SHELL,
                                                 node=node, node_id=node_id, container=container, netns='',
                                                 shell_password=shell_password, host_password=host_password)
            else:
                if self._cli_lvl.category == "DNOS":
                    if self._cli_lvl == self.SSH_ENUMS.CLI_MODE.DNOS_SHOW:
                        # request show -> config
                        cli_ready = self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_CFG,
                                                     node=node, node_id=node_id, container=container, netns='',
                                                     shell_password=shell_password, host_password=host_password)
                    elif self._cli_lvl == self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                        # request config -> show
                        cli_ready = self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW,
                                                     node=node, node_id=node_id, container=container, netns='',
                                                     shell_password=shell_password, host_password=host_password)

            if netns != '' and netns is not None:
                # we need netns, can execute here?
                if cli_ready and self._cli_lvl.category == "SHELL":
                    # we are at the correct location and can run netns
                    # open netns, validation done in function
                    return self.__enter_netns_bash(netns=netns)
                else:
                    return False
            else:
                # we don't need netns -> return if we are ready
                return cli_ready

        # do we have a valid target?
        if requested_cli.category == 'DEBUG' or requested_cli.category == 'CLOSED':
            return False

        # can we move right now?
        # if we are in gdb we need to exit to perform a move
        if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.GDB and requested_cli is not self.SSH_ENUMS.CLI_MODE.GDB:
            if not self.__exit_gdb_mode():
                # we have failed to exit gdb, move can't be done
                return False

        # we allow GDB as it will be covered by the functions in the future
        if self._cli_lvl.category == 'CLOSED':
            return False

        # do we need to move check requested ENUM
        if self._cli_lvl is requested_cli:
            # check for shell category, we need to check for potential node/container move
            if self._cli_lvl.category == 'SHELL':
                # check node/node_id as movement happens after this if logic
                if self._cli_cur_node == node and self._cli_cur_node_id == node_id:
                    # we are on the correct node! check if shell container node?
                    # if we are in shell mode check for container?
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
                        if self._cli_cur_container == container:
                            if self._cli_cur_netns and netns:
                                if self._cli_cur_netns == netns:
                                    return True
                            else:
                                # we don't need to move
                                return True
                    else:
                        # we are in host, check for netns only
                        if self._cli_cur_netns and netns:
                            if self._cli_cur_netns == netns:
                                return True
            else:
                # we are in DNOS and requested cli is current cli so no move is needed
                return True
        else:
            # we need to move, do we move category?
            if self._cli_lvl.category == requested_cli.category:
                # we don't need to move category, check what category
                if self._cli_lvl.category == 'DNOS':
                    # DNOS lvl movement
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_SHOW:
                        # we move dnos->dnos_cfg
                        return self.__enter_cfg_mode()
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                        # we move dnos_cfg -> dnos
                        return self.__exit_cfg_mode()
                elif self._cli_lvl.category == 'SHELL':
                    # SHELL lvl movement
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
                        # check container movement first
                        if self._cli_lvl == requested_cli and self._cli_cur_container != container:
                            # we need to move containers, exit to show first
                            if self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
                                # we moved to show, we may run again to enter container now
                                return self.change_mode(requested_cli=requested_cli, node=node, node_id=node_id,
                                                        container=container, netns=netns,
                                                        shell_password=shell_password, host_password=host_password)
                            else:
                                # we failed to move to show
                                return False
                        else:
                            # we go shell -> host, no container movement
                            if host_password is not None:
                                cli_ready = self.__enter_host_mode(shell_password=host_password)
                            else:
                                cli_ready = self.__enter_host_mode()

                            # check if we moved?
                            if cli_ready is False:
                                # we failed to go into host, exit to show and repeat
                                if self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
                                    return self.change_mode(requested_cli=requested_cli, node=node, node_id=node_id,
                                                            container=container, netns=netns,
                                                            shell_password=shell_password,
                                                            host_password=host_password)
                                else:
                                    # We failed to move to show
                                    return False

                    elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
                        # we go host -> shell
                        # we need to check if container was requested?
                        if container == self._cli_last_container:
                            # we can just exit host back into RE container
                            return self.__exit_host_mode()
                        else:
                            # a container is requested we need to exit and re-enter
                            if self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW, node=node,
                                                node_id=node_id,
                                                container=container, netns=netns, shell_password=shell_password,
                                                host_password=host_password):

                                # we now are in dnos and can enter docker
                                return self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.SHELL,
                                                        node=node, node_id=node_id,
                                                        container=container, netns=netns, shell_password=shell_password,
                                                        host_password=host_password)
                            else:
                                # we failed to move to dnos
                                return False
            else:
                # we are requested to go between categories:
                if self._cli_lvl.category == 'DNOS':
                    # if we are in cfg we should exit to show first
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                        # ask to exit CFG mode
                        response = self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW,
                                                    node=node, node_id=node_id,
                                                    container=container, netns=netns, shell_password=shell_password,
                                                    host_password=host_password)
                        if not response:
                            # we don't continue if there was an issue
                            return response
                    # do we need shell?
                    if requested_cli is self.SSH_ENUMS.CLI_MODE.SHELL:
                        # we go dnos -> shell, are we using container alias? we should transform it into numeric id
                        if node_id == 'bfd-master':
                            node_id = self.get_bfd_master_id()
                        elif node_id == 'active':
                            node_id = self.get_active_ncc_id()

                        # check password
                        if shell_password is not None:
                            return self.__enter_docker_mode(docker_pass=shell_password, node=node, node_id=node_id,
                                                            container=container)
                        else:
                            # password not requested by user, do we have a global?
                            if self.__shell_password is not None:
                                return self.__enter_docker_mode(docker_pass=self.__shell_password, node=node,
                                                                node_id=node_id, container=container)
                            else:
                                # we have no password requirements
                                return self.__enter_docker_mode(node=node, node_id=node_id, container=container)
                    elif requested_cli is self.SSH_ENUMS.CLI_MODE.HOST:
                        # we go dnos -> shell -> host, rerun to enter shell first
                        response = self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.SHELL,
                                                    node=node, node_id=node_id, container=container, netns=netns,
                                                    shell_password=shell_password,
                                                    host_password=host_password)
                        if response:
                            # we have a good response we are in shell, can go into host mode now
                            if host_password is not None:
                                return self.__enter_host_mode(shell_password=host_password)
                            else:
                                return self.__enter_host_mode()
                else:
                    # are we in host cause if so we need to exit
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
                        if not self.__exit_host_mode():
                            # failed exit from host
                            return False

                    # we can proceed to exit shell
                    if not self.__exit_docker_mode():
                        return False

                    # we are in show, check if we need to go config?
                    if requested_cli is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                        # enter cfg mode
                        return self.__enter_cfg_mode()
                    else:
                        return True

    def open_core_gdb(self, node: str = 'ncc', node_id: str = 'active', container: str = 'routing-engine',
                      shell_password: str = None, bin_file: str = None, core_file: str = None) -> Optional[str]:
        if node is None or node_id is None or container is None:
            node = 'ncc'
            node_id = 'active'
            container = 'routing-engine'

        tmp_cli_location = self._cli_lvl
        tmp_node = self._cli_cur_node
        tmp_node_id = self._cli_cur_node_id
        tmp_container = self._cli_cur_container
        tmp_netns = self._cli_cur_netns

        gdb_is_open = None
        response = None

        # move to shell
        if self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.SHELL, node=node,
                            node_id=node_id, container=container, shell_password=shell_password):

            # we have moved to shell, and can execute gdb
            response = self.__enter_gdb_mode(bin_location=bin_file, core_file=core_file)
            if response is not None:
                # we are in GDB
                gdb_is_open = True
            else:
                # we could not open gdb
                gdb_is_open = False

        if gdb_is_open is None or gdb_is_open is False:
            # return to starting location
            self.change_mode(requested_cli=tmp_cli_location, node=tmp_node, node_id=tmp_node_id,
                             container=tmp_container, netns=tmp_netns)
            return None
        else:
            return response

    # region Mode change internal functions
    def __enter_cfg_mode(self):
        # Check if connection is open
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_SHOW:
            # can try to enter cfg mode
            # enter config mode
            output = self._net_connect.send_command("configure",
                                                    cmd_verify=False,
                                                    expect_string=self._cli_expect_prompt)
            # change cfg mode value
            self._cli_lvl = self.SSH_ENUMS.CLI_MODE.DNOS_CFG

            if output is not None:
                return True
            else:
                return False

    def __exit_cfg_mode(self):
        # Check if connection is open
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
            # can try to exit cfg mode
            # check if any change is pending, we wait for 30sec for potential large commit
            output = self._net_connect.send_command("show config compare", cmd_verify=False,
                                                    expect_string=(self._hostname + ' config-end'),
                                                    read_timeout=30)
            # check if no commit is pending
            reg_to_use = r"^Added:|^Deleted:"

            # NOTE:: DO-NOT-REPLACE re.search for re.match it won't work.
            if re.search(reg_to_use, output, re.MULTILINE):
                # we have cfg pending... do we enable commit on exit in global?
                if self.__cfg_commit_on_exit:
                    # we enable commit on exit, try to commit the config
                    commit_response = self.commit_cfg()
                    if commit_response:
                        # we had a good commit
                        return True

                # no global commit_on_exit or failed to commit, exit and drop not committed cfg
                self._net_connect.send_command("end", expect_string=r'\[cancel\]?', cmd_verify=False)
                # change expected base prompt
                output = self._net_connect.send_command("no", cmd_verify=False,
                                                        expect_string=(self._hostname + self._cli_expect_prompt))
            else:
                # we don't have cfg changes pending, we can just exit
                output = self._net_connect.send_command("end", cmd_verify=False,
                                                        expect_string=(self._hostname + self._cli_expect_prompt))
            if output is not None:
                # change cli_lvl to read_mode
                self._cli_lvl = self.SSH_ENUMS.CLI_MODE.DNOS_SHOW
                return True
            else:
                return False

        else:
            return False

    def __enter_docker_mode(self,
                            docker_pass: str = None,
                            node: str = "ncc", node_id: str = "active",
                            container: str = "",
                            iteration: int = None):
        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry

        # Check if connection is open
        if self._isOpen and (self._cli_lvl is self.SSH_ENUMS.CLI_MODE.DNOS_SHOW or self._cli_lvl is
                             self.SSH_ENUMS.CLI_MODE.DNOS_CFG):
            # can try to enter docker mode

            # build start shell command
            shell_cmd = f"run start shell {node} {node_id}"

            if container is not None and container != '':
                shell_cmd = f"run start shell {node} {node_id} container {container}"

            # was password derived from global
            if docker_pass is None and self.__shell_password is not None:
                docker_pass = self.__shell_password

            self.__exec_inter_single_cmd(shell_cmd, timeout=10, verify=False, interact_pass=docker_pass,
                                         exp_prompt=self._cli_expect_prompt)

            # # check if password is required
            # if docker_pass is not None:
            #     # we should handle a condition where password is provided but not prompted
            #     _expect_str = rf"(?:(?:P|p)assword:|)|(?:{self._cli_expect_prompt})"
            #     # execute run docker shell
            #     self.__exec_inter_single_cmd(shell_cmd, verify=False,interact_pass=docker_pass, exp_prompt=self._cli_expect_prompt)
            #     _tmp_output = self._net_connect.send_command(shell_cmd, cmd_verify=False, expect_string=_expect_str)
            #     if _tmp_output and isinstance(_tmp_output, str):
            #         _last_line = _tmp_output.splitlines()[-1]
            #         # we need to verify last line includes password prompt
            #         if re.search(r"(?:P|p)assword:", _last_line):
            #             # we were prompted for password try to put it
            #     self._net_connect.send_command(docker_pass, cmd_verify=False, expect_string=self._cli_expect_prompt)
            # else:
            #     self._net_connect.send_command(shell_cmd, cmd_verify=False, expect_string=self._cli_expect_prompt)

            # try to resync once executed to see session is open and in correct place
            if self.__int_var_sync(exp_cli_lvl=self.SSH_ENUMS.CLI_MODE.SHELL):
                self._cli_cur_node = node
                self._cli_cur_node_id = node_id
                return True
            else:
                # We failed but we might need to retry
                if iteration > 0:
                    iteration -= 1
                    if self.__enter_docker_mode(docker_pass=docker_pass, node=node, node_id=node_id,
                                                container=container, iteration=iteration):
                        self._cli_cur_node = node
                        self._cli_cur_node_id = node_id
                        return True
                    else:
                        # retry failed
                        return False
                # change failed
                return False

        else:
            return False

    def __exit_docker_mode(self, iteration: int = None):
        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry

        # Check if connection is open
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
            # can try to exit docker mode

            # close any open bash instances
            self.__exit_netns_bash()
            # no netns bash open, try exiting docker mode
            # build exit host command list TODO load from cfg definition
            self._net_connect.send_command("exit",
                                           expect_string=self._cli_expect_prompt,
                                           cmd_verify=False)

            # try to resync once executed to see session is open and in correct place
            if self.__int_var_sync(exp_cli_lvl=[self.SSH_ENUMS.CLI_MODE.DNOS_SHOW, self.SSH_ENUMS.CLI_MODE.DNOS_CFG]):
                # We exited docker_docker mode
                self._cli_cur_node = None
                self._cli_cur_node_id = None
                return True
            else:
                # We failed but we might need to retry
                if iteration > 0:
                    iteration -= 1
                    if self.__exit_docker_mode(iteration=iteration):
                        # We exited docker_docker mode
                        self._cli_cur_node = None
                        self._cli_cur_node_id = None
                        return True
                    else:
                        # retry failed
                        return False
                # change failed
                return False

        else:
            return False

    def __enter_netns_bash(self, netns: str, iteration: int = None):
        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry

        # Check if connection is open
        if self._isOpen and (
                self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL or self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST):
            # can try to enter docker mode

            # build shell command TODO load from cfg definition
            self._net_connect.send_command(f"ip netns exec {netns} bash",
                                           expect_string=self._cli_expect_prompt,
                                           cmd_verify=False)

            # try to resync once executed to see session is open and in correct place
            if self.__int_var_sync():
                if self._cli_cur_netns == netns:
                    if self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
                        self._cli_cur_docker_netns_lvl += 1
                    elif self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
                        self._cli_cur_host_netns_lvl += 1
                return True
            else:
                # We failed but we might need to retry
                if iteration > 0:
                    iteration -= 1
                    if self.__enter_netns_bash(netns=netns, iteration=iteration):
                        return True
                    else:
                        # retry failed
                        return False
                # change failed
                return False

        else:
            return False

    def __exit_netns_bash(self, iteration: int = None):
        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry

        # Check if connection is open
        if self._isOpen and (
                self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL or self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST):
            # can try to close netns bash instances

            cmd = "exit"

            if self._cli_cur_host_netns_lvl > 0 and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
                for i in range(self._cli_cur_host_netns_lvl):
                    self._net_connect.send_command(cmd, expect_string=self._cli_expect_prompt, cmd_verify=False)
                # clear host pending netns hierarchy
                self._cli_cur_host_netns_lvl = 0

            elif self._cli_cur_docker_netns_lvl > 0 and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
                for i in range(self._cli_cur_docker_netns_lvl):
                    self._net_connect.send_command(cmd, expect_string=self._cli_expect_prompt, cmd_verify=False)
                # clear docker pending netns hierarchy
                self._cli_cur_docker_netns_lvl = 0
            # try to resync once executed to see session is open and in correct place
            if self.__int_var_sync():
                # We closed all netns bash instances in hierarchy
                return True
            else:
                # We failed but we might need to retry
                if iteration > 0:
                    iteration -= 1
                    if self.__exit_netns_bash(iteration=iteration):
                        return True
                    else:
                        # retry failed
                        return False
                # change failed
                return False
        else:
            return False

    def __enter_host_mode(self, shell_password: str = None, iteration: int = None):
        if iteration is None:
            iteration = self.__change_mode_retry

        # Check if connection is open
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
            # can try to enter host mode

            # build shell command TODO load from cfg definitions
            shell_cmd = f"access_host.sh"
            # validate if password is derived from global?
            if shell_password is None and self.__host_password is not None:
                shell_password = self.__host_password

            if shell_password is not None:
                # execute host access sequence with password
                self._net_connect.send_command(shell_cmd,
                                               expect_string='Password:',
                                               cmd_verify=False)
                shell_response = self._net_connect.send_command(shell_password,
                                                                expect_string=self._cli_expect_prompt,
                                                                cmd_verify=False)
            else:
                # execute host access sequence without password
                shell_response = self._net_connect.send_command(shell_cmd,
                                                                expect_string=self._cli_expect_prompt,
                                                                cmd_verify=False)

            # try to resync once executed to see session is open and in correct place
            if self.__int_var_sync(exp_cli_lvl=self.SSH_ENUMS.CLI_MODE.HOST):
                self._cli_last_container = self._cli_cur_container
                self._cli_cur_container = None
                return True
            else:
                # we didn't move, need to analyze why?
                re_pattern = r"command not found"
                if re.search(re_pattern, shell_response):
                    # no access_host.sh in this container need to try access_host instead

                    # try to run access_host instead of access_host.sh
                    shell_cmd = f"access_host"

                    if shell_password is not None:
                        # execute host access sequence with password
                        self._net_connect.send_command(shell_cmd,
                                                       expect_string='Password:',
                                                       cmd_verify=False)
                        shell_response = self._net_connect.send_command(shell_password,
                                                                        expect_string=self._cli_expect_prompt,
                                                                        cmd_verify=False)
                    else:
                        # execute host access sequence without password
                        shell_response = self._net_connect.send_command(shell_cmd,
                                                                        expect_string=self._cli_expect_prompt,
                                                                        cmd_verify=False)

                    if self.__int_var_sync(exp_cli_lvl=self.SSH_ENUMS.CLI_MODE.HOST):
                        self._cli_last_container = self._cli_cur_container
                        self._cli_cur_container = None
                        return True
                    else:
                        # enter host failed with both options, should we retry?
                        # we didn't move, need to analyze why?
                        re_pattern = r"command not found"
                        if re.search(re_pattern, shell_response):
                            # this container doesn't have access_host option
                            return False
                        else:
                            cli_ready = False
                            # Loop required retry time
                            while iteration > 0:
                                if cli_ready is False:
                                    iteration -= 1
                                    if self.__enter_host_mode(shell_password=shell_password, iteration=iteration):
                                        self._cli_last_container = self._cli_cur_container
                                        self._cli_cur_container = None
                                        cli_ready = True
                                    else:
                                        cli_ready = False

                            return cli_ready

        else:
            return False

    def __exit_host_mode(self, iteration: int = None):
        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry

        # Check if connection is open
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.HOST:
            # can try to exit host mode

            # close all host netns bash instances
            self.__exit_netns_bash()

            # build exit host command list TODO load from cfg definition
            self._net_connect.send_command("exit", expect_string=self._cli_expect_prompt, cmd_verify=False)
            # try to resync once executed to see session is open and in correct place
            if self.__int_var_sync(exp_cli_lvl=self.SSH_ENUMS.CLI_MODE.SHELL):
                # We exited host mode
                return True
            else:
                # We failed to exit host mode, we might need to retry
                if iteration > 0:
                    iteration -= 1
                    if self.__exit_host_mode(iteration=iteration):
                        return True
                    else:
                        # retry failed
                        return False
                # change failed
                return False
        else:
            return False

    def __enter_gdb_mode(self, iteration: int = None, bin_location: str = None, core_file: str = None) -> Optional[str]:
        response = None

        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry

        # check variables
        if bin_location is None or core_file is None:
            return response
        elif not isinstance(bin_location, str) or not isinstance(core_file, str):
            return response
        elif bin_location == '' or core_file == '':
            return response

        # check if connection is open and location is shell
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.SHELL:
            # connection is up, we are in shell, we can proceed to try to enter gdb
            gdb_prompt = '(gdb)'
            cmd_line = f'gdb {bin_location} {core_file}'

            # execute gdb move on node
            response = self.__exec_single_or_bulk(cmd_list=cmd_line, timeout=10, exp_prompt=gdb_prompt, verify=False,
                                                    interactive=self.SSH_ENUMS.INTERACTIVE_RESPONSE.YES)

            # response = self.__exec_inter_single_cmd(xray_cmd=cmd_line, timeout=10, exp_prompt=gdb_prompt, verify=False,
            #                                         interact_response=self.SSH_ENUMS.INTERACTIVE_RESPONSE.YES)

            # verify move to gdb was done
            if self.__int_var_sync(exp_cli_lvl=self.SSH_ENUMS.CLI_MODE.GDB):
                # we have indeed moved and opened gdb shell
                if response is None or response == '':
                    response = ' '
                return response
            else:
                # We failed to go into gdb but we might need to retry
                if iteration > 0:
                    iteration -= 1
                    response = self.__enter_gdb_mode(iteration=iteration, bin_location=bin_location,
                                                     core_file=core_file)
                    if response is not None:
                        return response
                    else:
                        # retry failed
                        return None
                # change failed
                return None

    def __exit_gdb_mode(self, iteration: int = None) -> bool:
        # check and apply default iterator
        if iteration is None:
            iteration = self.__change_mode_retry
        # check if connection is open and location is GDB
        if self._isOpen and self._cli_lvl is self.SSH_ENUMS.CLI_MODE.GDB:
            # connection is up, we are in gdb, we can proceed to try to exit
            cmd_line = f'exit'

            # execute gdb move on node
            self.__exec_inter_single_cmd(cmd=cmd_line, timeout=10, exp_prompt=self._cli_expect_prompt, verify=False,
                                         interact_response=self.SSH_ENUMS.INTERACTIVE_RESPONSE.YES)

            # verify move to gdb was done
            if self.__int_var_sync(exp_cli_lvl=[self.SSH_ENUMS.CLI_MODE.SHELL, self.SSH_ENUMS.CLI_MODE.HOST]):
                # we have indeed moved and opened gdb shell
                return True
            else:
                # We failed to exit gdb, we might need to retry
                if iteration > 0:
                    iteration -= 1
                    if self.__exit_gdb_mode(iteration=iteration):
                        return True
                    else:
                        # retry failed
                        return False
                # change failed
                return False


    # endregion

    # endregion

    # region sync and general Internal Functions
    def __int_sync_con_status(self):
        # check we don't have a missmatch with alive connection marked as dead

        # are we even initialized?
        if self._net_connect is not None:
            tmp_is_alive = self._net_connect.is_alive()
            if not self._isOpen and tmp_is_alive or (self._isOpen and not tmp_is_alive):
                # sync to correct state, connection is open
                if not self._isOpen and tmp_is_alive:
                    self._isOpen = True
                # sync to correct state, connection is close
                elif self._isOpen and not tmp_is_alive:
                    self._isOpen = False
        else:
            # session was not initialized = treat as closed
            self._isOpen = False
        return self._isOpen

    def __int_var_sync(self, **kwargs):
        exp_cli_lvl_entries = kwargs.get("exp_cli_lvl", None)
        # match in case we are GDB to handle prompt pattern recognition
        prompt_pattern = None

        # check if we are expecting GDB if so add supported prompt termination
        if exp_cli_lvl_entries:
            if isinstance(exp_cli_lvl_entries, List):
                for exp_cli in exp_cli_lvl_entries:
                    if exp_cli is self.SSH_ENUMS.CLI_MODE.GDB:
                        prompt_pattern = r'[\#\$\)]'
            elif isinstance(exp_cli_lvl_entries, self.SSH_ENUMS.CLI_MODE):
                if exp_cli_lvl_entries is self.SSH_ENUMS.CLI_MODE.GDB:
                    prompt_pattern = r'[\#\$\)]'

        # attempt to resync internal values
        # flag for sync response
        sync_done = False

        # are we connected? we need to sync connection status
        if self.__int_sync_con_status():
            # resync current prompt value -> will update if changed
            self.get_current_prompt(pattern=prompt_pattern)
            # run location sync based on prompt
            if self.__int_sync_location():
                sync_done = True
        else:
            if self.__reconnect:
                # reconnect expected and session not open
                self.connect()
                # retry sync now once connected
                self.__int_var_sync()
            sync_done = False
            # we don't have connection

        # we failed in sync, or we have no expected cli --> we just return sync_done status
        if not sync_done or exp_cli_lvl_entries is None:
            return sync_done
        else:
            cli_lvl_mismatch = True
            # Do we have multiple potential cli levels expected?
            if isinstance(exp_cli_lvl_entries, List):
                for exp_cli in exp_cli_lvl_entries:
                    if exp_cli == self._cli_lvl:
                        cli_lvl_mismatch = False
            else:
                if exp_cli_lvl_entries == self._cli_lvl:
                    cli_lvl_mismatch = False

            # check sync status and expected cli_lvl
            if sync_done and cli_lvl_mismatch:
                return False
            else:
                return True

    def __int_sync_location(self):
        # attempt to resync internal values

        # return value location var synced - default False aka not synced
        sync_done = False

        # TEMP: init all the regex pattern for prompt analysis TODO: move to general and load from cfg file
        re_cfg_pattern = r"\(cfg\)#"
        re_ro_pattern = r"(.+)#"
        # device S/N filter regex
        re_global_os_pattern = r"root@"
        re_docker_pattern = r"\((.*)\)root@"
        re_host_pattern = r"^root@(.*):/#"
        re_gdb_pattern = r"\(gdb\)"

        # conditional logic to match current mode to prompt
        if self._cli_cur_prompt is not None:
            # we have prompt initialized, can proceed to logic
            # try to match gdb prompt
            if re.search(re_gdb_pattern, self._cli_cur_prompt):
                # we are in gdb mode, verify cur cli lvl is matching
                if self._cli_lvl != self.SSH_ENUMS.CLI_MODE.GDB:
                    self._cli_lvl = self.SSH_ENUMS.CLI_MODE.GDB
                # nothing else to sync at this point
                sync_done = True
            else:
                # try to match to ubuntu os lvl prompt
                if re.search(re_global_os_pattern, self._cli_cur_prompt):
                    # derive S/N value from docker/host patterns
                    tmp_host_sn = None
                    tmp_match_value = re.match(re_host_pattern, self._cli_cur_prompt)
                    if tmp_match_value is not None and len(tmp_match_value.groups()) == 1:
                        tmp_host_sn = tmp_match_value.groups()[0]
                    else:
                        tmp_match_value = re.match(re_docker_pattern, self._cli_cur_prompt)
                        if tmp_match_value is not None and len(tmp_match_value.groups()) == 1:
                            tmp_host_sn = tmp_match_value.groups()[0]
                        else:
                            raise Exception(f"__int-var-sync: host_sn_not_found"
                                            f"for mode {self._cli_lvl} on {self._cli_cur_node}/{self._cli_cur_node_id}"
                                            f"with input {self._cli_cur_prompt} for mode {self._cli_lvl.value}")

                    if tmp_host_sn is not None:
                        # host re pattern init
                        host_mode_expected_pattern = r"root@" + tmp_host_sn + r":/#"
                        if re.match(host_mode_expected_pattern, self._cli_cur_prompt):
                            # host mode found check S/N update and cli lvl
                            if self._hw_serial != tmp_host_sn:
                                self._hw_serial = tmp_host_sn
                            if self._cli_lvl is not self.SSH_ENUMS.CLI_MODE.HOST:
                                self._cli_lvl = self.SSH_ENUMS.CLI_MODE.HOST
                            # check netns value for host
                            get_host_netns = self.__int_exec_cmd_direct("ip netns identify")
                            # crop the netns value only, in case we get the OS prompt
                            get_host_netns = re.sub(r'\n.*', '', get_host_netns)
                            if self._cli_cur_netns != get_host_netns:
                                self._cli_cur_netns = get_host_netns
                            sync_done = True
                        else:
                            # check if docker mode
                            re_docker_pattern = r"\(" + tmp_host_sn + r"\)" + r"root@(.*?):/.*\[(.*)\]#"
                            tmp_match_value = re.match(re_docker_pattern, self._cli_cur_prompt)
                            if tmp_match_value is not None:
                                if self._hw_serial != tmp_host_sn:
                                    self._hw_serial = tmp_host_sn
                                if self._cli_lvl is not self.SSH_ENUMS.CLI_MODE.SHELL:
                                    self._cli_lvl = self.SSH_ENUMS.CLI_MODE.SHELL
                                if self._cli_cur_container != tmp_match_value.groups()[0].replace('_', '-'):
                                    self._cli_cur_container = tmp_match_value.groups()[0].replace('_', '-')
                                if self._cli_cur_netns != tmp_match_value.groups()[1]:
                                    self._cli_cur_netns = tmp_match_value.groups()[1]
                                sync_done = True
                else:
                    # check if we're in cfg mode
                    tmp_match_value = re.match(re_cfg_pattern, self._cli_cur_prompt)
                    if tmp_match_value is None:
                        # we're not in cfg mode, try ro
                        tmp_match_value = re.match(re_ro_pattern, self._cli_cur_prompt)
                        if tmp_match_value is not None:
                            # we're in dnos ro cli mode
                            self.get_hostname()
                            # cli lvl sync:
                            if self._cli_lvl is not self.SSH_ENUMS.CLI_MODE.DNOS_SHOW:
                                self._cli_lvl = self.SSH_ENUMS.CLI_MODE.DNOS_SHOW
                            sync_done = True
                    else:
                        # we're in dnos cfg mode
                        self.get_hostname()
                        # cli lvl sync
                        if self._cli_lvl is not self.SSH_ENUMS.CLI_MODE.DNOS_CFG:
                            self._cli_lvl = self.SSH_ENUMS.CLI_MODE.DNOS_CFG
                        sync_done = True

        return sync_done

    def __int_exec_cmd_direct(self, cmd):
        # execute the command
        output = self._net_connect.send_command(cmd, expect_string=self._cli_expect_prompt, cmd_verify=False)
        return output

    def __int_strip_ansi(self, line):
        # standard ansi removal
        pattern = re.compile(r'\x1B\[\d+(;\d+){0,2}m')
        stripped = pattern.sub('', line)
        # Dnos open ansi removal
        pattern = re.compile(r'\x1B\[F')
        stripped = pattern.sub('', stripped)
        # for ubuntu host side
        pattern = re.compile(r'^.*\x07')
        stripped = pattern.sub('', stripped)
        return stripped

    def __try_next_auth(self) -> bool:
        next_auth = self.auth.get_next_credentials()
        if len(next_auth) > 0:
            self.__user = next_auth[0]
            self.__pass = next_auth[1]
            self.__shell_password = next_auth[2]
            self.__host_password = next_auth[3]
            return True
        else:
            self.auth.reset_credentials()
            return False

    def __int_var_lower(self, var: list | str):
        if var is not None:
            if isinstance(var, list):
                for i in var:
                    if i is not None and isinstance(i, str):
                        i = i.lower()
            elif isinstance(var, str):
                var = var.lower()

        return var

    def __int_get_bfd_master_id(self) -> str:
        # prepare default response
        response = 'bfd-master'
        # try change to show mode, will skip if already in show
        if self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
            # we are in show mode, prepare command for bfd master verification
            cmd = 'show dnos-internal ncp * system info  | inc master'
            output = self.exec_command(cmd=cmd)

            if output is not None and output != '':
                # we have output for verification, match to regex for id
                re_pattern = r"master_ncp_id:\s+(\d+)\n"
                match = re.search(re_pattern, output)
                if match is not None and len(match.groups()) >= 1:
                    # update response
                    response = match.groups()[0]

        return response

    def __int_get_ncc_active_id(self) -> str:
        # prepare default response
        response = 'active'
        # try change to show mode, will skip if already in show
        if self.change_mode(requested_cli=self.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
            # we are in show mode, prepare command for active ncc verification
            cmd = 'show system | inc active'
            output = self.exec_command(cmd=cmd)

            if output is not None and output != '':
                # we have output for verification, match to regex for id
                re_pattern = r"\|\s+?NCC\s+?\|\s+?(\d+)\s+?\|.*?\|.*?active.*?\|"
                match = re.search(re_pattern, output)
                if match is not None and len(match.groups()) >= 1:
                    # update response
                    response = match.groups()[0]

        return response

    # using subprocess module for sending icmp ping messages with params
    # returns: on success True, on ANY failure return False
    # return on logic/process failure: False
    def __icmp_ping(self, host: str = None, count: int = 1,
                    retry_wait_timer: int = 0, retry_count: int = 1, timeout: int = 10,
                    size: int = 32, ttl: int = 255, df_bit: bool = False,
                    fast_ping: bool = False):
        iteration = 0

        # Returns True if host responds to a ping request
        import subprocess
        import platform
        import time

        if host is None:
            host = self.__host

        # Ping parameters as function of OS
        if platform.system().lower() == "windows":
            ping_params = f"-n {str(count)}"
            if size != 32:
                ping_params += f" -l {size}"
            if ttl != 255:
                ping_params += f" -i {ttl}"
            if df_bit:
                ping_params += f" -f"
            if fast_ping:
                ping_params += f" -w 10"
        else:
            ping_params = f"-c {str(count)}"
            if size != 32:
                ping_params += f" -s {size}"
            if ttl != 255:
                ping_params += f" -m {ttl}"
            if df_bit:
                ping_params += f" -D"
            if fast_ping:
                ping_params += f" -i 0.1 -W 10"

        ping_cmd = "ping" + " " + ping_params + " " + host
        need_sh = False if platform.system().lower() == "windows" else True

        if timeout > 0:
            # calculate loop timeout time
            func_timeout = time.time() + timeout

            while func_timeout >= time.time() and iteration < retry_count:
                icmp_resp = subprocess.call(ping_cmd, shell=need_sh, stdout=subprocess.DEVNULL)
                if icmp_resp == 0:
                    return True
                elif icmp_resp == 1 or icmp_resp == 2:
                    iteration += 1
                    if retry_wait_timer > 0:
                        time.sleep(retry_wait_timer)
        else:

            while iteration < retry_count:
                icmp_resp = subprocess.call(ping_cmd, shell=need_sh, stdout=subprocess.DEVNULL)
                if icmp_resp == 0:
                    return True
                elif icmp_resp == 1 or icmp_resp == 2:
                    iteration += 1
                    if retry_wait_timer > 0:
                        time.sleep(retry_wait_timer)
        return False

    # check for xray_cmd str/list and return true if anything contains a show command
    def __contains_show_cmd(self, cmd):
        contains_show = False
        re_show = r'^show'
        if cmd is not None:
            if isinstance(cmd, str):
                if re.search(re_show, cmd):
                    contains_show = True
            elif isinstance(cmd, list):
                for line in cmd:
                    if re.search(re_show, line):
                        contains_show = True

        return contains_show
    # endregion

class BaseConnector:

    def __init__(self, ip, username, interface=None, session_log=False):
        self.ip = ip
        self.username = username
        self.interface = '' if interface is None else interface
        # Get the current directory of the script that is being run
        try:
            self.connection: SSH_Conn = SSH_Conn(host=self.ip, authentication=None, localized_exec=True,
                                                 session_log=session_log,
                                                 icmp_test=True)
            self.connection.connect()

        except Exception as e:
            print(f'Error: {e}')
            self.connection: SSH_Conn = None

    def get_interfaces(self, *args):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_SHOW)
        output = self.connection.exec_command(cmd=f'show interfaces {args}' if args else 'show interfaces', timeout=100)
        interfaces = re.findall(INTERFACE_REGEX, output)
        # Convert to a set and back to a list to remove duplicates
        interfaces = list(OrderedDict.fromkeys(interfaces))
        return interfaces

    def backup_config(self, filename='Automated_Snapshot'):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.connection.exec_command(f'save {filename}')

    def load_override_factory_default(self):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.connection.exec_command('load override factory-default')

    def load_merge_config(self, filename='Automator'):
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        if not self.connection.exec_command(cmd=f'load merge {filename}', timeout=3600):
            print(f'Failed to load config')
        else:
            print(f'Load overriding original config prior to changes.')
            if not self.connection.commit_cfg():
                print(f'Commit FAILED please reffer to test_con_log')
                sys.exit(1)

    def SCP_To_Device(self, filename, path='/config'):
        try:
            # Create an SSH client instance.
            ssh = paramiko.SSHClient()

            # Automatically add the remote host (prevents MissingHostKeyPolicy error)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the remote host
            ssh.connect(self.ip, username=self.username, password='dnroot')

            # SCPCLient takes a paramiko transport as its only argument
            scp = SCPClient(ssh.get_transport())

            # Upload the file to the remote host
            scp.put(filename, remote_path=path)

            # Close the SCP instance
            scp.close()

        except Exception as e:
            print(f"An error occurred while uploading the file: {e}")

# test region
if __name__ == '__main__':

    start_id = 44
    end_id = 52
    for i in range(end_id - start_id):
        id = start_id + i
        host = f'100.64.14.{str(id)}'
        print(f"{host} - execution started")
        router = SSH_Conn(host=host, icmp_test=True)
        router.connect()
        router.change_mode()
        if router.change_mode(requested_cli=router.SSH_ENUMS.CLI_MODE.DNOS_CFG):
            router.exec_command(cmd='system aaa-server admin-state disable')
            if router.commit_cfg():
                print(f"{host} - execution successful")
            else:
                print(f"{host} - commit failed")
        else:
            print(f"{host} - cfg enter failed")



    # run_start = datetime.now()
    # ip_addr = '100.64.14.49'
    #
    # # auth example
    # router = SSH_Conn(host=ip_addr, authentication=None, localized_exec=True, session_log='test_con.log',
    #                   icmp_test=True)
    #
    # # execute interactive command test:
    # print(f"connecting to node {ip_addr}")
    # connect_start = datetime.now()
    # router.connect()
    # connect_end = datetime.now()
    # print('connected')
    #
    # ls = ['show system', 'show interface']
    # if_info = router.exec_command(xray_cmd=ls, output_object_type=dict)
    # if router.change_mode(requested_cli=router.SSH_ENUMS.CLI_MODE.DNOS_CFG):
    #     # Im in config
    #     router.exec_command(xray_cmd='interfaces ge100-0/0/1 description "hello this is dog"')
    #     router.commit_cfg(timeout=30)


    # cmd_list = ['show system', 'show file core list']
    # cmd_exec_start = datetime.now()
    # print("executing command batch:")
    # for i in cmd_list:
    #     print(f"--> {i}")
    # print("executing...")
    # output = router.exec_command(xray_cmd=cmd_list, timeout=30, output_object_type=dict,
    #                              interactive=router.SSH_ENUMS.INTERACTIVE_RESPONSE.YES,
    #                              interactive_pass='drive1234!')
    # cmd_exec_end = datetime.now()
    #
    # if output is not None:
    #     for i in output:
    #         print(i)
    #         if isinstance(output[i], list):
    #             for resp in output[i]:
    #                 print(f"-->\n{resp}\n--")
    #         else:
    #             print(f"###{output[i]}###\n")

    # print(f"attempt to open core gdb shell")
    # core_file = 'routing_engine/core-rsvpd.46148.sig-11.2023-07-16.21-06-19'
    # bin_file = '/usr/sbin/rsvpd'
    # output = router.open_core_gdb(node='ncc', node_id='active', container='routing-engine',
    #                               bin_file=bin_file, core_file=core_file)
    #
    # if output is not None:
    #     print(f"we are in GDB...\ninit data:\n{output}")
    #     print(f"executing bt command")
    #     bt_output = router.exec_command(xray_cmd='bt', timeout=10,
    #                                     interactive=router.SSH_ENUMS.INTERACTIVE_RESPONSE.CONTINUE)
    #
    #     print(f"got back:\n{bt_output}\n####")
    #     print(f"exit GDB")
    #     if router.change_mode(requested_cli=router.SSH_ENUMS.CLI_MODE.DNOS_SHOW):
    #         print(f"performed gdb -> dnos_show move")
    #     #     print("executing command batch:")
    #     #     for i in cmd_list:
    #     #         print(f"--> {i}")
    #     #     print("executing...")
    #     #     output = router.exec_command(xray_cmd=cmd_list, timeout=30, output_object_type=dict,
    #     #                                  interactive=router.SSH_ENUMS.INTERACTIVE_RESPONSE.YES,
    #     #                                  interactive_pass='drive1234!')
    #     #     if output is not None:
    #     #         for i in output:
    #     #             print(i)
    #     #             if isinstance(output[i], list):
    #     #                 for resp in output[i]:
    #     #                     print(f"-->\n{resp}\n--")
    #     #             else:
    #     #                 print(f"###{output[i]}###\n")
    #     else:
    #         print(f"failed to performed gdb -> dnos_show move")
    # else:
    #     print(f"failed to go into gdb")
    # # print(f"moving to shell")
    # # router.change_mode(requested_cli=router.SSH_ENUMS.CLI_MODE.SHELL, node='', node_id='', container='',
    # #                    shell_password=None)
    # # output = router.exec_command(xray_cmd=['cd /core/traces/', 'ls -la'])
    # # print(f"shell output:\n{output}")
    # # router.change_mode(requested_cli=router.SSH_ENUMS.CLI_MODE.HOST, node='', node_id='', container='')
    # # output = router.exec_command(xray_cmd=['ip addr'])
    # # print(f"host output:\n{output}")
    # router.disconnect()
    # print("disconnected...")
    # run_end = datetime.now()
    #
    # print(f"total runtime: {run_end - run_start}\nConnect time: {connect_end - connect_start}\n")

    # print(f"Exec time: {cmd_exec_end - cmd_exec_start}")
