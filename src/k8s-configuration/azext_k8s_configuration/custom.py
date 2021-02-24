# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import base64
import io
from urllib.parse import urlparse
from azure.cli.core import telemetry
from azure.cli.core.azclierror import InvalidArgumentValueError, ResourceNotFoundError, \
    RequiredArgumentMissingError, MutuallyExclusiveArgumentError, CommandNotFoundError
from knack.log import get_logger
from paramiko.ed25519key import Ed25519Key
from paramiko.hostkeys import HostKeyEntry
from paramiko.ssh_exception import SSHException
from Crypto.PublicKey import RSA, ECC, DSA

from azext_k8s_configuration.vendored_sdks.models import SourceControlConfiguration
from azext_k8s_configuration.vendored_sdks.models import HelmOperatorProperties
from azext_k8s_configuration.vendored_sdks.models import ErrorResponseException
import azext_k8s_configuration._constants as consts
from azext_k8s_configuration._validators import validate_configuration_name

logger = get_logger(__name__)


def show_k8s_configuration(client, resource_group_name, cluster_name, name, cluster_type):
    """Get an existing Kubernetes Source Control Configuration.

    """
    # Determine ClusterRP
    cluster_rp = __get_cluster_type(cluster_type)

    try:
        config = client.get(resource_group_name, cluster_rp, cluster_type, cluster_name, name)
        return __fix_compliance_state(config)
    except ErrorResponseException as ex:
        # Customize the error message for resources not found
        if ex.response.status_code == 404:
            # If Cluster not found
            if ex.message.__contains__("(ResourceNotFound)"):
                message = ex.message
                recommendation = 'Verify that the --cluster-type is correct and the Resource ' \
                                 '{0}/{1}/{2} exists'.format(cluster_rp, cluster_type, cluster_name)
            # If Configuration not found
            elif ex.message.__contains__("Operation returned an invalid status code 'Not Found'"):
                message = '(ConfigurationNotFound) The Resource {0}/{1}/{2}/Microsoft.KubernetesConfiguration/' \
                          'sourcecontrolConfigurations/{3} could not be found!'.format(cluster_rp, cluster_type,
                                                                                       cluster_name, name)
                recommendation = 'Verify that the Resource {0}/{1}/{2}/Microsoft.KubernetesConfiguration' \
                                 '/sourcecontrolConfigurations/{3} exists'.format(cluster_rp, cluster_type,
                                                                                  cluster_name, name)
            else:
                message = ex.message
                recommendation = ''
            telemetry.set_user_fault()
            telemetry.set_exception(
                exception=message,
                fault_type=consts.Resource_Does_Not_Exist_Fault_Type,
                summary='Cluster configuration does not exist'
            )
            raise ResourceNotFoundError(message, recommendation) from ex


# pylint: disable=too-many-locals
def create_k8s_configuration(client, resource_group_name, cluster_name, name, repository_url, scope, cluster_type,
                             operator_instance_name=None, operator_namespace='default',
                             helm_operator_chart_version='1.2.0', operator_type='flux', operator_params='',
                             ssh_private_key='', ssh_private_key_file='', https_user='', https_key='',
                             ssh_known_hosts='', ssh_known_hosts_file='', enable_helm_operator=None,
                             helm_operator_params=''):
    """Create a new Kubernetes Source Control Configuration.

    """
    # Validate configuration name
    validate_configuration_name(name)

    # Determine ClusterRP
    cluster_rp = __get_cluster_type(cluster_type)

    # Determine operatorInstanceName
    if operator_instance_name is None:
        operator_instance_name = name

    # Create helmOperatorProperties object
    helm_operator_properties = None
    if enable_helm_operator:
        helm_operator_properties = HelmOperatorProperties()
        helm_operator_properties.chart_version = helm_operator_chart_version.strip()
        helm_operator_properties.chart_values = helm_operator_params.strip()

    protected_settings = validate_and_get_protected_settings(ssh_private_key,
                                                             ssh_private_key_file,
                                                             https_user,
                                                             https_key)
    knownhost_data = get_data_from_key_or_file(ssh_known_hosts, ssh_known_hosts_file)
    if knownhost_data:
        validate_known_hosts(knownhost_data)

    # Flag which parameters have been set and validate these settings against the set repository url
    ssh_private_key_set = ssh_private_key != '' or ssh_private_key_file != ''
    known_hosts_contents_set = knownhost_data != ''
    https_auth_set = https_user != '' and https_key != ''
    validate_url_with_params(repository_url,
                             ssh_private_key_set=ssh_private_key_set,
                             known_hosts_contents_set=known_hosts_contents_set,
                             https_auth_set=https_auth_set)

    # Create sourceControlConfiguration object
    source_control_configuration = SourceControlConfiguration(repository_url=repository_url,
                                                              operator_namespace=operator_namespace,
                                                              operator_instance_name=operator_instance_name,
                                                              operator_type=operator_type,
                                                              operator_params=operator_params,
                                                              configuration_protected_settings=protected_settings,
                                                              operator_scope=scope,
                                                              ssh_known_hosts_contents=knownhost_data,
                                                              enable_helm_operator=enable_helm_operator,
                                                              helm_operator_properties=helm_operator_properties)

    # Try to create the resource
    config = client.create_or_update(resource_group_name, cluster_rp, cluster_type, cluster_name,
                                     name, source_control_configuration)

    return __fix_compliance_state(config)


def update_k8s_configuration(client, resource_group_name, cluster_name, name, cluster_type,
                             repository_url=None, operator_params=None, ssh_known_hosts='',
                             ssh_known_hosts_file='', enable_helm_operator=None, helm_operator_chart_version=None,
                             helm_operator_params=None):
    """Update an existing Kubernetes Source Control Configuration.

    """

    # TODO: Remove this after we eventually get PATCH implemented for update and uncomment
    raise CommandNotFoundError(
        "\"k8s-configuration update\" currently is not available. "
        "Use \"k8s-configuration create\" to update a previously created configuration."
    )

    # # Determine ClusterRP
    # cluster_rp = __get_cluster_type(cluster_type)

    # source_control_configuration_name = name.strip()

    # config = client.get(resource_group_name, cluster_rp, cluster_type, cluster_name,
    #                     source_control_configuration_name)
    # update_yes = False

    # # Set input values, if they are supplied
    # if repository_url is not None:
    #     config.repository_url = repository_url
    #     update_yes = True

    # if operator_params is not None:
    #     config.operator_params = operator_params
    #     update_yes = True

    # knownhost_data = get_data_from_key_or_file(ssh_known_hosts, ssh_known_hosts_file)
    # if knownhost_data:
    #     validate_known_hosts(knownhost_data)
    #     config.ssh_known_hosts_contents = knownhost_data
    #     update_yes = True

    # if enable_helm_operator is not None:
    #     config.enable_helm_operator = enable_helm_operator
    #     update_yes = True

    # # Get the helm operator properties from the config and set them
    # if config.helm_operator_properties is None:
    #     config.helm_operator_properties = HelmOperatorProperties()
    # if helm_operator_chart_version is not None:
    #     config.helm_operator_properties.chart_version = helm_operator_chart_version.strip()
    #     update_yes = True
    # if helm_operator_params is not None:
    #     config.helm_operator_properties.chart_values = helm_operator_params.strip()
    #     update_yes = True

    # if update_yes is False:
    #     raise RequiredArgumentMissingError(
    #         'Invalid update. No values to update!',
    #         'Verify that at least one changed parameter is provided in the update command')

    # # Flag which parameters have been set and validate these settings against the set repository url
    # known_hosts_contents_set = config.ssh_known_hosts_contents != ""
    # validate_url_with_params(config.repository_url,
    #                          ssh_private_key_set=False,
    #                          known_hosts_contents_set=known_hosts_contents_set,
    #                          https_auth_set=False)

    # config = client.create_or_update(resource_group_name, cluster_rp, cluster_type, cluster_name,
    #                                  source_control_configuration_name, config)

    # return __fix_compliance_state(config)


def list_k8s_configuration(client, resource_group_name, cluster_name, cluster_type):
    cluster_rp = __get_cluster_type(cluster_type)
    return client.list(resource_group_name, cluster_rp, cluster_type, cluster_name)


def delete_k8s_configuration(client, resource_group_name, cluster_name, name, cluster_type):
    """Delete an existing Kubernetes Source Control Configuration.

    """
    # Determine ClusterRP
    cluster_rp = __get_cluster_type(cluster_type)

    source_control_configuration_name = name

    return client.delete(resource_group_name, cluster_rp, cluster_type, cluster_name, source_control_configuration_name)


def validate_and_get_protected_settings(ssh_private_key, ssh_private_key_file, https_user, https_key):
    protected_settings = {}
    ssh_private_key_data = get_data_from_key_or_file(ssh_private_key, ssh_private_key_file)

    # Add gitops private key data to protected settings if exists
    # Dry-run all key types to determine if the private key is in a valid format
    invalid_rsa_key, invalid_ecc_key, invalid_dsa_key, invalid_ed25519_key = (False, False, False, False)
    if ssh_private_key_data != '':
        try:
            RSA.import_key(from_base64(ssh_private_key_data))
        except ValueError:
            invalid_rsa_key = True
        try:
            ECC.import_key(from_base64(ssh_private_key_data))
        except ValueError:
            invalid_ecc_key = True
        try:
            DSA.import_key(from_base64(ssh_private_key_data))
        except ValueError:
            invalid_dsa_key = True
        try:
            key_obj = io.StringIO(from_base64(ssh_private_key_data).decode('utf-8'))
            Ed25519Key(file_obj=key_obj)
        except SSHException:
            invalid_ed25519_key = True

        if invalid_rsa_key and invalid_ecc_key and invalid_dsa_key and invalid_ed25519_key:
            telemetry.set_user_fault()
            telemetry.set_exception(
                exception=consts.Invalid_Private_Key_Format_Error,
                fault_type=consts.Invalid_Private_Key_Format_Fault_Type,
                summary='Invalid ssh private key format'
            )
            raise InvalidArgumentValueError(
                consts.Invalid_Private_Key_Format_Error,
                consts.Invalid_Private_Key_Format_Help)
        protected_settings["sshPrivateKey"] = ssh_private_key_data

    # Check if both httpsUser and httpsKey exist, then add to protected settings
    if https_user != '' and https_key != '':
        protected_settings['httpsUser'] = to_base64(https_user)
        protected_settings['httpsKey'] = to_base64(https_key)
    elif https_user != '' or https_key != '':
        telemetry.set_user_fault()
        telemetry.set_exception(
            exception=consts.Https_Parameter_Missing_Error,
            fault_type=consts.Https_Parameter_Missing_Fault_Type,
            summary='Https parameter missing'
        )
        raise RequiredArgumentMissingError(
            consts.Https_Parameter_Missing_Error,
            consts.Https_Parameter_Missing_Help
        )

    return protected_settings


def __get_cluster_type(cluster_type):
    if cluster_type.lower() == 'connectedclusters':
        return 'Microsoft.Kubernetes'
    # Since cluster_type is an enum of only two values, if not connectedClusters, it will be managedClusters.
    return 'Microsoft.ContainerService'


def __fix_compliance_state(config):
    # If we get Compliant/NonCompliant as compliance_sate, change them before returning
    if config.compliance_status.compliance_state.lower() == 'noncompliant':
        config.compliance_status.compliance_state = 'Failed'
    elif config.compliance_status.compliance_state.lower() == 'compliant':
        config.compliance_status.compliance_state = 'Installed'

    return config


def validate_url_with_params(repository_url, ssh_private_key_set, known_hosts_contents_set, https_auth_set):
    scheme = urlparse(repository_url).scheme

    if scheme in ('http', 'https'):
        if ssh_private_key_set:
            telemetry.set_user_fault()
            telemetry.set_exception(
                exception=consts.Ssh_Parameter_Mismatch_Error,
                fault_type=consts.Ssh_Parameter_Mismatch_Fault_Type,
                summary='Ssh parameter specified with http(s) url'
            )
            raise MutuallyExclusiveArgumentError(
                consts.Ssh_Parameter_Mismatch_Error,
                consts.Ssh_Parameter_Mismatch_Help
            )
        if known_hosts_contents_set:
            telemetry.set_user_fault()
            telemetry.set_exception(
                exception=consts.Ssh_Parameter_Mismatch_Error,
                fault_type=consts.Ssh_Parameter_Mismatch_Fault_Type,
                summary='Ssh parameter specified with http(s) url'
            )
            raise MutuallyExclusiveArgumentError(
                consts.Ssh_Parameter_Mismatch_Error,
                consts.Ssh_Parameter_Mismatch_Help
            )
        if not https_auth_set and scheme == 'https':
            logger.warning('Warning! https url is being used without https auth params, ensure the repository '
                           'url provided is not a private repo')
    else:
        if https_auth_set:
            telemetry.set_user_fault()
            telemetry.set_exception(
                exception=consts.Https_Parameter_Mismatch_Error,
                fault_type=consts.Https_Parameter_Mismatch_Fault_Type,
                summary='Https parameter specified with non-http(s) url'
            )
            raise MutuallyExclusiveArgumentError(
                consts.Https_Parameter_Mismatch_Error,
                consts.Https_Parameter_Mismatch_Help
            )


def validate_known_hosts(knownhost_data):
    try:
        knownhost_str = from_base64(knownhost_data).decode('utf-8')
    except Exception as ex:
        telemetry.set_user_fault()
        raise InvalidArgumentValueError(
            'Error! ssh known_hosts is not a valid utf-8 base64 encoded string',
            'Verify that the string provided safely decodes into a valid utf-8 format') from ex
    lines = knownhost_str.split('\n')
    for line in lines:
        line = line.strip(' ')
        line_len = len(line)
        if (line_len == 0) or (line[0] == "#"):
            continue
        try:
            host_key = HostKeyEntry.from_line(line)
            if not host_key:
                raise Exception('not enough fields found in known_hosts line')
        except Exception as ex:
            telemetry.set_user_fault()
            raise InvalidArgumentValueError(
                'Error! ssh known_hosts provided in wrong format',
                'Verify that all lines in the known_hosts contents are provided in a valid sshd(8) format') from ex


def get_data_from_key_or_file(key, filepath):
    if key != '' and filepath != '':
        telemetry.set_user_fault()
        raise MutuallyExclusiveArgumentError(
            'Error! Both textual key and key filepath cannot be provided',
            'Try providing the file parameter without providing the plaintext parameter')
    data = ''
    if filepath != '':
        data = read_key_file(filepath)
    elif key != '':
        data = key
    return data


def read_key_file(path):
    try:
        with open(path, "r") as myfile:  # user passed in filename
            data_list = myfile.readlines()  # keeps newline characters intact
            data_list_len = len(data_list)
            if (data_list_len) <= 0:
                raise Exception("File provided does not contain any data")
            raw_data = ''.join(data_list)
        return to_base64(raw_data)
    except Exception as ex:
        telemetry.set_user_fault()
        raise InvalidArgumentValueError(
            'Error! Unable to read key file specified with: {0}'.format(ex),
            'Verify that the filepath specified exists and contains valid utf-8 data') from ex


def from_base64(base64_str):
    return base64.b64decode(base64_str)


def to_base64(raw_data):
    bytes_data = raw_data.encode('utf-8')
    return base64.b64encode(bytes_data).decode('utf-8')
