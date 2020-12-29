# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.paging import Paged


class ServiceResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`ServiceResource <azure.mgmt.appplatform.v2020_11_01_preview.models.ServiceResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ServiceResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(ServiceResourcePaged, self).__init__(*args, **kwargs)
class AppResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`AppResource <azure.mgmt.appplatform.v2020_11_01_preview.models.AppResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[AppResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(AppResourcePaged, self).__init__(*args, **kwargs)
class BindingResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`BindingResource <azure.mgmt.appplatform.v2020_11_01_preview.models.BindingResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[BindingResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(BindingResourcePaged, self).__init__(*args, **kwargs)
class CertificateResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`CertificateResource <azure.mgmt.appplatform.v2020_11_01_preview.models.CertificateResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[CertificateResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(CertificateResourcePaged, self).__init__(*args, **kwargs)
class CustomDomainResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`CustomDomainResource <azure.mgmt.appplatform.v2020_11_01_preview.models.CustomDomainResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[CustomDomainResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(CustomDomainResourcePaged, self).__init__(*args, **kwargs)
class DeploymentResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`DeploymentResource <azure.mgmt.appplatform.v2020_11_01_preview.models.DeploymentResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DeploymentResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(DeploymentResourcePaged, self).__init__(*args, **kwargs)
class OperationDetailPaged(Paged):
    """
    A paging container for iterating over a list of :class:`OperationDetail <azure.mgmt.appplatform.v2020_11_01_preview.models.OperationDetail>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[OperationDetail]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationDetailPaged, self).__init__(*args, **kwargs)
class ResourceSkuPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ResourceSku <azure.mgmt.appplatform.v2020_11_01_preview.models.ResourceSku>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ResourceSku]'}
    }

    def __init__(self, *args, **kwargs):

        super(ResourceSkuPaged, self).__init__(*args, **kwargs)
