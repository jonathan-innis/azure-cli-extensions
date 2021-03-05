# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest

from azure_devtools.scenario_tests import AllowLargeResponse
from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer)


TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), '..'))


class K8sExtensionScenarioTest(ScenarioTest):

    @ResourceGroupPreparer(name_prefix='cli_test_k8s_extension')
    def test_k8s_extension(self, resource_group):

        self.kwargs.update({
            'name': 'azuremonitor-containers',
            'rg': 'nanthirg0923',
            'cluster_name': 'nanthicluster0923',
            'cluster_type': 'connectedClusters',
            'extension_type': 'microsoft.azuremonitor.containers'
        })

        self.cmd('k8s-extension create -g {rg} -n {name} --tags foo=doo -c {cluster_name} --cluster-type {cluster_type} --extension-type {extension_type}', checks=[
            self.check('name', '{name}')
        ])
        # self.cmd('k8s-extension update -g {rg} -n {name} --tags foo=boo', checks=[
        #     self.check('tags.foo', 'boo')
        # ])
        count = len(self.cmd('k8s-extension list -c {cluster_name} -g {rg} --cluster-type {cluster_type}').get_output_in_json())
        self.cmd('k8s-extension show -c {cluster_name} -g {rg} -n {name} --cluster-type {cluster_type}', checks=[
            self.check('name', '{name}'),
            self.check('resourceGroup', '{rg}'),
        ])
        self.cmd('k8s-extension delete -g {rg} -c {cluster_name} -n {name} --cluster-type {cluster_type} -y')
        final_count = len(self.cmd('k8s-extension list -c {cluster_name} -g {rg} --cluster-type {cluster_type}').get_output_in_json())
        self.assertTrue(final_count, count - 1)
