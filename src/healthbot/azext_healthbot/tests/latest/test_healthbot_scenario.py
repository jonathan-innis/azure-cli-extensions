# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

import os
from azure.cli.testsdk import ScenarioTest
from azure.cli.testsdk import ResourceGroupPreparer
from .example_steps import step_create
from .example_steps import step_list
from .example_steps import step_list2
from .example_steps import step_show
from .example_steps import step_update
from .example_steps import step_delete
from .. import (
    try_manual,
    raise_if,
    calc_coverage
)


TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), '..'))


# Env setup_scenario
@try_manual
def setup_scenario(test, rg, rg_2):
    pass


# Env cleanup_scenario
@try_manual
def cleanup_scenario(test, rg, rg_2):
    pass


# Testcase: Scenario
@try_manual
def call_scenario(test, rg, rg_2):
    setup_scenario(test, rg, rg_2)
    step_create(test, rg, rg_2, checks=[
        test.check("name", "{myBot}", case_sensitive=False),
        test.check("location", "eastus", case_sensitive=False),
        test.check("sku.name", "F0", case_sensitive=False),
    ])
    step_list(test, rg, rg_2, checks=[])
    step_list2(test, rg, rg_2, checks=[
        test.check('length(@)', 1),
    ])
    step_show(test, rg, rg_2, checks=[
        test.check("name", "{myBot}", case_sensitive=False),
        test.check("location", "eastus", case_sensitive=False),
        test.check("sku.name", "F0", case_sensitive=False),
    ])
    step_update(test, rg, rg_2, checks=[
        test.check("name", "{myBot}", case_sensitive=False),
        test.check("location", "eastus", case_sensitive=False),
        test.check("sku.name", "F0", case_sensitive=False),
    ])
    step_delete(test, rg, rg_2, checks=[])
    cleanup_scenario(test, rg, rg_2)


# Test class for Scenario
@try_manual
class HealthbotScenarioTest(ScenarioTest):

    def __init__(self, *args, **kwargs):
        super(HealthbotScenarioTest, self).__init__(*args, **kwargs)
        self.kwargs.update({
            'myBot': 'samplebotname',
        })

    @ResourceGroupPreparer(name_prefix='clitest', random_name_length=20, key='rg', parameter_name='rg')
    @ResourceGroupPreparer(name_prefix='clitest', random_name_length=20, key='rg_2', parameter_name='rg_2')
    def test_healthbot_Scenario(self, rg, rg_2):
        call_scenario(self, rg, rg_2)
        calc_coverage(__file__)
        raise_if()
