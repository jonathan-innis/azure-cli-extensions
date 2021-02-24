# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------


# pylint: disable=line-too-long

Resource_Already_Exists_Fault_Type = 'resource-already-exists-error'
Resource_Does_Not_Exist_Fault_Type = 'resource-does-not-exist-error'

Invalid_Private_Key_Format_Fault_Type = 'invalid-private-key-format-error'
Invalid_Private_Key_Format_Error = 'Error! ssh private key provided in invalid format'
Invalid_Private_Key_Format_Help = 'Verify the key provided is a valid PEM-formatted key of type RSA, ECC, DSA, or Ed25519'

Https_Parameter_Missing_Fault_Type = 'https-parameter-missing-error'
Https_Parameter_Missing_Error = 'Error! --https-user and --https-key must be provided together'
Https_Parameter_Missing_Help = 'Try specifying both --https-user and --https-key'

Ssh_Parameter_Mismatch_Fault_Type = 'ssh-parameter-mismatch-error'
Ssh_Parameter_Mismatch_Error = 'Error! An ssh private key cannot be used with an http(s) url'
Ssh_Parameter_Mismatch_Help = 'Verify the url provided is a valid ssh url and not an http(s) url'

Https_Parameter_Mismatch_Fault_Type = 'https-parameter-mismatch-error'
Https_Parameter_Mismatch_Error = 'Error! https auth (--https-user and --https-key) cannot be used with a non-http(s) url'
Https_Parameter_Mismatch_Help = 'Verify the url provided is a valid http(s) url and not an ssh url'
