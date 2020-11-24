import unittest
import base64
from azure.cli.core.util import CLIError
from azext_k8sconfiguration.custom import get_protected_settings
import azext_k8sconfiguration._validators as validators
from Crypto.PublicKey import RSA, ECC, DSA
from paramiko.ed25519key import Ed25519Key


class TestValidateKeyTypes(unittest.TestCase):
    def test_bad_private_key(self):
        private_key_encoded = base64.b64encode("this is not a valid private key".encode('utf-8')).decode('utf-8')
        err = "Error! ssh private key provided in wrong format, ensure your private key is valid"
        with self.assertRaises(CLIError) as cm:
            protected_settings = get_protected_settings(private_key_encoded, '', '', '')
        self.assertEqual(str(cm.exception), err)

    def test_rsa_private_key(self):
        key = RSA.generate(2048)
        private_key_encoded = base64.b64encode(key.export_key('PEM')).decode('utf-8')
        protected_settings = get_protected_settings(private_key_encoded, '', '', '')
        self.assertEqual('sshPrivateKey' in protected_settings, True)
        self.assertEqual(protected_settings.get('sshPrivateKey'), private_key_encoded)

    def test_dsa_private_key(self):
        key = DSA.generate(2048)
        private_key_encoded = base64.b64encode(key.export_key()).decode('utf-8')
        protected_settings = get_protected_settings(private_key_encoded, '', '', '')
        self.assertEqual('sshPrivateKey' in protected_settings, True)
        self.assertEqual(protected_settings.get('sshPrivateKey'), private_key_encoded)

    def test_ecdsa_private_key(self):
        key = ECC.generate(curve='P-256')
        private_key_encoded = base64.b64encode(key.export_key(format='PEM')).decode('utf-8')
        protected_settings = get_protected_settings(private_key_encoded, '', '', '')
        self.assertEqual('sshPrivateKey' in protected_settings, True)
        self.assertEqual(protected_settings.get('sshPrivateKey'), private_key_encoded)


class TestValidateK8sNaming(unittest.TestCase):
    def test_long_operator_namespace(self):
        operator_namespace = "thisisaverylongnamethatistoolongtobeused"
        namespace = OperatorNamespace(operator_namespace)
        err = 'Invalid operator namespace parameter. Valid operator namespaces can be a maximum of 23 characters'
        with self.assertRaises(CLIError) as cm:
            validators.validate_operator_namespace(namespace)
        self.assertEqual(str(cm.exception), err)

    def test_long_operator_instance_name(self):
        operator_instance_name = "thisisaverylongnamethatistoolongtobeused"
        namespace = OperatorInstanceName(operator_instance_name)
        err = 'Invalid operator instance name parameter. Valid operator instance names can be a maximum of 23 characters'
        with self.assertRaises(CLIError) as cm:
            validators.validate_operator_instance_name(namespace)
        self.assertEqual(str(cm.exception), err)

    def test_caps_operator_namespace(self):
        operator_namespace = 'Myoperatornamespace'
        namespace = OperatorNamespace(operator_namespace)
        err = 'Invalid operator namespace parameter. Valid operator namespaces must match with the regex [a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*'
        with self.assertRaises(CLIError) as cm:
            validators.validate_operator_namespace(namespace)
        self.assertEqual(str(cm.exception), err)
    
    def test_caps_operator_instance_name(self):
        operator_instance_name = 'Myoperatorname'
        namespace = OperatorInstanceName(operator_instance_name)
        err = 'Invalid operator instance name parameter. Valid operator instance names must match with the regex [a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*'
        with self.assertRaises(CLIError) as cm:
            validators.validate_operator_instance_name(namespace)
        self.assertEqual(str(cm.exception), err)


class OperatorNamespace:
    def __init__(self, operator_namespace):
        self.operator_namespace = operator_namespace

class OperatorInstanceName:
    def __init__(self, operator_instance_name):
        self.operator_instance_name = operator_instance_name