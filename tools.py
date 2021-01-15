import os
import sys
import pickle
import yaml
import base64
import copy
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

SIGKEY = 'insights_signature'
DEFAULT_EXCLUSION = '/hosts,/vars'
EXCLUDABLE_VARIABLES = ['hosts', 'vars']
VALID_OPERATIONS = ['-sign', '-validate']

# Template Dumper class:  Allows for correct YAML indentation
class TemplateDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(TemplateDumper, self).increase_indent(flow, False)


# Function that creates and returns the signature based off of a given private key and filtered yaml.  At the moment the
# private key is stored locally in the repo, however this is bound to change later.
#   output: signature (base64)
def createSignature(unsignedSnippet, privateKeyPath):
    serializedSnippet = pickle.dumps(unsignedSnippet)

    # load private key
    with open(privateKeyPath, 'rb') as privateKeyFile:
        privateKey = serialization.load_pem_private_key(
            privateKeyFile.read(),
            password=None
        )

    # create signature
    signature = privateKey.sign(
        serializedSnippet,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature)


# Function that excludes dynamic elements from play template yaml.  Excluded vars are designated by the
# insights_signature_exclude variable.  If insights_signature_exclude variable is not present it reverts
# to default exclustion.
# (By default the signing tool excludes the hosts / all vars including insights_signature) 
#   output: unsignedSnippet - dynamic elements
def excludeDynamicElements(unsignedSnippet):
    exclusions = unsignedSnippet['vars']['insights_signature_exclude'].split(',')

    for element in exclusions:
        element = element.split('/')

        # remove empty strings
        element = [string for string in element if string != '']

        if (len(element) == 1 and element[0] in EXCLUDABLE_VARIABLES):
            del unsignedSnippet[element[0]]
        elif (len(element) == 2 and element[0] in EXCLUDABLE_VARIABLES):
            try:
                del unsignedSnippet[element[0]][element[1]]
            except:
                raise Exception(f'INVALID FIELD: the variable {element} defined in insights_signature_exclude does not exist.')
        else:
            raise Exception(f'INVALID EXCLUSION: the variable {element} is not a valid exclusion.')

    return unsignedSnippet


# Function that takes in unsigned snippet yaml, removes dynamic elements, and adds signature to yaml
#   output: signed snippet
def signPlaybookSnippet(unsignedSnippet, privateKeyPath):
    if ('vars' not in unsignedSnippet):
        unsignedSnippet['vars'] = {'insights_signature_exclude': DEFAULT_EXCLUSION}

    unsignedSnippetCopy = copy.deepcopy(unsignedSnippet)

    unsignedSnippetCopy = excludeDynamicElements(unsignedSnippetCopy)
    signature = createSignature(unsignedSnippetCopy, privateKeyPath)
    unsignedSnippet['vars'][SIGKEY] = signature

    return unsignedSnippet


# Play Template Signing Function 
# output: modified snippet containing signature
def sign(templatePath, privateKeyPath):
    with open(templatePath, 'r') as template_file:
        unsignedSnippet = yaml.load(template_file, Loader=yaml.FullLoader)
        unsignedSnippet = unsignedSnippet[0]

        signedSnippet = signPlaybookSnippet(unsignedSnippet, privateKeyPath)

    with(open(templatePath, 'w')) as output:
        yaml.dump(
            [signedSnippet],
            output,
            Dumper=TemplateDumper,
            width=100,
            sort_keys=False,
            default_flow_style=False
        )


# Function that checks signature againsed stringified filtered snippet
def executeValidation(signedSnippet, encodedSignature, publicKeyPath):
    serializedSnippet = pickle.dumps(signedSnippet)
    decodedSignature = base64.b64decode(encodedSignature)

    # load public key
    with open(publicKeyPath, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
        )

    # Validate Signature
    result = public_key.verify(
        decodedSignature,
        serializedSnippet,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return result


# Function that validates the playbook snippet
# output: Boolean of either true: validated || false: NOT validated
def verifyPlaybookSnippet(signedSnippet, publicKeyPath):
    encodedSignature = signedSnippet['vars'][SIGKEY]
    signedSnippetCopy = copy.deepcopy(signedSnippet)

    signedSnippetCopy = excludeDynamicElements(signedSnippetCopy)

    validation = executeValidation(signedSnippetCopy, encodedSignature, publicKeyPath)

    return validation

# Parent Validation function:
# output: Validation "success" to console
def verify(templatePath, publicKeyPath):
    with open(templatePath, 'r') as yaml_file:
        yml = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for signedSnippet in yml:
            if (SIGKEY not in signedSnippet['vars']):
                raise Exception('MISSING SIGNATURE: Playbook must first be signed before it is validated.')
            
            try:
                verifyPlaybookSnippet(signedSnippet, publicKeyPath)

                print(f"Validation was Successful for template [name: { signedSnippet['name'] }]")
            except(InvalidSignature):
                print(f"Signature could not be verified for template [name: { signedSnippet['name'] }]")


def main():
    if (len(sys.argv) is not 4):
        raise Exception('INCORRECT PARAMETERS: Signature tool must be ran with [-sign || -validate] [TEMPLATE_PATH] [PUBLIC_KEY_PATH]')
    
    if (sys.argv[1] not in VALID_OPERATIONS):
        raise Exception('INVALID OPERATION: The operation passed must be [-sign || -validate]')

    operation = sys.argv[1]
    templatePath = sys.argv[2]
    keyPath = sys.argv[3]

    if (operation == VALID_OPERATIONS[0]):
        sign(templatePath, keyPath)
    else:
        verify(templatePath, keyPath)

if __name__ == '__main__':
    main()
