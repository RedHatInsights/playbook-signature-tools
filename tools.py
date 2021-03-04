import os
import sys
import pickle
import oyaml as yaml
import base64
import copy
import gnupg
import tempfile

SIGKEY = 'insights_signature'
DEFAULT_EXCLUSION = '/hosts,/vars'
EXCLUDABLE_VARIABLES = ['hosts', 'vars']
VALID_OPERATIONS = ['-sign', '-validate']

gpg = gnupg.GPG(gnupghome='./utils/.gnupg')

class TemplateDumper(yaml.Dumper):
    """
    Template Dumper class:  Allows for correct YAML indentation
    """
    def increase_indent(self, flow=False, indentless=False):
        return super(TemplateDumper, self).increase_indent(flow, False)


def createSignature(unsignedSnippet):
    """
    Function that creates and returns the signature based off of a given private key and filtered yaml.  At the moment the
    private key is stored locally in the repo, however this is bound to change later.
      output: signature (base64)
    """
    serializedSnippet = yaml.dump(unsignedSnippet)

    signature = gpg.sign(serializedSnippet, detach=True, passphrase='something')
    signature = bytes(str(signature).encode("UTF-8"))

    return base64.b64encode(signature)


def excludeDynamicElements(unsignedSnippet):
    """
    Function that excludes dynamic elements from play template yaml.  Excluded vars are designated by the
    insights_signature_exclude variable.  If insights_signature_exclude variable is not present it reverts
    to default exclustion.
    (By default the signing tool excludes the hosts / all vars including insights_signature) 
        output: unsignedSnippet - dynamic elements
    """
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


def signPlaybookSnippet(unsignedSnippet):
    """
    Function that takes in unsigned snippet yaml, removes dynamic elements, and adds signature to yaml
        output: signed snippet
    """
    if ('vars' not in unsignedSnippet):
        unsignedSnippet['vars'] = {'insights_signature_exclude': DEFAULT_EXCLUSION}
        unsignedSnippet['tasks'] = unsignedSnippet.pop('tasks') # order playbook such that tasks is the last element.

    unsignedSnippetCopy = copy.deepcopy(unsignedSnippet)

    unsignedSnippetCopy = excludeDynamicElements(unsignedSnippetCopy)
    signature = createSignature(unsignedSnippetCopy)
    unsignedSnippet['vars'][SIGKEY] = signature

    return unsignedSnippet


def sign(templatePath):
    """
    Play Template Signing Function 
        output: modified snippet containing signature
    """
    with open(templatePath, 'r') as template_file:
        unsignedSnippet = yaml.load(template_file, Loader=yaml.FullLoader)
        unsignedSnippet = unsignedSnippet[0]

        signedSnippet = signPlaybookSnippet(unsignedSnippet)

    with(open(templatePath, 'w')) as output:
        yaml.dump(
            [signedSnippet],
            output,
            Dumper=TemplateDumper,
            width=100,
            sort_keys=False,
            default_flow_style=False
        )


def executeValidation(signedSnippet, encodedSignature):
    """
    Function that checks signature againsed stringified filtered snippet
    """
    serializedSnippet = bytes(yaml.dump(signedSnippet, default_flow_style=False).encode("UTF-8"))
    decodedSignature = base64.b64decode(encodedSignature)

    fd, fn = tempfile.mkstemp()
    os.write(fd, decodedSignature)
    os.close(fd)

    result = gpg.verify_data(fn, serializedSnippet)
    os.unlink(fn)

    return result


def verifyPlaybookSnippet(signedSnippet):
    """
    Function that validates the playbook snippet
        output: Boolean of either true: validated || false: NOT validated
    """
    encodedSignature = signedSnippet['vars'][SIGKEY]
    signedSnippetCopy = copy.deepcopy(signedSnippet)

    signedSnippetCopy = excludeDynamicElements(signedSnippetCopy)

    validation = executeValidation(signedSnippetCopy, encodedSignature)

    return validation

# Parent Validation function:
# output: Validation "success" to console
def verify(templatePath):
    """
    Parent Validation function:
        output: Validation "success" to console
    """
    with open(templatePath, 'r') as yaml_file:
        yml = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for signedSnippet in yml:
            if (SIGKEY not in signedSnippet['vars']):
                raise Exception('MISSING SIGNATURE: Playbook must first be signed before it is validated.')
            
            result = verifyPlaybookSnippet(signedSnippet)

            if not result:
                print(f"Signature could not be verified for template [name: { signedSnippet['name'] }]")
            else:
                print(f"Validation was Successful for template [name: { signedSnippet['name'] }]")


def main():
    if (len(sys.argv) is not 3):
        raise Exception('INCORRECT PARAMETERS: Signature tool must be ran with [-sign || -validate] [TEMPLATE_PATH] [PUBLIC_KEY_PATH]')
    
    if (sys.argv[1] not in VALID_OPERATIONS):
        raise Exception('INVALID OPERATION: The operation passed must be [-sign || -validate]')

    operation = sys.argv[1]
    templatePath = sys.argv[2]

    if (operation == VALID_OPERATIONS[0]):
        sign(templatePath)
    else:
        verify(templatePath)

if __name__ == '__main__':
    main()
