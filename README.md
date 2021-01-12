# Playbook Signature Tools

You've arrived at the repo for the playbook signature tools.  This repo contains a script
used for signing and validating Ansible play templates for cloud.redhat.com.

# Getting Started

This project uses pipenv to manage the dependencies for development and regular use.
To set the project up for development, we recommend using [pyenv](https://github.com/pyenv/pyenv) to install/manage the appropriate python (currently 3.6.x), pip and pipenv version. Once you have pipenv, do the following:

```
pipenv install --dev
```

Afterwards you can activate the virtual environment by running:

```
pipenv shell
```

# Running the Script

Once your virtual environment is up and running you are able to run the signature script itself.

## Signing

Currently the script is able to sign one template at a time, this operation will take the template referenced in the [PATH to Template] and
sign it using the private key given in the [PATH to Private Key].

```
python tools.py -sign [PATH to Template] [PATH to Private Key]
```

## Validation

Unlike the signing tool, this operation is able to validate one or more templates, as long as they meet the following parameters:
* Each template is aggregated to a single yaml file.
* Each template has been signed by the same private key.

```
python tools.py -validate [PATH to Template file] [PATH to Public Key]
```