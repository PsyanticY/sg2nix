from setuptools import setup
import os
import io
import runpy

current = os.path.realpath(os.path.dirname(__file__))

with io.open(os.path.join(current, 'README.rst'), encoding="utf-8") as f:
    long_description = f.read()

with open(os.path.join(current, 'requirements.txt')) as f:
    install_requirements = f.read().splitlines()

__version__ = "1.0.1"

setup(name='sg2nix',
      description='Create nix expressions for existing AWS security groups.',
      url='https://github.com/PsyanticY/sg2nix',
      long_description=long_description,
      version=__version__,
      author='PsyanticY',
      author_email='iuns@outlook.fr',
      license='MIT',
      platforms=["Linux"],
      packages=["sg2nix"],
      include_package_data=True,
      install_requires=install_requirements,
      classifiers=[
        'Development Status :: 1 - Development',
        'Intended Audience :: Security/Automation',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only'
        ],
      keywords='AWS Security_Groups NixOps',
      entry_points = {
         'console_scripts': [
            'sg2nix = sg2nix.sg2nix:main',
         ],
       },
      zip_safe=False)